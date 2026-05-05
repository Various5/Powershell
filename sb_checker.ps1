<#
.SYNOPSIS
    Interaktives Toolkit zur Secure Boot 2023 CA-Verwaltung auf Windows Server.

.DESCRIPTION
    Menübasiertes Script zur Inventarisierung, Diagnose, Hardware-/Firmware-Check
    und (optional) zum Auslösen des Secure Boot 2023 CA-Updates.
    Funktioniert lokal und remote (per WinRM).

    Hintergrund: Die 2011 Secure Boot CAs laufen ab Juni 2026 ab.
    Server bekommen die 2023 CAs NICHT automatisch via Windows Update –
    der Rollout muss durch den Admin angestossen werden.

.NOTES
    Author : Varous
    Quelle : https://aka.ms/GetSecureBoot
    Run    : Als Administrator ausführen.
#>

[CmdletBinding()]
param()

#region ===================== Helper Functions ============================

function Write-Section {
    param([string]$Title, [ConsoleColor]$Color = 'Cyan')
    Write-Host ''
    Write-Host ('═' * 72) -ForegroundColor $Color
    Write-Host "  $Title" -ForegroundColor $Color
    Write-Host ('═' * 72) -ForegroundColor $Color
}

function Pause-AndContinue {
    Write-Host ''
    Write-Host 'Drücke ENTER um zum Menü zurückzukehren...' -ForegroundColor DarkGray
    [void](Read-Host)
}

#endregion

#region ===================== Data Collection ============================

function Get-SecureBootStatusLocal {
    [CmdletBinding()] param()

    $sbEnabled = $null; $sbSupported = $true
    try { $sbEnabled = Confirm-SecureBootUEFI -ErrorAction Stop }
    catch { $sbSupported = $false }

    $sbPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
    $ca2023Status     = (Get-ItemProperty -Path $sbPath -Name 'UEFICA2023Status'  -ErrorAction SilentlyContinue).UEFICA2023Status
    $ca2023Error      = (Get-ItemProperty -Path $sbPath -Name 'UEFICA2023Error'   -ErrorAction SilentlyContinue).UEFICA2023Error
    $availableUpdates = (Get-ItemProperty -Path $sbPath -Name 'AvailableUpdates'  -ErrorAction SilentlyContinue).AvailableUpdates

    $firmwareHas2023 = $null
    if ($sbSupported -and $sbEnabled) {
        try {
            $dbBytes = (Get-SecureBootUEFI -Name db -ErrorAction Stop).bytes
            $dbAscii = [System.Text.Encoding]::ASCII.GetString($dbBytes)
            $firmwareHas2023 = $dbAscii -match 'Windows UEFI CA 2023'
        } catch { $firmwareHas2023 = $null }
    }

    $needsAction = $false; $hasError = $false; $summary = ''
    if (-not $sbSupported)        { $summary = 'Secure Boot wird nicht unterstützt (Legacy BIOS / Gen1-VM).' }
    elseif (-not $sbEnabled)      { $summary = 'Secure Boot ist deaktiviert.' }
    else {
        switch ($ca2023Status) {
            'Updated'    { $summary = 'OK – 2023 Zertifikate sind installiert.' }
            'InProgress' { $summary = 'Deployment läuft – Reboot abwarten oder anstossen.'; $needsAction = $true }
            'NotStarted' { $summary = 'Update noch nicht gestartet.'; $needsAction = $true }
            $null        { $summary = 'Status-Key fehlt – LCU-Patchstand prüfen.'; $needsAction = $true }
            default      { $summary = "Unbekannter Status: $ca2023Status"; $needsAction = $true }
        }
        if ($null -ne $ca2023Error -and $ca2023Error -ne 0) {
            $hasError = $true
            $summary += " UEFICA2023Error=0x$('{0:X}' -f $ca2023Error)."
        }
    }

    [PSCustomObject]@{
        ComputerName        = $env:COMPUTERNAME
        OS                  = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
        OSVersion           = [Environment]::OSVersion.Version.ToString()
        SecureBootSupported = $sbSupported
        SecureBootEnabled   = $sbEnabled
        FirmwareHas2023CA   = $firmwareHas2023
        CA2023Status        = $ca2023Status
        CA2023ErrorCode     = if ($null -ne $ca2023Error)      { '0x{0:X}' -f $ca2023Error }      else { $null }
        AvailableUpdates    = if ($null -ne $availableUpdates) { '0x{0:X}' -f $availableUpdates } else { $null }
        NeedsAction         = $needsAction
        HasError            = $hasError
        Summary             = $summary
        CheckedAt           = Get-Date
    }
}

function Get-HardwareInfo {
    [CmdletBinding()] param()

    $cs    = Get-CimInstance Win32_ComputerSystem    -ErrorAction SilentlyContinue
    $bios  = Get-CimInstance Win32_BIOS              -ErrorAction SilentlyContinue
    $board = Get-CimInstance Win32_BaseBoard         -ErrorAction SilentlyContinue
    $encl  = Get-CimInstance Win32_SystemEnclosure   -ErrorAction SilentlyContinue
    $cpu   = Get-CimInstance Win32_Processor         -ErrorAction SilentlyContinue | Select-Object -First 1
    $mem   = Get-CimInstance Win32_PhysicalMemory    -ErrorAction SilentlyContinue
    $os    = Get-CimInstance Win32_OperatingSystem   -ErrorAction SilentlyContinue

    # Boot Mode (UEFI vs Legacy)
    $bootMode = 'Unknown'
    try {
        $r = Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control' -Name PEFirmwareType -ErrorAction SilentlyContinue
        $bootMode = if ($r.PEFirmwareType -eq 2) { 'UEFI' } elseif ($r.PEFirmwareType -eq 1) { 'Legacy BIOS' } else { 'Unknown' }
    } catch {}

    # VM detection
    $isVm = $false; $vmType = $null
    if ($cs) {
        if ($cs.Manufacturer -match 'Microsoft|VMware|Xen|innotek|QEMU|Red Hat|Parallels|Nutanix') {
            $isVm = $true
            $vmType = switch -Wildcard ($cs.Manufacturer) {
                '*Microsoft*'  { 'Hyper-V' }
                '*VMware*'     { 'VMware' }
                '*innotek*'    { 'VirtualBox' }
                '*Xen*'        { 'Xen' }
                '*QEMU*'       { 'QEMU/KVM' }
                '*Red Hat*'    { 'Red Hat KVM' }
                '*Parallels*'  { 'Parallels' }
                '*Nutanix*'    { 'Nutanix AHV' }
                default        { $cs.Manufacturer }
            }
        }
        if ($cs.Model -match 'Virtual') { $isVm = $true; if (-not $vmType) { $vmType = 'Virtual (generic)' } }
    }

    # BIOS Datum / Alter
    $biosDate = $null; $biosAgeYears = $null
    if ($bios -and $bios.ReleaseDate) {
        $biosDate = $bios.ReleaseDate
        $biosAgeYears = [math]::Round(((Get-Date) - $biosDate).TotalDays / 365.25, 1)
    }

    # TPM
    $tpm = $null
    try {
        $tpmObj = Get-Tpm -ErrorAction Stop
        $tpm = [PSCustomObject]@{
            Present             = $tpmObj.TpmPresent
            Ready               = $tpmObj.TpmReady
            Enabled             = $tpmObj.TpmEnabled
            ManufacturerVersion = $tpmObj.ManufacturerVersion
        }
    } catch {
        try {
            $tpmWmi = Get-CimInstance -Namespace 'root\cimv2\security\microsofttpm' -ClassName Win32_Tpm -ErrorAction Stop
            $tpm = [PSCustomObject]@{
                Present             = $true
                Ready               = $tpmWmi.IsActivated_InitialValue
                Enabled             = $tpmWmi.IsEnabled_InitialValue
                ManufacturerVersion = $tpmWmi.ManufacturerVersion
            }
        } catch { $tpm = $null }
    }

    # RAM gesamt
    $totalRamGb = if ($mem) { [math]::Round(($mem | Measure-Object Capacity -Sum).Sum / 1GB, 0) } else { $null }

    # Server Generation Heuristik (für OEM-Hinweise)
    $generation = 'Unknown'
    if ($bios -and $bios.ReleaseDate) {
        $year = $bios.ReleaseDate.Year
        $generation = if ($year -ge 2024) { 'Modern (2024+) – wahrscheinlich 2023 CA-fähig' }
                       elseif ($year -ge 2022) { 'Aktuell (2022-2023) – sollte mit Firmware-Update gehen' }
                       elseif ($year -ge 2018) { 'Älter (2018-2021) – Firmware-Update vom OEM nötig' }
                       elseif ($year -ge 2014) { 'Alt (2014-2017) – OEM-Support fraglich' }
                       else { 'Sehr alt (<2014) – Firmware-Support unwahrscheinlich' }
    }

    [PSCustomObject]@{
        Manufacturer       = $cs.Manufacturer
        Model              = $cs.Model
        SystemFamily       = $cs.SystemFamily
        SerialNumber       = $bios.SerialNumber
        ServiceTag         = $encl.SerialNumber
        IsVirtualMachine   = $isVm
        VirtualizationType = $vmType
        BiosManufacturer   = $bios.Manufacturer
        BiosVersion        = $bios.SMBIOSBIOSVersion
        BiosReleaseDate    = $biosDate
        BiosAgeYears       = $biosAgeYears
        BoardManufacturer  = $board.Manufacturer
        BoardProduct       = $board.Product
        BoardVersion       = $board.Version
        BootMode           = $bootMode
        CpuName            = $cpu.Name
        CpuCores           = $cpu.NumberOfCores
        CpuLogical         = $cpu.NumberOfLogicalProcessors
        TotalRamGB         = $totalRamGb
        OS                 = $os.Caption
        OSVersion          = $os.Version
        OSBuild            = "$($os.BuildNumber).$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue).UBR)"
        TPM                = $tpm
        HardwareGeneration = $generation
    }
}

function Get-OemGuidance {
    param([string]$Manufacturer)
    if (-not $Manufacturer) { return $null }
    switch -Wildcard ($Manufacturer) {
        '*Dell*'        { return [PSCustomObject]@{ Vendor='Dell';            Url='https://www.dell.com/support';                                                                                    Note='Dell BIOS-Update via iDRAC/Lifecycle Controller oder Dell Update Utility. PowerEdge 13G+ generell unterstützt; ältere Modelle ggf. ohne Firmware-Update für 2023 CAs.' } }
        '*HP*'          { return [PSCustomObject]@{ Vendor='HPE/HP';          Url='https://support.hpe.com';                                                                                          Note='HPE ProLiant: Service Pack for ProLiant (SPP) oder iLO Lifecycle. Gen10/Gen11 generell unterstützt.' } }
        '*Lenovo*'      { return [PSCustomObject]@{ Vendor='Lenovo';          Url='https://datacentersupport.lenovo.com';                                                                              Note='Lenovo ThinkSystem: BIOS via XClarity Controller oder OneCLI. Modelle ab SR-Reihe meist gut unterstützt.' } }
        '*Cisco*'       { return [PSCustomObject]@{ Vendor='Cisco';           Url='https://www.cisco.com/c/en/us/support/servers-unified-computing/index.html';                                       Note='Cisco UCS: HUU (Host Upgrade Utility) oder UCS Manager.' } }
        '*Supermicro*'  { return [PSCustomObject]@{ Vendor='Supermicro';      Url='https://www.supermicro.com/en/support';                                                                             Note='Supermicro: BIOS-Update via SUM/IPMI. Modellabhängig – Support-Status pro Board prüfen.' } }
        '*Fujitsu*'     { return [PSCustomObject]@{ Vendor='Fujitsu';         Url='https://support.ts.fujitsu.com';                                                                                    Note='Fujitsu PRIMERGY: Server View Update Manager.' } }
        '*Huawei*'      { return [PSCustomObject]@{ Vendor='Huawei';          Url='https://support.huawei.com';                                                                                        Note='Huawei FusionServer: iBMC oder eService.' } }
        '*Microsoft*'   { return [PSCustomObject]@{ Vendor='Microsoft (VM)';  Url='https://learn.microsoft.com/windows-server/virtualization/hyper-v/learn-more/generation-2-virtual-machine-overview'; Note='Hyper-V Gen2-VM: VM-Konfigurationsversion auf neueste Version upgraden, dann Update auslösen.' } }
        '*VMware*'      { return [PSCustomObject]@{ Vendor='VMware';          Url='https://kb.vmware.com';                                                                                             Note='VMware: VM-Hardware-Version aktualisieren. EFI-Firmware-Stand der VM prüfen.' } }
        default         { return [PSCustomObject]@{ Vendor=$Manufacturer;     Url='https://support.microsoft.com/topic/9ecc3ba4-fb50-4bd3-9e9b-f16b35b8fb68';                                          Note='OEM nicht in der lokalen Liste. Microsoft pflegt eine Übersicht der OEM-Pages für Secure Boot.' } }
    }
}

function Get-SecureBootEvents {
    param([int]$Days = 30)
    $cutoff = (Get-Date).AddDays(-$Days)
    try {
        Get-WinEvent -FilterHashtable @{
            LogName   = 'System'
            Id        = 1795, 1800, 1801, 1803, 1808
            StartTime = $cutoff
        } -ErrorAction SilentlyContinue | Sort-Object TimeCreated -Descending
    } catch { @() }
}

function Get-ActionPlan {
    param($Status, $Hardware)

    $steps = New-Object System.Collections.Generic.List[string]
    $severity = 'Info'

    if (-not $Status.SecureBootSupported) {
        $severity = 'Info'
        $steps.Add('Dieser Server unterstützt kein Secure Boot (Legacy BIOS oder Hyper-V Gen1-VM).')
        $steps.Add('Kein direkter Handlungsbedarf – aber Security-Posture mit Kunde besprechen.')
        $steps.Add('Bei Gen1-VMs: Migration auf Gen2 prüfen, falls Secure Boot gewünscht ist.')
    }
    elseif (-not $Status.SecureBootEnabled) {
        $severity = 'Info'
        $steps.Add('Secure Boot ist im UEFI deaktiviert.')
        $steps.Add('Wenn Secure Boot gewünscht ist: im UEFI-Setup aktivieren, dann Toolkit erneut laufen lassen.')
        $steps.Add('Wenn bewusst deaktiviert (z.B. wegen Legacy-Bootloader): kein Handlungsbedarf, aber dokumentieren.')
    }
    elseif ($Status.CA2023Status -eq 'Updated' -and $Status.FirmwareHas2023CA) {
        $severity = 'Info'
        $steps.Add('[OK] Alles erledigt. 2023 CAs sind in der Firmware aktiv und Status ist "Updated".')
        $steps.Add('Optional: Eine letzte Verifikation per Event-ID 1808 im System-Log.')
    }
    elseif ($Status.CA2023Status -eq 'Updated' -and -not $Status.FirmwareHas2023CA) {
        $severity = 'Warning'
        $steps.Add('Status sagt "Updated", aber Firmware-DB enthält die 2023 CAs noch nicht.')
        $steps.Add('Reboot ist wahrscheinlich noch ausstehend – Boot Manager Update braucht einen Restart.')
        $steps.Add('Plane einen Reboot ein, danach erneut Option 4 (Firmware-DB Check).')
    }
    elseif ($Status.HasError) {
        $severity = 'Critical'
        $steps.Add("Fehler aufgetreten: $($Status.CA2023ErrorCode)")
        $steps.Add('1. Event-Log Details ansehen (Option 7) – speziell Events 1795/1803.')
        $steps.Add('2. Bei Event 1803 (PK-signed KEK fehlt): OEM-Support kontaktieren.')
        $steps.Add('3. Bei Event 1795: Firmware-Update vom OEM einspielen, dann erneut versuchen.')
    }
    elseif ($Status.CA2023Status -eq 'InProgress') {
        $severity = 'Action'
        $steps.Add('Deployment läuft bereits.')
        $steps.Add('1. Event 1800 prüfen – wenn vorhanden, ist ein Reboot nötig.')
        $steps.Add('2. Reboot anstossen oder bis zur nächsten geplanten Wartung warten.')
        $steps.Add('3. Nach Reboot Option 4 (Firmware-DB Check) für finale Verifikation.')
    }
    elseif ($null -eq $Status.CA2023Status) {
        $severity = 'Action'
        $steps.Add('UEFICA2023Status-Key fehlt – Servicing-Stack ist noch nicht ready.')
        $steps.Add('1. Latest Cumulative Update fürs OS installieren (Option 6 für Patchstand).')
        $steps.Add('   -> Server 2019: mind. April-2026-LCU oder neuer.')
        $steps.Add('   -> Server 2022: mit aktuellem LCU sollten Keys da sein.')
        $steps.Add('2. Reboot.')
        $steps.Add('3. Toolkit erneut laufen lassen, Status-Key sollte dann existieren.')
        $steps.Add('4. Wenn Key auch nach LCU fehlt: WSUS-Approval prüfen.')
    }
    elseif ($Status.CA2023Status -eq 'NotStarted') {
        $severity = 'Action'
        $steps.Add('Bereit für Rollout – aber Vorbereitung zwingend nötig.')
        $steps.Add('1. OEM-Firmware/BIOS-Stand prüfen und ggf. updaten (siehe Hardware-Info).')
        $steps.Add('2. Backup/Snapshot erstellen.')
        $steps.Add('3. Auf einem Pilot-System (gleiche Hardware-Generation) zuerst testen.')
        $steps.Add('4. Trigger setzen via Menü-Option 9 oder GPO.')
        $steps.Add('5. Nach Reboot Verifikation per Option 4 (Firmware-DB Check).')
    }

    if ($Hardware -and $null -ne $Hardware.BiosAgeYears -and $Hardware.BiosAgeYears -gt 3 -and -not $Hardware.IsVirtualMachine) {
        if ($severity -eq 'Info') { $severity = 'Action' }
        $steps.Add("[!] BIOS ist $($Hardware.BiosAgeYears) Jahre alt (Datum: $($Hardware.BiosReleaseDate.ToString('yyyy-MM-dd'))). Update vor dem CA-Rollout dringend prüfen.")
    }

    [PSCustomObject]@{ Severity = $severity; Steps = $steps }
}

#endregion

#region ===================== Display Functions ==========================

function Format-StatusLine {
    param($Result)
    $color = if ($Result.HasError) { 'Red' }
             elseif (-not $Result.SecureBootSupported) { 'DarkGray' }
             elseif ($Result.NeedsAction) { 'Yellow' }
             else { 'Green' }
    Write-Host ("  {0,-22} : {1}" -f 'ComputerName',         $Result.ComputerName)
    Write-Host ("  {0,-22} : {1}" -f 'OS',                   $Result.OS)
    Write-Host ("  {0,-22} : {1}" -f 'Secure Boot enabled',  $Result.SecureBootEnabled)
    Write-Host ("  {0,-22} : {1}" -f 'Firmware hat 2023 CA', $Result.FirmwareHas2023CA)
    Write-Host ("  {0,-22} : {1}" -f 'CA2023 Status',        $Result.CA2023Status)
    Write-Host ("  {0,-22} : {1}" -f 'CA2023 Error',         $Result.CA2023ErrorCode)
    Write-Host ("  {0,-22} : {1}" -f 'AvailableUpdates',     $Result.AvailableUpdates)
    Write-Host ("  {0,-22} : {1}" -f 'Summary',              $Result.Summary) -ForegroundColor $color
}

#endregion

#region ===================== Menu Options ================================

function Show-QuickStatusLocal {
    Write-Section 'Quick Status Check (lokal)'
    Format-StatusLine -Result (Get-SecureBootStatusLocal)
    Pause-AndContinue
}

function Show-DetailedInfoLocal {
    Write-Section 'Detaillierte Info (lokal)'
    Format-StatusLine -Result (Get-SecureBootStatusLocal)

    Write-Host ''
    Write-Host '─── Registry Werte ──────────────────────────────────────────' -ForegroundColor Cyan
    $sbPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot'
    Get-ItemProperty -Path $sbPath -ErrorAction SilentlyContinue |
        Select-Object -Property * -ExcludeProperty PS* |
        Format-List | Out-Host

    Write-Host '─── Relevante Events (letzte 30 Tage) ──────────────────────' -ForegroundColor Cyan
    $events = Get-SecureBootEvents -Days 30
    if ($events.Count -eq 0) {
        Write-Host '  Keine Events gefunden.' -ForegroundColor DarkGray
    } else {
        $events | Group-Object Id | ForEach-Object {
            [PSCustomObject]@{
                EventId  = [int]$_.Name
                Count    = $_.Count
                LastSeen = ($_.Group | Select-Object -First 1).TimeCreated
                Meaning  = switch ([int]$_.Name) {
                    1795 { 'Fehler beim Übergeben an Firmware' }
                    1800 { 'Reboot erforderlich' }
                    1801 { 'Zertifikate/Boot Manager nicht angewandt' }
                    1803 { 'PK-signed KEK fehlt – OEM kontaktieren' }
                    1808 { 'Erfolg: 2023 CAs in Firmware' }
                }
            }
        } | Format-Table -AutoSize | Out-Host
    }
    Pause-AndContinue
}

function Show-RemoteCheck {
    Write-Section 'Remote Check (mehrere Server)'
    Write-Host 'Computernamen kommagetrennt eingeben (oder Pfad zu .txt-Datei):' -ForegroundColor Yellow
    $userInput = Read-Host 'Server'
    if ([string]::IsNullOrWhiteSpace($userInput)) { return }

    $computers = if (Test-Path $userInput -ErrorAction SilentlyContinue) {
        Get-Content $userInput | Where-Object { $_ -and -not $_.StartsWith('#') }
    } else {
        $userInput -split ',' | ForEach-Object { $_.Trim() }
    }

    Write-Host ''
    Write-Host "Prüfe $($computers.Count) Server..." -ForegroundColor Cyan

    $results = Invoke-Command -ComputerName $computers `
        -ScriptBlock ${function:Get-SecureBootStatusLocal} `
        -ErrorAction SilentlyContinue -ErrorVariable remoteErrors

    if ($results) {
        $results | Sort-Object NeedsAction, HasError -Descending |
            Format-Table ComputerName, OS, SecureBootEnabled, CA2023Status,
                         FirmwareHas2023CA, NeedsAction, HasError, Summary -AutoSize -Wrap |
            Out-Host
    }

    if ($remoteErrors.Count -gt 0) {
        Write-Host ''
        Write-Host "Nicht erreichbar: $($remoteErrors.Count)" -ForegroundColor Red
        $remoteErrors | ForEach-Object { Write-Host "  - $($_.TargetObject): $($_.Exception.Message)" -ForegroundColor DarkRed }
    }

    Write-Host ''
    if ((Read-Host 'Ergebnis als CSV exportieren? (j/N)') -eq 'j') {
        $csvPath = "$env:USERPROFILE\Desktop\SecureBoot2023_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
        $results | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "Exportiert nach: $csvPath" -ForegroundColor Green
    }
    Pause-AndContinue
}

function Show-FirmwareDbCheck {
    Write-Section 'Firmware-DB Prüfung – sind die 2023 Zertifikate drin?'
    try {
        $db  = Get-SecureBootUEFI -Name db  -ErrorAction Stop
        $kek = Get-SecureBootUEFI -Name KEK -ErrorAction Stop

        $dbAscii  = [System.Text.Encoding]::ASCII.GetString($db.bytes)
        $kekAscii = [System.Text.Encoding]::ASCII.GetString($kek.bytes)

        $checks = [ordered]@{
            'Windows UEFI CA 2023 (DB)'        = $dbAscii  -match 'Windows UEFI CA 2023'
            'Microsoft UEFI CA 2023 (DB)'      = $dbAscii  -match 'Microsoft UEFI CA 2023'
            'Microsoft Option ROM UEFI 2023'   = $dbAscii  -match 'Microsoft Option ROM UEFI CA 2023'
            'KEK 2K CA 2023 (KEK)'             = $kekAscii -match 'Microsoft Corporation KEK 2K CA 2023'
            '— 2011 KEK noch vorhanden'        = $kekAscii -match 'Microsoft Corporation KEK CA 2011'
            '— 2011 UEFI CA noch vorhanden'    = $dbAscii  -match 'Microsoft Corporation UEFI CA 2011'
            '— Windows Production PCA 2011'    = $dbAscii  -match 'Windows Production PCA 2011'
        }

        Write-Host ''
        foreach ($k in $checks.Keys) {
            $val = $checks[$k]
            $color = if ($k.StartsWith('—')) { 'DarkGray' }
                     elseif ($val) { 'Green' } else { 'Yellow' }
            $marker = if ($val) { '[X]' } else { '[ ]' }
            Write-Host ("  {0} {1,-40} {2}" -f $marker, $k, $val) -ForegroundColor $color
        }

        Write-Host ''
        $has2023 = $checks['Windows UEFI CA 2023 (DB)'] -and $checks['KEK 2K CA 2023 (KEK)']
        if ($has2023) {
            Write-Host '  => 2023 Zertifikate sind in der Firmware aktiv.' -ForegroundColor Green
        } else {
            Write-Host '  => 2023 Zertifikate fehlen ganz oder teilweise.' -ForegroundColor Yellow
        }
    } catch {
        Write-Host "  Fehler beim Lesen der Firmware-Variablen: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host '  (Secure Boot deaktiviert oder Legacy BIOS?)' -ForegroundColor DarkGray
    }
    Pause-AndContinue
}

function Show-HardwareInfo {
    Write-Section 'Hardware & Firmware Info'
    $hw = Get-HardwareInfo

    Write-Host '─── System ───' -ForegroundColor Cyan
    Write-Host ("  {0,-22} : {1}" -f 'Hersteller',     $hw.Manufacturer)
    Write-Host ("  {0,-22} : {1}" -f 'Modell',         $hw.Model)
    Write-Host ("  {0,-22} : {1}" -f 'System Family',  $hw.SystemFamily)
    Write-Host ("  {0,-22} : {1}" -f 'Serial / SvcTag',$hw.SerialNumber)
    if ($hw.IsVirtualMachine) {
        Write-Host ("  {0,-22} : {1}" -f 'Virtualisierung', $hw.VirtualizationType) -ForegroundColor Magenta
    } else {
        Write-Host ("  {0,-22} : {1}" -f 'Virtualisierung', 'Physisch')
    }

    Write-Host ''
    Write-Host '─── Firmware / BIOS ───' -ForegroundColor Cyan
    Write-Host ("  {0,-22} : {1}" -f 'BIOS Hersteller', $hw.BiosManufacturer)
    Write-Host ("  {0,-22} : {1}" -f 'BIOS Version',    $hw.BiosVersion)
    if ($hw.BiosReleaseDate) {
        $dateColor = if ($hw.BiosAgeYears -gt 5) { 'Red' }
                     elseif ($hw.BiosAgeYears -gt 3) { 'Yellow' }
                     else { 'Green' }
        Write-Host ("  {0,-22} : {1:yyyy-MM-dd} ({2} Jahre alt)" -f 'BIOS Release Datum', $hw.BiosReleaseDate, $hw.BiosAgeYears) -ForegroundColor $dateColor
    }
    Write-Host ("  {0,-22} : {1}" -f 'Boot Mode',           $hw.BootMode)
    Write-Host ("  {0,-22} : {1}" -f 'Mainboard',           "$($hw.BoardManufacturer) $($hw.BoardProduct) $($hw.BoardVersion)")
    Write-Host ("  {0,-22} : {1}" -f 'Hardware-Generation', $hw.HardwareGeneration) -ForegroundColor Cyan

    Write-Host ''
    Write-Host '─── Compute ───' -ForegroundColor Cyan
    Write-Host ("  {0,-22} : {1}" -f 'CPU',  "$($hw.CpuName) ($($hw.CpuCores)C/$($hw.CpuLogical)T)")
    Write-Host ("  {0,-22} : {1} GB" -f 'RAM',$hw.TotalRamGB)
    Write-Host ("  {0,-22} : {1}" -f 'OS',   "$($hw.OS) Build $($hw.OSBuild)")

    if ($hw.TPM) {
        Write-Host ''
        Write-Host '─── TPM ───' -ForegroundColor Cyan
        Write-Host ("  {0,-22} : {1}" -f 'Present',     $hw.TPM.Present)
        Write-Host ("  {0,-22} : {1}" -f 'Ready',       $hw.TPM.Ready)
        Write-Host ("  {0,-22} : {1}" -f 'Enabled',     $hw.TPM.Enabled)
        Write-Host ("  {0,-22} : {1}" -f 'Mfg Version', $hw.TPM.ManufacturerVersion)
    }

    $oem = Get-OemGuidance -Manufacturer $hw.Manufacturer
    if ($oem) {
        Write-Host ''
        Write-Host '─── OEM Firmware-Update Hinweis ───' -ForegroundColor Cyan
        Write-Host ("  Vendor : {0}" -f $oem.Vendor) -ForegroundColor Yellow
        Write-Host ("  URL    : {0}" -f $oem.Url)
        Write-Host ("  Note   : {0}" -f $oem.Note)
    }

    Pause-AndContinue
}

function Show-PatchStatus {
    Write-Section 'Patchstand & OS-Build'

    Write-Host 'Letzte 10 installierte Updates:' -ForegroundColor Cyan
    Get-HotFix | Sort-Object InstalledOn -Descending |
        Select-Object -First 10 HotFixID, Description, InstalledOn |
        Format-Table -AutoSize | Out-Host

    Write-Host 'OS-Build:' -ForegroundColor Cyan
    $os = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    Write-Host ("  ProductName  : {0}" -f $os.ProductName)
    Write-Host ("  DisplayVer   : {0}" -f $os.DisplayVersion)
    Write-Host ("  Build        : {0}.{1}" -f $os.CurrentBuild, $os.UBR)

    $lastCu = Get-HotFix | Where-Object { $_.Description -in 'Security Update','Update' } |
              Sort-Object InstalledOn -Descending | Select-Object -First 1
    if ($lastCu) {
        $age = ((Get-Date) - $lastCu.InstalledOn).Days
        $ageColor = if ($age -gt 60) { 'Red' } elseif ($age -gt 35) { 'Yellow' } else { 'Green' }
        Write-Host ''
        Write-Host ("  Letztes Update: {0} ({1} Tage alt)" -f $lastCu.HotFixID, $age) -ForegroundColor $ageColor
    }

    Write-Host ''
    Write-Host 'Hinweise:' -ForegroundColor Cyan
    Write-Host '  - Server 2019 braucht aktuellen LCU damit der UEFICA2023Status-Key existiert.'
    Write-Host '  - Server 2022 hat vollen Registry/GPO/WinCS-Support.'
    Write-Host '  - Server 2025 zertifizierte Hardware: 2023 CAs ab Werk in Firmware.'

    Pause-AndContinue
}

function Show-EventDetails {
    Write-Section 'Event-Log Details'
    $days = Read-Host 'Zeitraum in Tagen (Default: 30)'
    if (-not $days) { $days = 30 } else { $days = [int]$days }

    $events = Get-SecureBootEvents -Days $days
    if ($events.Count -eq 0) {
        Write-Host '  Keine relevanten Events gefunden.' -ForegroundColor DarkGray
    } else {
        Write-Host ("  {0} Events gefunden in den letzten {1} Tagen." -f $events.Count, $days) -ForegroundColor Cyan
        Write-Host ''
        $events | Select-Object -First 20 |
            Format-List TimeCreated, Id, LevelDisplayName, Message | Out-Host

        if ($events.Count -gt 20) {
            Write-Host "  ... und $($events.Count - 20) weitere (gekürzt)." -ForegroundColor DarkGray
        }
    }
    Pause-AndContinue
}

function Show-ActionPlan {
    Write-Section 'Action Plan – was du jetzt tun solltest'

    Write-Host 'Sammle Daten...' -ForegroundColor DarkGray
    $status = Get-SecureBootStatusLocal
    $hw     = Get-HardwareInfo
    $events = Get-SecureBootEvents -Days 30
    $plan   = Get-ActionPlan -Status $status -Hardware $hw

    Write-Host ''
    Write-Host '─── Aktueller Zustand ───' -ForegroundColor Cyan
    Write-Host ("  Server               : {0} ({1})" -f $status.ComputerName, $status.OS)
    Write-Host ("  Hardware             : {0} {1}" -f $hw.Manufacturer, $hw.Model)
    Write-Host ("  BIOS                 : {0} ({1})" -f $hw.BiosVersion, $(if ($hw.BiosReleaseDate) { $hw.BiosReleaseDate.ToString('yyyy-MM-dd') }))
    Write-Host ("  Secure Boot          : {0}" -f $status.SecureBootEnabled)
    Write-Host ("  CA2023 Status        : {0}" -f $(if ($status.CA2023Status) { $status.CA2023Status } else { '<nicht gesetzt>' }))
    Write-Host ("  Firmware hat 2023 CA : {0}" -f $status.FirmwareHas2023CA)
    Write-Host ("  Events letzte 30T    : {0}" -f $events.Count)

    $sevColor = switch ($plan.Severity) {
        'Critical' { 'Red' }
        'Warning'  { 'Yellow' }
        'Action'   { 'Yellow' }
        default    { 'Green' }
    }
    Write-Host ''
    Write-Host ('─── Empfehlung [{0}] ───' -f $plan.Severity) -ForegroundColor $sevColor
    foreach ($s in $plan.Steps) {
        Write-Host "  $s" -ForegroundColor $sevColor
    }

    if (-not $hw.IsVirtualMachine -and $status.SecureBootEnabled -and $status.CA2023Status -ne 'Updated') {
        $oem = Get-OemGuidance -Manufacturer $hw.Manufacturer
        if ($oem) {
            Write-Host ''
            Write-Host '─── OEM-Hinweis ───' -ForegroundColor Cyan
            Write-Host "  $($oem.Vendor): $($oem.Note)"
            Write-Host "  Doku : $($oem.Url)"
        }
    }

    Pause-AndContinue
}

function Invoke-DeploymentTrigger {
    Write-Section 'Update auslösen – AvailableUpdates = 0x5944' -Color Yellow

    Write-Host '  ACHTUNG: Dies stösst den Secure Boot 2023 CA-Rollout an.' -ForegroundColor Yellow
    Write-Host '    Vorher zwingend prüfen:' -ForegroundColor Yellow
    Write-Host '    1. Aktuelle OEM-Firmware/BIOS ist installiert.'
    Write-Host '    2. Aktueller LCU ist drauf (Status-Key sollte existieren).'
    Write-Host '    3. Server ist KEIN Produktivsystem ohne Pilot-Vorlauf.'
    Write-Host '    4. Backup/Snapshot ist aktuell.'
    Write-Host ''

    $current = Get-SecureBootStatusLocal
    Format-StatusLine -Result $current
    Write-Host ''

    if (-not $current.SecureBootSupported) {
        Write-Host '  Abbruch: Secure Boot wird nicht unterstützt.' -ForegroundColor Red
        Pause-AndContinue; return
    }
    if (-not $current.SecureBootEnabled) {
        Write-Host '  Abbruch: Secure Boot ist deaktiviert.' -ForegroundColor Red
        Pause-AndContinue; return
    }
    if ($current.CA2023Status -eq 'Updated') {
        Write-Host '  Hinweis: Status ist bereits "Updated" – nichts zu tun.' -ForegroundColor Green
        Pause-AndContinue; return
    }

    Write-Host '  Bestätigung 1/2: Möchtest du den Trigger auf DIESEM Server setzen?' -ForegroundColor Yellow
    $c1 = Read-Host '  Tippe "JA" zum Bestätigen'
    if ($c1 -ne 'JA') { Write-Host '  Abgebrochen.' -ForegroundColor DarkGray; Pause-AndContinue; return }

    Write-Host ''
    Write-Host "  Bestätigung 2/2: Servername zur Verifikation eingeben ($env:COMPUTERNAME):" -ForegroundColor Yellow
    $c2 = Read-Host '  Servername'
    if ($c2 -ne $env:COMPUTERNAME) { Write-Host '  Servername stimmt nicht – abgebrochen.' -ForegroundColor Red; Pause-AndContinue; return }

    try {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' `
            -Name 'AvailableUpdates' -Value 0x5944 -PropertyType DWord -Force | Out-Null
        Write-Host ''
        Write-Host '  AvailableUpdates auf 0x5944 gesetzt.' -ForegroundColor Green
        Write-Host '  Nächste Schritte:' -ForegroundColor Cyan
        Write-Host '    - Geplanten Task triggern oder bis zu 12h warten:'
        Write-Host '      Start-ScheduledTask -TaskPath ''\Microsoft\Windows\PI\'' -TaskName ''Secure-Boot-Update'''
        Write-Host '    - Reboot, sobald Status auf "InProgress" wechselt.'
        Write-Host '    - Nach Reboot dieses Script erneut laufen, Option 1 oder 2.'
    } catch {
        Write-Host "  Fehler beim Setzen: $($_.Exception.Message)" -ForegroundColor Red
    }
    Pause-AndContinue
}

function Show-Help {
    Write-Section 'Hintergrund & Hilfe'
    @'
  Was passiert hier?
  ──────────────────
  Die UEFI Secure Boot Zertifikate von 2011 laufen ab Juni 2026 ab.
  Server bekommen die neuen 2023 CAs NICHT automatisch via Windows
  Update – das muss manuell ausgerollt werden.

  Workflow für deine Umgebung:
  ────────────────────────────
  1. Inventar: Option 3 (Remote Check) gegen alle Server.
  2. Pro Server: Option 8 (Action Plan) für tailored Empfehlung.
  3. Hardware/Firmware: Option 5 für BIOS-Stand und OEM-Doku-Link.
  4. Bei "Status-Key fehlt": LCU-Patchstand hochziehen.
  5. Pilot-Server: Option 9 (Trigger setzen).
     - 12h warten oder Task manuell starten.
     - Reboot.
     - Mit Option 4 verifizieren, dass 2023 CAs in Firmware sind.
  6. Auf Server-Flotte ausrollen – idealerweise per GPO.

  Wichtige Werte:
  ───────────────
  AvailableUpdates  0x5944  -> Voller Rollout angestossen
  AvailableUpdates  0x4104  -> KEK-Phase
  AvailableUpdates  0x4100  -> Boot Manager-Phase ausstehend
  AvailableUpdates  0x4000  -> Komplett, evtl. noch Reboot

  CA2023Status      NotStarted / InProgress / Updated

  Events:
    1795  Firmware-Übergabe fehlgeschlagen
    1800  Reboot nötig
    1801  Update läuft / nicht (vollständig) angewandt
    1803  PK-signed KEK fehlt -> OEM kontaktieren
    1808  Erfolg

  Doku:
  ─────
  Server Playbook : https://aka.ms/GetSecureBoot
  Registry Keys   : https://support.microsoft.com/topic/a7be69c9-4634-42e1-9ca1-df06f43f360d
  OEM Pages       : https://support.microsoft.com/topic/9ecc3ba4-fb50-4bd3-9e9b-f16b35b8fb68
'@ | Write-Host
    Pause-AndContinue
}

#endregion

#region ===================== Main Menu Loop ==============================

function Show-Menu {
    Clear-Host
    Write-Host ''
    Write-Host '╔══════════════════════════════════════════════════════════════════════╗' -ForegroundColor Cyan
    Write-Host '║         Secure Boot 2023 CA Toolkit – Windows Server                 ║' -ForegroundColor Cyan
    Write-Host '╚══════════════════════════════════════════════════════════════════════╝' -ForegroundColor Cyan
    Write-Host ''
    Write-Host "  Host: $env:COMPUTERNAME    User: $env:USERNAME    Datum: $(Get-Date -Format 'dd.MM.yyyy HH:mm')"
    Write-Host ''
    Write-Host '  ── DIAGNOSE ──' -ForegroundColor DarkCyan
    Write-Host '   1) Quick Status Check (lokal)'
    Write-Host '   2) Detaillierte Info (lokal, inkl. Events & Registry)'
    Write-Host '   3) Remote Check für mehrere Server'
    Write-Host '   4) Firmware-DB prüfen (sind 2023 CAs aktiv?)'
    Write-Host ''
    Write-Host '  ── KONTEXT ──' -ForegroundColor DarkCyan
    Write-Host '   5) Hardware & Firmware Info (BIOS, OEM, TPM)'
    Write-Host '   6) Patchstand & OS-Build'
    Write-Host '   7) Event-Log Details'
    Write-Host ''
    Write-Host '  ── PLANUNG & AKTION ──' -ForegroundColor DarkCyan
    Write-Host '   8) Action Plan – was muss ich tun?' -ForegroundColor Green
    Write-Host '   9) Update auslösen (Trigger setzen)' -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  ── INFO ──' -ForegroundColor DarkCyan
    Write-Host '   H) Hintergrund & Hilfe'
    Write-Host '   Q) Beenden'
    Write-Host ''
}

# Admin-Check
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()
            ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Warning 'Script läuft nicht als Administrator. Manche Werte sind evtl. nicht lesbar.'
    Start-Sleep -Seconds 2
}

do {
    Show-Menu
    $choice = (Read-Host '  Auswahl').Trim().ToUpper()
    switch ($choice) {
        '1' { Show-QuickStatusLocal }
        '2' { Show-DetailedInfoLocal }
        '3' { Show-RemoteCheck }
        '4' { Show-FirmwareDbCheck }
        '5' { Show-HardwareInfo }
        '6' { Show-PatchStatus }
        '7' { Show-EventDetails }
        '8' { Show-ActionPlan }
        '9' { Invoke-DeploymentTrigger }
        'H' { Show-Help }
        'Q' { break }
        ''  { }
        default {
            Write-Host "  Ungültige Auswahl: $choice" -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
} while ($choice -ne 'Q')

Write-Host ''
Write-Host 'Bye.' -ForegroundColor DarkGray

#endregion
