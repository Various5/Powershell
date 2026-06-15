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

    Version: 2.0 (2026-06)
    Neu in 2.0 (nach mindcore.dk- und Microsoft-KB-Findings):
      - WindowsUEFICA2023Capable (0/1/2) als verlässlichster Fertig-Indikator
        (gelesen aus ...\Secureboot UND ...\Secureboot\Servicing).
      - MicrosoftUpdateManagedOptIn wird ausgelesen und vom direkten Trigger
        klar getrennt.
      - Trigger prüft jetzt Voraussetzungen: geplanter Task vorhanden
        (Juli-2024-CU+) und Payload-.bin / WinCS verfügbar (sonst 0x80070002).
      - Trigger bietet Volles Bundle (0x5944), reversible Phase 1 (0x140) und
        gegatete, irreversible Revocation-Phase (0x280).
      - Transienter UEFICA2023Error 2147942750 wird als Staging-Signal erkannt,
        nicht mehr als Fehler.
      - BitLocker-Warnung (PCR 7) vor dem Boot-Manager-Wechsel.
      - Erweiterte Event-IDs (1036/1043/1044/1045/1796/1798).

    WICHTIG: Diese Datei als UTF-8 MIT BOM speichern, sonst zerschiesst
    Windows PowerShell 5.1 die Umlaute/Box-Zeichen (ANSI-Fehlinterpretation).
#>

[CmdletBinding()]
param(
    # Nicht-interaktiver RMM/Silent-Modus: Status-Ausgabe + Exit-Code, kein Menü.
    # Exit-Codes: 0=OK/N/A, 1=Action Needed, 2=Error, 3=Trigger gesetzt
    [switch]$Quick,

    # Im Quick-Modus zusätzlich AvailableUpdates=0x5944 setzen + Task starten.
    # Vorsicht: ohne Bestätigung. Nur in geprüften RMM-Workflows verwenden.
    [switch]$AutoTrigger
)

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

    # MicrosoftUpdateManagedOptIn (0x5944) = Opt-In für den von Windows Update gesteuerten
    # Staged-Rollout. NICHT zu verwechseln mit AvailableUpdates=0x5944 (= direkter Trigger).
    $managedOptIn = (Get-ItemProperty -Path $sbPath -Name 'MicrosoftUpdateManagedOptIn' -ErrorAction SilentlyContinue).MicrosoftUpdateManagedOptIn

    # WindowsUEFICA2023Capable ist der verlässlichste Fertig-Indikator:
    #   0 = 2023 CA nicht in der DB
    #   1 = in der DB, aber Gerät bootet noch den alten 2011-Chain (Reboot fehlt)
    #   2 = in der DB UND bootet vom 2023-signierten Boot Manager (= fertig)
    # Je nach Build schreibt Windows den Wert unter ...\SecureBoot oder ...\SecureBoot\Servicing.
    $ca2023Capable = $null
    foreach ($p in @($sbPath, (Join-Path $sbPath 'Servicing'))) {
        $v = (Get-ItemProperty -Path $p -Name 'WindowsUEFICA2023Capable' -ErrorAction SilentlyContinue).WindowsUEFICA2023Capable
        if ($null -ne $v) { $ca2023Capable = [int]$v; break }
    }

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

        # WindowsUEFICA2023Capable überschreibt den Status-String, wo es verlässlicher ist.
        switch ($ca2023Capable) {
            2 { $summary = 'OK – 2023 CA in der DB und bootet vom 2023 Boot Manager (fertig).'; $needsAction = $false }
            1 { $summary = '2023 CA ist in der DB, aber Boot Manager noch alt – ein Reboot fehlt (Stage 4).'; $needsAction = $true }
        }

        if ($null -ne $ca2023Error -and $ca2023Error -ne 0) {
            # 2147942750 (0x8007015E) tritt nach AvailableUpdates=0x100 auf: Boot-Manager-Update
            # ist gestaged und wartet auf Reboot. Das ist KEIN Fehler-Endzustand (klärt sich nach Reboot).
            if ($ca2023Error -eq 2147942750) {
                $needsAction = $true
                $summary += ' Hinweis: UEFICA2023Error 2147942750 ist ein Staging-Signal (Reboot ausstehend), kein echter Fehler.'
            } else {
                $hasError = $true
                $summary += " UEFICA2023Error=0x$('{0:X}' -f $ca2023Error)."
            }
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
        CA2023Capable       = $ca2023Capable
        CA2023CapableText   = $(switch ($ca2023Capable) {
                                  0 { '0 – nicht in DB' }
                                  1 { '1 – in DB, alter Boot Manager (Reboot fehlt)' }
                                  2 { '2 – in DB + 2023 Boot Manager (fertig)' }
                                  default { if ($null -eq $ca2023Capable) { '<nicht gesetzt>' } else { "$ca2023Capable" } }
                              })
        ManagedOptIn        = if ($null -ne $managedOptIn) { '0x{0:X}' -f $managedOptIn } else { $null }
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
            Id        = 1036, 1043, 1044, 1045, 1795, 1796, 1797, 1798, 1800, 1801, 1803, 1808
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
    elseif ($Status.CA2023Capable -eq 2) {
        $severity = 'Info'
        $steps.Add('[OK] Fertig. WindowsUEFICA2023Capable=2 – das Gerät bootet vom 2023-signierten Boot Manager.')
        $steps.Add('Optional: Verifikation per Event-ID 1808 und Option 4 (Firmware-DB).')
    }
    elseif ($Status.CA2023Capable -eq 1) {
        $severity = 'Action'
        $steps.Add('Stage 4: 2023 CA ist in der Firmware-DB, aber der alte Boot Manager wird noch geladen.')
        $steps.Add('Es fehlt nur noch EIN Reboot, um auf den 2023 Boot Manager zu wechseln.')
        $steps.Add('1. Bei aktivem BitLocker vorher: Suspend-BitLocker -MountPoint C: -RebootCount 1')
        $steps.Add('2. Reboot durchführen (in Low-Reboot-/Hotpatch-Umgebungen aktiv erzwingen!).')
        $steps.Add('3. Danach erneut prüfen – Capable sollte auf 2 stehen.')
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
        $steps.Add('4. Voraussetzungen prüfen: Task "Secure-Boot-Update" vorhanden (Juli-2024-CU+) und Payload/WinCS da.')
        $steps.Add('5. Trigger setzen via Menü-Option 9 (konservativ: erst Phase 1 / 0x140) oder GPO.')
        $steps.Add('6. Nach Reboot Verifikation: WindowsUEFICA2023Capable sollte 2 sein (Option 1/4).')
    }

    if ($Hardware -and $null -ne $Hardware.BiosAgeYears -and $Hardware.BiosAgeYears -gt 3 -and -not $Hardware.IsVirtualMachine) {
        if ($severity -eq 'Info') { $severity = 'Action' }
        $steps.Add("[!] BIOS ist $($Hardware.BiosAgeYears) Jahre alt (Datum: $($Hardware.BiosReleaseDate.ToString('yyyy-MM-dd'))). Update vor dem CA-Rollout dringend prüfen.")
    }

    [PSCustomObject]@{ Severity = $severity; Steps = $steps }
}

function Get-HyperVHostInventory {
    [CmdletBinding(DefaultParameterSetName = 'Local')]
    param(
        [Parameter(ParameterSetName = 'Cluster')]
        [switch]$IncludeCluster,

        [Parameter(ParameterSetName = 'External')]
        [string[]]$ComputerNames
    )

    if (-not (Get-Module -ListAvailable Hyper-V -ErrorAction SilentlyContinue)) {
        return $null
    }
    Import-Module Hyper-V -ErrorAction SilentlyContinue | Out-Null

    $clusterName = $null
    $nodes = @($env:COMPUTERNAME)

    if ($IncludeCluster) {
        try {
            $cluster = Get-Cluster -ErrorAction Stop
            $clusterName = $cluster.Name
            $nodes = (Get-ClusterNode).Name
        } catch { }
    }
    elseif ($ComputerNames) {
        $nodes = $ComputerNames
    }

    $allVms = New-Object System.Collections.Generic.List[object]
    foreach ($node in $nodes) {
        try {
            $vms = if ($node -eq $env:COMPUTERNAME) { Get-VM -ErrorAction Stop }
                   else { Get-VM -ComputerName $node -ErrorAction Stop }

            foreach ($vm in $vms) {
                $sbEnabled = $null; $sbTemplate = $null; $vtpmEnabled = $null
                $needsCheck = $false; $note = ''

                if ($vm.Generation -eq 1) {
                    $note = 'Gen1 – kein Secure Boot, ignorieren'
                } else {
                    try {
                        $fw = if ($node -eq $env:COMPUTERNAME) { Get-VMFirmware -VMName $vm.Name -ErrorAction Stop }
                              else { Get-VMFirmware -VMName $vm.Name -ComputerName $node -ErrorAction Stop }
                        $sbEnabled  = ($fw.SecureBoot -eq 'On')
                        $sbTemplate = $fw.SecureBootTemplate
                    } catch { }

                    try {
                        $sec = if ($node -eq $env:COMPUTERNAME) { Get-VMSecurity -VMName $vm.Name -ErrorAction Stop }
                               else { Get-VMSecurity -VMName $vm.Name -ComputerName $node -ErrorAction Stop }
                        $vtpmEnabled = $sec.TpmEnabled
                    } catch { }

                    if ($sbEnabled) {
                        $needsCheck = $true
                        if ($sbTemplate -match 'UEFI Certificate Authority|OpenSourceShielded') {
                            $note = 'Linux/Open-Source Template – separate Behandlung'
                        } elseif ($vtpmEnabled) {
                            $note = 'vTPM aktiv – BitLocker vor Trigger suspenden!'
                        } else {
                            $note = 'In der VM Toolkit ausführen'
                        }
                    } else {
                        $note = 'Secure Boot deaktiviert'
                    }
                }

                $allVms.Add([PSCustomObject]@{
                    Host               = $node
                    Name               = $vm.Name
                    State              = $vm.State
                    Generation         = $vm.Generation
                    Version            = $vm.Version
                    SecureBoot         = $sbEnabled
                    SecureBootTemplate = $sbTemplate
                    vTPM               = $vtpmEnabled
                    NeedsCheck         = $needsCheck
                    Note               = $note
                })
            }
        } catch {
            Write-Warning "Konnte VMs auf Host '$node' nicht abfragen: $($_.Exception.Message)"
        }
    }

    [PSCustomObject]@{
        ClusterName = $clusterName
        Nodes       = $nodes
        VMs         = $allVms
    }
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
    Write-Host ("  {0,-22} : {1}" -f 'CA2023 Capable',       $Result.CA2023CapableText)
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
                    1036 { 'Boot-Zeit Kontext-Event (Eventtext lesen)' }
                    1043 { 'Boot-Zeit Kontext-Event (Eventtext lesen)' }
                    1044 { 'Boot-Zeit Kontext-Event (Eventtext lesen)' }
                    1045 { 'Boot-Zeit Kontext-Event (Eventtext lesen)' }
                    1795 { 'Fehler beim Übergeben an Firmware' }
                    1796 { 'DB/Variablen-Update Ereignis (Eventtext lesen)' }
                    1797 { 'Update fehlgeschlagen – 2023 CA fehlt in DB' }
                    1798 { 'DB/Variablen-Update Ereignis (Eventtext lesen)' }
                    1800 { 'Reboot erforderlich' }
                    1801 { 'Zertifikate/Boot Manager nicht (vollständig) angewandt' }
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
            Format-Table ComputerName, OS, SecureBootEnabled, CA2023Status, CA2023Capable,
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

        # Setup Mode vs. User Mode (Catch für "BIOS sagt enabled, Windows sagt disabled")
        $setupMode = $null
        try {
            $sm = Get-SecureBootUEFI -Name SetupMode -ErrorAction Stop
            $setupMode = if ($sm.bytes[0] -eq 1) { 'Setup Mode' } else { 'User Mode' }
        } catch { }

        Write-Host ''
        Write-Host '─── Firmware Mode ───' -ForegroundColor Cyan
        if ($setupMode) {
            $smColor = if ($setupMode -eq 'User Mode') { 'Green' } else { 'Yellow' }
            Write-Host ("  System Mode             : {0}" -f $setupMode) -ForegroundColor $smColor
            if ($setupMode -eq 'Setup Mode') {
                Write-Host '  ⚠ Secure Boot ist im Setup Mode – PK fehlt oder wurde gelöscht.' -ForegroundColor Yellow
                Write-Host '    Fix: BIOS -> Secure Boot Mode = "Custom" -> "Restore Factory Keys"'  -ForegroundColor Yellow
                Write-Host '    -> Reboot -> Secure Boot Mode = "Standard"' -ForegroundColor Yellow
            }
        }

        Write-Host ''
        Write-Host '─── Zertifikate in der Firmware ───' -ForegroundColor Cyan
        $checks = [ordered]@{
            'Windows UEFI CA 2023 (DB)'        = $dbAscii  -match 'Windows UEFI CA 2023'
            'Microsoft UEFI CA 2023 (DB)'      = $dbAscii  -match 'Microsoft UEFI CA 2023'
            'Microsoft Option ROM UEFI 2023'   = $dbAscii  -match 'Microsoft Option ROM UEFI CA 2023'
            'KEK 2K CA 2023 (KEK)'             = $kekAscii -match 'Microsoft Corporation KEK 2K CA 2023'
            '— 2011 KEK noch vorhanden'        = $kekAscii -match 'Microsoft Corporation KEK CA 2011'
            '— 2011 UEFI CA noch vorhanden'    = $dbAscii  -match 'Microsoft Corporation UEFI CA 2011'
            '— Windows Production PCA 2011'    = $dbAscii  -match 'Windows Production PCA 2011'
        }

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
    Write-Host ("  CA2023 Capable       : {0}" -f $status.CA2023CapableText)
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

    if ($status.SecureBootEnabled -and $status.CA2023Capable -ne 2 -and $status.CA2023Status -ne 'Updated') {
        Write-Host ''
        Write-Host '─── Trigger-Voraussetzungen ───' -ForegroundColor Cyan
        Show-PrereqLines -Pre (Test-SecureBootPrereqs)
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

function Show-HyperVHostInventory {
    Write-Section 'Hyper-V VM Inventory'

    if (-not (Get-Module -ListAvailable Hyper-V -ErrorAction SilentlyContinue)) {
        Write-Host '  Hyper-V Modul nicht verfügbar.' -ForegroundColor Yellow
        Write-Host '  Diese Option läuft nur auf einem Hyper-V Host.' -ForegroundColor DarkGray
        Pause-AndContinue; return
    }

    # Cluster verfügbar?
    $clusterAvailable = $false
    try {
        $null = Get-Command Get-Cluster -ErrorAction Stop
        $null = Get-Cluster -ErrorAction Stop
        $clusterAvailable = $true
    } catch { }

    # Sub-Menü
    Write-Host ''
    Write-Host '  Was möchtest du scannen?' -ForegroundColor Cyan
    Write-Host ''
    Write-Host '   1) Lokaler Hyper-V Host (nur dieser Server)'
    if ($clusterAvailable) {
        Write-Host '   2) Failover Cluster (alle Knoten automatisch erkennen)' -ForegroundColor Magenta
    } else {
        Write-Host '   2) Failover Cluster (nicht verfügbar – kein Cluster erkannt)' -ForegroundColor DarkGray
    }
    Write-Host '   3) Spezifische Hosts (manuelle Liste oder Datei)'
    Write-Host '   Z) Zurück'
    Write-Host ''
    $sub = (Read-Host '   Auswahl').Trim().ToUpper()

    switch ($sub) {
        '1' { Invoke-HyperVScan -Mode 'Standalone' }
        '2' {
            if ($clusterAvailable) { Invoke-HyperVScan -Mode 'Cluster' }
            else {
                Write-Host '  Kein Cluster erkannt. Verwende Option 1 oder 3.' -ForegroundColor Yellow
                Pause-AndContinue
            }
        }
        '3' { Invoke-HyperVScan -Mode 'MultiHost' }
        'Z' { return }
        default {
            Write-Host '  Ungültige Auswahl.' -ForegroundColor Red
            Start-Sleep -Seconds 1
        }
    }
}

function Invoke-HyperVScan {
    param(
        [ValidateSet('Standalone','Cluster','MultiHost')]
        [string]$Mode
    )

    # Inventory einholen je nach Modus
    $inv = $null
    $modeTitle = ''

    switch ($Mode) {
        'Standalone' {
            $modeTitle = "Lokaler Hyper-V Host: $env:COMPUTERNAME"
            Write-Host ''
            Write-Host "  Sammle VM-Daten von $env:COMPUTERNAME..." -ForegroundColor DarkGray
            $inv = Get-HyperVHostInventory
        }
        'Cluster' {
            try {
                $cl = Get-Cluster -ErrorAction Stop
                $modeTitle = "Failover Cluster: $($cl.Name)"
                Write-Host ''
                Write-Host "  Sammle VM-Daten von allen Knoten in '$($cl.Name)'..." -ForegroundColor DarkGray
            } catch {
                Write-Host '  Cluster-Abfrage fehlgeschlagen.' -ForegroundColor Red
                Pause-AndContinue; return
            }
            $inv = Get-HyperVHostInventory -IncludeCluster
        }
        'MultiHost' {
            Write-Host ''
            Write-Host '  Hostnamen kommagetrennt eingeben (oder Pfad zu .txt-Datei):' -ForegroundColor Yellow
            $userInput = Read-Host '  Hosts'
            if ([string]::IsNullOrWhiteSpace($userInput)) { return }

            $hosts = if (Test-Path $userInput -ErrorAction SilentlyContinue) {
                Get-Content $userInput | Where-Object { $_ -and -not $_.StartsWith('#') }
            } else {
                $userInput -split ',' | ForEach-Object { $_.Trim() }
            }
            $modeTitle = "Multi-Host Scan ($($hosts.Count) Hosts)"
            Write-Host "  Sammle VM-Daten von $($hosts.Count) Hosts..." -ForegroundColor DarkGray
            $inv = Get-HyperVHostInventory -ComputerNames $hosts
        }
    }

    if (-not $inv -or $inv.VMs.Count -eq 0) {
        Write-Host ''
        Write-Host '  Keine VMs gefunden.' -ForegroundColor Yellow
        Pause-AndContinue; return
    }

    # Übersicht
    Write-Host ''
    Write-Host '─── Übersicht ───' -ForegroundColor Cyan
    Write-Host ("  Modus            : {0}" -f $modeTitle)
    if ($inv.ClusterName) {
        Write-Host ("  Cluster          : {0} ({1} Knoten)" -f $inv.ClusterName, $inv.Nodes.Count)
    } else {
        Write-Host ("  Hosts            : {0}" -f ($inv.Nodes -join ', '))
    }

    $total      = $inv.VMs.Count
    $gen1       = @($inv.VMs | Where-Object { $_.Generation -eq 1 }).Count
    $gen2       = @($inv.VMs | Where-Object { $_.Generation -eq 2 }).Count
    $needCheck  = @($inv.VMs | Where-Object { $_.NeedsCheck }).Count
    $vtpmCount  = @($inv.VMs | Where-Object { $_.vTPM }).Count
    $linuxCount = @($inv.VMs | Where-Object { $_.SecureBootTemplate -match 'UEFI Certificate Authority|OpenSourceShielded' }).Count
    $running    = @($inv.VMs | Where-Object { $_.State -eq 'Running' }).Count

    Write-Host ("  Total VMs        : {0} (davon {1} Running)" -f $total, $running)
    Write-Host ("  Gen1 (skip)      : {0}" -f $gen1) -ForegroundColor DarkGray
    Write-Host ("  Gen2             : {0}" -f $gen2)
    Write-Host ("  Mit vTPM         : {0}" -f $vtpmCount)
    Write-Host ("  Linux/Open-Src   : {0}" -f $linuxCount) -ForegroundColor DarkYellow
    Write-Host ("  Nachzuziehen     : {0}" -f $needCheck) -ForegroundColor $(if ($needCheck -gt 0) { 'Yellow' } else { 'Green' })

    # Detail
    Write-Host ''
    Write-Host '─── Details ───' -ForegroundColor Cyan
    $inv.VMs | Sort-Object Host, @{Expression='NeedsCheck';Descending=$true}, Name |
        Format-Table -Wrap -Property `
            @{N='Host';     E={$_.Host};               Width=14},
            @{N='Name';     E={$_.Name};               Width=24},
            @{N='State';    E={$_.State};              Width=8},
            @{N='Gen';      E={$_.Generation};         Width=4},
            @{N='Ver';      E={$_.Version};            Width=5},
            @{N='SB';       E={$_.SecureBoot};         Width=6},
            @{N='Template'; E={$_.SecureBootTemplate -replace 'Microsoft','MS'}; Width=22},
            @{N='vTPM';     E={$_.vTPM};               Width=6},
            @{N='Note';     E={$_.Note}} | Out-Host

    # Empfohlenes Vorgehen
    Show-HyperVProcedure -Mode $Mode -Inventory $inv

    # CSV Export
    Write-Host ''
    if ((Read-Host '  Inventar als CSV exportieren? (j/N)') -eq 'j') {
        $csvPath = "$env:USERPROFILE\Desktop\HyperV_VM_Inventory_$($Mode)_$(Get-Date -Format 'yyyyMMdd_HHmm').csv"
        $inv.VMs | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8 -Delimiter ';'
        Write-Host "  Exportiert nach: $csvPath" -ForegroundColor Green
    }
    Pause-AndContinue
}

function Show-HyperVProcedure {
    param(
        [ValidateSet('Standalone','Cluster','MultiHost')]
        [string]$Mode,
        [Parameter(Mandatory)]$Inventory
    )

    $needCheck  = @($Inventory.VMs | Where-Object { $_.NeedsCheck }).Count
    $vtpmCount  = @($Inventory.VMs | Where-Object { $_.vTPM -and $_.NeedsCheck }).Count
    $linuxCount = @($Inventory.VMs | Where-Object { $_.SecureBootTemplate -match 'UEFI Certificate Authority|OpenSourceShielded' }).Count

    Write-Host ''
    Write-Host '─── Empfohlenes Vorgehen ───' -ForegroundColor Cyan

    if ($needCheck -eq 0) {
        Write-Host '  Keine Gen2-VMs mit aktivem Secure Boot zu bearbeiten.' -ForegroundColor Green
        Write-Host '  Optional: Periodischer Re-Scan, falls neue VMs hinzukommen.' -ForegroundColor DarkGray
        return
    }

    switch ($Mode) {

        'Standalone' {
            Write-Host '  Workflow für Standalone-Host:' -ForegroundColor Yellow
            Write-Host ''
            Write-Host '  Phase 1 – Host vorbereiten:' -ForegroundColor White
            Write-Host '    1. Aktuellen Cumulative Update auf Host installieren'
            Write-Host '    2. OEM-Firmware/BIOS prüfen und ggf. aktualisieren'
            Write-Host '    3. Auf Host: Toolkit Option 8 (Action Plan) ausführen'
            Write-Host '       -> Host selbst kann ggf. ebenfalls CA-Update brauchen'
            Write-Host ''
            Write-Host '  Phase 2 – Pro Gen2-VM (ein-für-eins, Test/Dev zuerst):' -ForegroundColor White
            Write-Host '    a) VM-Snapshot erstellen (Hyper-V Checkpoint)'
            if ($vtpmCount -gt 0) {
                Write-Host "    b) [Bei vTPM, $vtpmCount VMs betroffen] BitLocker in der VM suspenden:" -ForegroundColor Yellow
                Write-Host '         Suspend-BitLocker -MountPoint C: -RebootCount 1' -ForegroundColor DarkGray
            }
            Write-Host '    c) In der VM: Toolkit kopieren und ausführen'
            Write-Host '       Interaktiv: Option 8 (Action Plan), dann Option 9 (Trigger)'
            Write-Host '       Oder per RMM: .\toolkit.ps1 -Quick -AutoTrigger'
            Write-Host '    d) VM neu starten (innerhalb der VM, nicht Hyper-V-Restart)'
            Write-Host '    e) In der VM: Verifikation per Option 4 (Firmware-DB)'
            if ($vtpmCount -gt 0) {
                Write-Host '    f) BitLocker reaktivieren:' -ForegroundColor Yellow
                Write-Host '         Resume-BitLocker -MountPoint C:' -ForegroundColor DarkGray
            }
            Write-Host '    g) Snapshot löschen sobald alles stabil ist'
            Write-Host ''
            Write-Host '  Tipp: VMs in Wellen behandeln, damit nicht alle gleichzeitig'
            Write-Host '        neu starten (Reihenfolge: Test/Dev -> Apps -> DCs zuletzt).'
        }

        'Cluster' {
            Write-Host '  Workflow für Failover Cluster:' -ForegroundColor Yellow
            Write-Host ''
            Write-Host '  Phase 1 – Cluster-Knoten vorbereiten (knotenweise!):' -ForegroundColor White
            Write-Host '    Pro Knoten in Reihenfolge:'
            Write-Host '    1. Knoten in Maintenance-Modus / VMs evakuieren:'
            Write-Host '         Suspend-ClusterNode -Name <Knoten> -Drain' -ForegroundColor DarkGray
            Write-Host '    2. OEM-Firmware/BIOS-Update einspielen + Reboot'
            Write-Host '    3. Aktuellen LCU + Cluster-Updates installieren + Reboot'
            Write-Host '    4. Toolkit Option 8 lokal: Host-CA-Update auslösen'
            Write-Host '    5. Knoten wieder ins Cluster:'
            Write-Host '         Resume-ClusterNode -Name <Knoten> -Failback Immediate' -ForegroundColor DarkGray
            Write-Host '    6. Cluster-Status prüfen (Get-ClusterNode), dann nächster Knoten'
            Write-Host ''
            Write-Host '  Tipp: Cluster Aware Updating (CAU) automatisiert die Hosts-Phase.'
            Write-Host ''
            Write-Host '  Phase 2 – Pro Gen2-VM (live, mit Live Migration im Hintergrund):' -ForegroundColor White
            Write-Host '    a) VM-Backup über Cluster-Backup-Tool (Veeam, etc.)'
            if ($vtpmCount -gt 0) {
                Write-Host "    b) [Bei vTPM, $vtpmCount VMs] BitLocker in VM suspenden!" -ForegroundColor Yellow
                Write-Host '         Suspend-BitLocker -MountPoint C: -RebootCount 1' -ForegroundColor DarkGray
            }
            Write-Host '    c) In der VM: Toolkit ausführen'
            Write-Host '    d) VM neu starten (innerhalb der VM)'
            Write-Host '       -> Live Migration nicht nötig, VM kann auf demselben Host bleiben'
            Write-Host '    e) Verifikation per Option 4 in der VM'
            if ($vtpmCount -gt 0) {
                Write-Host '    f) BitLocker reaktivieren' -ForegroundColor Yellow
            }
            Write-Host ''
            Write-Host '  Reihenfolge / Pacing:' -ForegroundColor White
            Write-Host '    - Test/Dev-VMs zuerst (eine pro Tag/Stunde)'
            Write-Host '    - Produktiv-VMs in Wellen (max. 25% gleichzeitig)'
            Write-Host '    - Domain Controller: NICHT mehrere gleichzeitig!'
            Write-Host '    - Cluster-relevante VMs (Witness etc.) zuletzt'
            Write-Host ''
            Write-Host '  Hyperconverged (S2D / Storage Spaces Direct):' -ForegroundColor White
            Write-Host '    - Storage-Health vor Knoten-Maintenance prüfen:'
            Write-Host '         Get-StorageJob; Get-StorageSubSystem | Get-StorageHealthReport' -ForegroundColor DarkGray
            Write-Host '    - Pro Knoten ausreichend lange warten bis Storage Repair durch ist'
        }

        'MultiHost' {
            Write-Host '  Workflow für Multi-Host (kein Cluster):' -ForegroundColor Yellow
            Write-Host ''
            Write-Host '  Vorgehen wie Standalone, aber je Host:' -ForegroundColor White
            Write-Host '    1. Hosts einzeln in Reihenfolge nach Wichtigkeit abarbeiten'
            Write-Host '    2. Pro Host: Phase 1 (Host-Patches/Firmware) + Phase 2 (VMs)'
            Write-Host '    3. KEINE Live Migration verfügbar -> Wartungsfenster pro Host nötig'
            Write-Host '    4. VM-Reboots produzieren echte Downtime'
            Write-Host ''
            Write-Host '  Falls mehrere Hosts denselben Storage nutzen aber kein Cluster:'
            Write-Host '    - Vorsicht bei VM-Migrationen über Storage'
            Write-Host '    - Lieber pro Host abarbeiten als VMs umzuschieben'
            Write-Host ''
            if ($vtpmCount -gt 0) {
                Write-Host "  ⚠ $vtpmCount VMs mit vTPM – BitLocker pro VM zwingend suspenden!" -ForegroundColor Yellow
            }
        }
    }

    if ($linuxCount -gt 0) {
        Write-Host ''
        Write-Host "  ⚠ $linuxCount VMs mit Linux/Open-Source-Template:" -ForegroundColor DarkYellow
        Write-Host '    Diese folgen einem eigenen Workflow:' -ForegroundColor DarkYellow
        Write-Host '    - Ubuntu/Debian: shim-signed Update via apt' -ForegroundColor DarkYellow
        Write-Host '    - RHEL/Rocky/Alma: shim Update via dnf/yum' -ForegroundColor DarkYellow
        Write-Host '    - Distro-Doku konsultieren, NICHT den Microsoft-Trigger anwenden!' -ForegroundColor DarkYellow
    }
}

function Test-SecureBootPrereqs {
    # Prüft die Voraussetzungen, die der direkte Trigger zwingend braucht.
    # Quellen: KB5025885 / Microsoft "Registry key updates" + mindcore.dk (v3/v4 Findings).
    [CmdletBinding()] param()

    # 1) Geplanter Task – wird vom Juli-2024-CU (oder neuer) mitgeliefert.
    $task = $null
    try { $task = Get-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction Stop } catch { }
    $taskExists = $null -ne $task
    $taskLastResult = $null
    if ($taskExists) {
        try { $taskLastResult = (Get-ScheduledTaskInfo -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction Stop).LastTaskResult } catch { }
    }

    # 2) Payload-Ordner mit .bin-Dateien. Fehlt er, schlägt der Legacy-Task mit 0x80070002 fehl.
    $payloadPath = Join-Path $env:SystemRoot 'System32\SecureBootUpdates'
    $payloadOk = $false; $binCount = 0
    if (Test-Path $payloadPath) {
        $binCount  = @(Get-ChildItem -Path $payloadPath -Filter '*.bin' -ErrorAction SilentlyContinue).Count
        $payloadOk = $binCount -gt 0
    }

    # 3) WinCS (WinCsFlags.exe) – moderner Pfad, der ohne lokale .bin-Payload auskommt (Server 2022+/Win11 23H2+).
    $winCsPath = Join-Path $env:SystemRoot 'System32\WinCsFlags.exe'
    $winCsAvailable = Test-Path $winCsPath

    [PSCustomObject]@{
        TaskExists      = $taskExists
        TaskLastResult  = $taskLastResult
        PayloadPath     = $payloadPath
        PayloadOk       = $payloadOk
        BinCount        = $binCount
        WinCsAvailable  = $winCsAvailable
        WinCsPath       = $winCsPath
        # Trigger über den Task ist nur sinnvoll, wenn Task da ist UND (Payload da ODER WinCS verfügbar)
        CanTrigger      = $taskExists -and ($payloadOk -or $winCsAvailable)
    }
}

function Show-PrereqLines {
    param($Pre)
    $taskColor = if ($Pre.TaskExists) { 'Green' } else { 'Red' }
    Write-Host ("  {0,-26} : {1}" -f 'Secure-Boot-Update Task', $(if ($Pre.TaskExists) { 'vorhanden' } else { 'FEHLT (Juli-2024-CU oder neuer nötig)' })) -ForegroundColor $taskColor
    $payColor = if ($Pre.PayloadOk) { 'Green' } elseif ($Pre.WinCsAvailable) { 'Yellow' } else { 'Red' }
    Write-Host ("  {0,-26} : {1}" -f 'Payload (.bin)', $(if ($Pre.PayloadOk) { "OK ($($Pre.BinCount) Dateien)" } else { "FEHLT in $($Pre.PayloadPath) -> Risiko 0x80070002" })) -ForegroundColor $payColor
    $csColor = if ($Pre.WinCsAvailable) { 'Green' } else { 'DarkGray' }
    Write-Host ("  {0,-26} : {1}" -f 'WinCS (WinCsFlags.exe)', $(if ($Pre.WinCsAvailable) { 'verfügbar (umgeht .bin-Abhängigkeit)' } else { 'nicht vorhanden (nur Server 2022+/Win11 23H2+)' })) -ForegroundColor $csColor
}

function Invoke-DeploymentTrigger {
    Write-Section 'Update auslösen – Secure Boot 2023 CA' -Color Yellow

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
    if ($current.CA2023Status -eq 'Updated' -or $current.CA2023Capable -eq 2) {
        Write-Host '  Hinweis: Gerät ist bereits fertig (Status "Updated" bzw. Capable=2) – nichts zu tun.' -ForegroundColor Green
        Pause-AndContinue; return
    }

    # Voraussetzungen prüfen (Task + Payload/WinCS) – sonst läuft der Trigger ins Leere.
    Write-Host '  ── Voraussetzungen ──' -ForegroundColor Cyan
    $pre = Test-SecureBootPrereqs
    Show-PrereqLines -Pre $pre
    Write-Host ''
    if (-not $pre.TaskExists) {
        Write-Host '  Abbruch: Geplanter Task "Secure-Boot-Update" fehlt. Aktuellen CU (Juli 2024+) einspielen.' -ForegroundColor Red
        Pause-AndContinue; return
    }
    if (-not $pre.PayloadOk -and -not $pre.WinCsAvailable) {
        Write-Host '  WARNUNG: Weder .bin-Payload noch WinCS vorhanden – Trigger schlägt vermutlich mit 0x80070002 fehl.' -ForegroundColor Red
        if ((Read-Host '  Trotzdem fortfahren? (j/N)') -ne 'j') { Pause-AndContinue; return }
    }

    # BitLocker-Warnung: PCR 7 ändert sich beim Boot-Manager-Wechsel.
    try {
        $blv = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
        if ($blv.ProtectionStatus -eq 'On') {
            Write-Host "  ⚠ BitLocker ist auf $($env:SystemDrive) AKTIV. PCR 7 ändert sich beim Boot-Manager-Wechsel." -ForegroundColor Yellow
            Write-Host '    Empfohlen vor dem Reboot:  Suspend-BitLocker -MountPoint C: -RebootCount 1' -ForegroundColor DarkGray
            Write-Host '    Recovery-Key-Escrow (Entra ID / AD) vorher verifizieren!' -ForegroundColor DarkGray
            Write-Host ''
        }
    } catch { }

    # Methode wählen
    Write-Host '  Welche Methode?' -ForegroundColor Cyan
    Write-Host '   1) Volles Bundle  AvailableUpdates=0x5944  (Microsoft IT-managed Standard – DB+KEK+Boot Manager)'
    Write-Host '   2) Phase 1 nur     AvailableUpdates=0x140   (DB + Boot Manager, REVERSIBEL – konservativ)'
    Write-Host '   3) Phase 2 REVOKE  AvailableUpdates=0x280   (2011 via DBX sperren – IRREVERSIBEL!)' -ForegroundColor Red
    Write-Host '   Z) Zurück'
    $m = (Read-Host '  Auswahl').Trim().ToUpper()
    if ($m -eq 'Z' -or [string]::IsNullOrWhiteSpace($m)) { return }

    $value = $null; $label = ''; $irreversible = $false
    switch ($m) {
        '1' { $value = 0x5944; $label = 'Volles Bundle (0x5944)' }
        '2' { $value = 0x140;  $label = 'Phase 1 DB + Boot Manager (0x140, reversibel)' }
        '3' { $value = 0x280;  $label = 'Phase 2 Revocation (0x280, IRREVERSIBEL)'; $irreversible = $true }
        default { Write-Host '  Ungültig.' -ForegroundColor Red; Pause-AndContinue; return }
    }

    Write-Host ''
    Write-Host "  Gewählt: $label" -ForegroundColor Yellow
    if ($irreversible) {
        Write-Host '  ⚠⚠ Diese Phase sperrt die 2011-Zertifikate per DBX. Solange Secure Boot aktiv ist,' -ForegroundColor Red
        Write-Host '      gibt es KEINEN Rollback. Nur ausführen, wenn Capable=2 bereits erreicht und auf' -ForegroundColor Red
        Write-Host '      identischer Pilot-Hardware validiert wurde.' -ForegroundColor Red
        if ($current.CA2023Capable -ne 2) {
            Write-Host '  Abbruch: Capable ist noch nicht 2. Erst Phase 1 abschliessen + Reboot.' -ForegroundColor Red
            Pause-AndContinue; return
        }
    }
    Write-Host ''

    Write-Host '  Bestätigung 1/2: Trigger auf DIESEM Server setzen?' -ForegroundColor Yellow
    $confirmWord = if ($irreversible) { 'REVOKE' } else { 'JA' }
    $c1 = Read-Host "  Tippe `"$confirmWord`" zum Bestätigen"
    if ($c1 -ne $confirmWord) { Write-Host '  Abgebrochen.' -ForegroundColor DarkGray; Pause-AndContinue; return }

    Write-Host ''
    Write-Host "  Bestätigung 2/2: Servername zur Verifikation eingeben ($env:COMPUTERNAME):" -ForegroundColor Yellow
    $c2 = Read-Host '  Servername'
    if ($c2 -ne $env:COMPUTERNAME) { Write-Host '  Servername stimmt nicht – abgebrochen.' -ForegroundColor Red; Pause-AndContinue; return }

    try {
        New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' `
            -Name 'AvailableUpdates' -Value $value -PropertyType DWord -Force | Out-Null
        Write-Host ''
        Write-Host ("  AvailableUpdates auf 0x{0:X} gesetzt." -f $value) -ForegroundColor Green
        try {
            Start-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction Stop
            Write-Host '  Geplanter Task gestartet.' -ForegroundColor Green
        } catch {
            Write-Host '  Task konnte nicht sofort gestartet werden – läuft sonst automatisch (alle 12h).' -ForegroundColor DarkGray
        }
        Write-Host '  Nächste Schritte:' -ForegroundColor Cyan
        Write-Host '    - Wenn AvailableUpdates auf 0x4100 steht: Reboot durchführen.'
        Write-Host '    - Nach Reboot dieses Script erneut: Capable sollte Richtung 2 wandern.'
        Write-Host '    - Verifikation mit Option 4 (Firmware-DB) und Option 1 (Capable=2).'
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
  Die UEFI Secure Boot Zertifikate von 2011 laufen 2026 ab.
  Server bekommen die neuen 2023 CAs NICHT automatisch via Windows
  Update – das muss manuell ausgerollt werden.

  WICHTIG: Server brickt NICHT, wenn die Zertifikate ablaufen.
  Bestehende Boot Manager wurden seinerzeit mit gültigem Cert
  signiert und booten weiter. Was kaputt geht:
    - Neue Boot Manager Updates können nicht verifiziert werden.
    - DBX-Revocations (Sperrlisten) werden nicht mehr akzeptiert.
    - Recovery-Medien mit 2023-signierten Komponenten booten nicht.
    - Security-Posture verfällt mit der Zeit (BlackLotus etc.).

  Zertifikate und Ablaufdaten:
  ────────────────────────────
  Altes Zertifikat                    Ablauf    Neues Zertifikat
  ─────────────────────────────────── ───────── ──────────────────────────
  Microsoft Corporation KEK CA 2011   Jun 2026  KEK 2K CA 2023
  Microsoft UEFI CA 2011              Jun 2026  Microsoft UEFI CA 2023
                                                + Option ROM UEFI CA 2023
  Microsoft Windows Production PCA    Okt 2026  Windows UEFI CA 2023
    (signiert Windows Boot Manager)

  Anwendbare Server-SKUs:
  ───────────────────────
  Server 2012 ESU, 2012 R2 ESU, 2016, 2019, 2022, 2025
  (Server 2012/R2 nur mit Extended Security Updates)

  Workflow für deine Umgebung:
  ────────────────────────────
  1. Inventar: Option 3 (Remote Check) gegen alle Server.
  2. Auf Hyper-V Hosts: Option V – Gen2-VMs erkennen, die nachgezogen
     werden müssen.
  3. Pro Server/VM: Option 8 (Action Plan) für tailored Empfehlung.
  4. Hardware/Firmware: Option 5 für BIOS-Stand und OEM-Doku-Link.
  5. Bei "Status-Key fehlt": LCU-Patchstand hochziehen.
  6. Pilot-Server: Option 9 (Trigger setzen).
     - 12h warten oder Task manuell starten.
     - Reboot.
     - Mit Option 4 verifizieren, dass 2023 CAs in Firmware sind.
  7. Auf Server-Flotte ausrollen – idealerweise per GPO.

  Hyper-V Besonderheiten:
  ───────────────────────
  - Gen1-VMs: kein Secure Boot, ignorieren.
  - Gen2-VMs: jede VM ist ihre eigene Firmware-Welt, Update muss IN
    der VM laufen, nicht vom Host aus.
  - vTPM + BitLocker: BitLocker vorher suspenden:
      Suspend-BitLocker -MountPoint C: -RebootCount 1
  - Linux-VMs (Template "UEFI Certificate Authority"): folgen einem
    eigenen Workflow via Distro-SHIM, nicht Microsoft-Trigger.

  Wichtige Werte (Pfad: HKLM\SYSTEM\CurrentControlSet\Control\Secureboot):
  ──────────────────────────────────────────────────────────────────────
  Zwei verschiedene 0x5944, NICHT verwechseln:
    MicrosoftUpdateManagedOptIn = 0x5944
        -> Opt-In für den von Windows Update gesteuerten Staged-Rollout
           (hands-off, Microsoft liefert per WU). Braucht Required-Telemetrie
           + laufenden DiagTrack-Dienst, sonst greift die WU-Sicherheitslogik nicht.
    AvailableUpdates = 0x5944
        -> Direkter Trigger: Windows arbeitet das volle Bundle JETZT ab
           (DB + KEK + Boot Manager). Das ist der Server-/RMM-Weg.

  AvailableUpdates – Bitmasken (werden nach erfolgreicher Verarbeitung gelöscht):
    0x40   -> nur DB: Windows UEFI CA 2023 in die DB schreiben (Mitigation 1)
    0x100  -> Boot Manager auf 2023-signiert umstellen (Mitigation 2)
    0x140  -> 0x40 + 0x100 (DB + Boot Manager, REVERSIBEL) – konservative Phase 1
    0x280  -> 2011 via DBX sperren + SVN-Bump – IRREVERSIBEL – Phase 2
    0x5944 -> komplettes Bundle auf einmal (Microsoft IT-managed Standard)
    Verlauf nach Trigger: 0x5944 -> 0x4100 (=Reboot fällig) -> 0x4000 -> 0x0 (fertig)

  WindowsUEFICA2023Capable – der verlässlichste Fertig-Indikator:
    0 -> 2023 CA nicht in der DB
    1 -> in der DB, bootet aber noch alten 2011-Chain (Stage 4 – ein Reboot fehlt)
    2 -> in der DB UND bootet vom 2023 Boot Manager (= fertig)
    (Wert liegt je nach Build unter ...\Secureboot oder ...\Secureboot\Servicing)

  CA2023Status      NotStarted / InProgress / Updated
  CA2023Error       2147942750 nach 0x100 = Staging-Signal (Reboot fällig), KEIN Fehler

  Voraussetzungen für den Trigger:
  ────────────────────────────────
  - Geplanter Task \Microsoft\Windows\PI\Secure-Boot-Update muss existieren
    (kommt mit dem Juli-2024-CU oder neuer). Fehlt er -> Trigger läuft ins Leere.
  - Payload-.bin in C:\Windows\System32\SecureBootUpdates. Fehlen sie, schlägt der
    Legacy-Task mit 0x80070002 fehl. Moderner Weg WinCS (WinCsFlags.exe, Server 2022+/
    Win11 23H2+) umgeht die .bin-Abhängigkeit.
  - BitLocker: PCR 7 ändert sich beim Boot-Manager-Wechsel. Vor dem Reboot
    Suspend-BitLocker -MountPoint C: -RebootCount 1 und Recovery-Key-Escrow prüfen.

  Events:
    1036/1043/1044/1045  Boot-Zeit Kontext-Events (Eventtext lesen)
    1795  Firmware-Übergabe fehlgeschlagen
    1796/1798  DB/Variablen-Update Ereignisse (Eventtext lesen)
    1797  Update fehlgeschlagen – 2023 CA fehlt in DB
    1800  Reboot nötig
    1801  Update läuft / nicht (vollständig) angewandt
    1803  PK-signed KEK fehlt -> OEM kontaktieren
    1808  Erfolg

  Quick/RMM-Modus:
  ────────────────
  Für RMM-Integration kann das Script nicht-interaktiv laufen:
    .\SecureBoot2023-Toolkit.ps1 -Quick
  Gibt eine Status-Line aus und endet mit Exit-Code:
    0 = OK (Capable=2 / 2023 CAs aktiv, oder N/A: Legacy BIOS, Gen1, SB disabled)
    1 = Action needed
    2 = Error (inkl. BLOCKED: Task fehlt oder Payload/WinCS fehlt)
    3 = Trigger gesetzt (wenn -AutoTrigger genutzt)
  Mit -AutoTrigger wird AvailableUpdates=0x5944 automatisch gesetzt:
    .\SecureBoot2023-Toolkit.ps1 -Quick -AutoTrigger
  ACHTUNG: -AutoTrigger umgeht alle Sicherheitsabfragen! Es prüft aber vorher,
  ob der Task existiert und Payload/WinCS da ist – sonst BLOCKED + Exit 2.

  Wichtige Diagnose-Falle:
  ────────────────────────
  Wenn BIOS sagt "Secure Boot enabled" aber Windows sagt disabled:
  Check System Mode (Option 4). Wenn dort "Setup Mode" steht, ist
  der PK weg/ungültig. Fix:
    BIOS -> Secure Boot Mode = Custom -> Restore Factory Keys
    -> Reboot -> Mode = Standard

  Doku (KB-Referenzen):
  ─────────────────────
  KB5062710  Übersicht (Einstiegspunkt)
  KB5062713  IT-Profi Leitfaden
  KB5068202  Registry Keys
  KB5068198  GPO-Methode
  KB5068197  WinCS APIs (nur Server 2022+)
  KB5073196  Intune-Methode
  KB5081884  Updates & Ankündigungen
  KB5068008  FAQ
  KB5079373  Was passiert bei Ablauf
  KB5067177  OEM-Seiten Sammlung

  Weitere nützliche Ressourcen:
  ─────────────────────────────
  - github.com/cjee21/Check-UEFISecureBootVariables  (Skripte)
  - andysblog.de "Secure Boot-Zertifikate laufen im Juni 2026 ab"
  - borncity.com  (mehrere ausführliche Artikel)
  - Sioni Secure Boot Zertifikat-Prüfer  (GUI-Tool)
  - blog.mindcore.dk  Intune-Remediation + 40-Tage-Fallback-Fallstudie (v3/v4)
  - github.com/mmelkersen/EndpointManager  (Detect/Remediate Client-Skripte)
  - Microsoft "Registry key updates for Secure Boot" (AvailableUpdates 0x5944-Verlauf)

  URLs:
  ─────
  Server Playbook : https://aka.ms/GetSecureBoot
  Doku-Index DE   : https://support.microsoft.com/de-de/help/5062710
  Doku-Index EN   : https://support.microsoft.com/topic/7ff40d33
  Act-now Blog    : https://techcommunity.microsoft.com/blog/windows-itpro-blog/4426856
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
    if ($script:HasHyperV) {
        Write-Host '  ── HYPER-V ──' -ForegroundColor DarkCyan
        Write-Host '   V) Hyper-V VM Inventory (Gen2-VMs auf Host/Cluster)' -ForegroundColor Magenta
        Write-Host ''
    }
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

# Hyper-V verfügbar?
$script:HasHyperV = $null -ne (Get-Module -ListAvailable Hyper-V -ErrorAction SilentlyContinue)

# ─── Quick / RMM Mode ─────────────────────────────────────────────────
# Nicht-interaktive Ausgabe für RMM-Integration. Ein Status-Line + Exit-Code.
if ($Quick) {
    $r = Get-SecureBootStatusLocal
    $hostname = $env:COMPUTERNAME

    if (-not $r.SecureBootSupported) {
        Write-Output "$hostname | N/A | SecureBoot not supported"
        exit 0
    }
    if (-not $r.SecureBootEnabled) {
        Write-Output "$hostname | N/A | SecureBoot disabled"
        exit 0
    }
    if ($r.HasError) {
        Write-Output ("$hostname | ERROR | Status={0} Error={1}" -f $r.CA2023Status, $r.CA2023ErrorCode)
        exit 2
    }
    if ($r.CA2023Capable -eq 2 -or ($r.CA2023Status -eq 'Updated' -and $r.FirmwareHas2023CA)) {
        Write-Output "$hostname | OK | Capable=2 / 2023 CAs in Firmware aktiv"
        exit 0
    }
    if ($r.CA2023Capable -eq 1) {
        Write-Output "$hostname | ACTION | Stage 4: 2023 CA in DB, Reboot fehlt (Capable=1)"
        # weiter unten (AutoTrigger setzt hier nichts mehr, da Cert schon in DB)
    }

    # Action needed
    Write-Output ("$hostname | ACTION | Status={0} Capable={1} FirmwareHas2023CA={2} AvailableUpdates={3}" -f `
        $r.CA2023Status, $r.CA2023Capable, $r.FirmwareHas2023CA, $r.AvailableUpdates)

    if ($AutoTrigger -and $r.CA2023Status -ne 'InProgress' -and $r.CA2023Status -ne 'Updated' -and $r.CA2023Capable -ne 2) {
        $pre = Test-SecureBootPrereqs
        if (-not $pre.TaskExists) {
            Write-Output "$hostname | BLOCKED | Secure-Boot-Update Task fehlt (CU Juli 2024+ nötig)"
            exit 2
        }
        if (-not $pre.PayloadOk -and -not $pre.WinCsAvailable) {
            Write-Output "$hostname | BLOCKED | Payload (.bin) fehlt und kein WinCS -> Risiko 0x80070002"
            exit 2
        }
        try {
            New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot' `
                -Name 'AvailableUpdates' -Value 0x5944 -PropertyType DWord -Force | Out-Null
            try {
                Start-ScheduledTask -TaskPath '\Microsoft\Windows\PI\' -TaskName 'Secure-Boot-Update' -ErrorAction Stop
            } catch { }
            Write-Output "$hostname | TRIGGERED | AvailableUpdates=0x5944, Task gestartet"
            exit 3
        } catch {
            Write-Output "$hostname | ERROR | Trigger failed: $($_.Exception.Message)"
            exit 2
        }
    }
    exit 1
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
        'V' { if ($script:HasHyperV) { Show-HyperVHostInventory } else { Write-Host '  Hyper-V nicht verfügbar.' -ForegroundColor Red; Start-Sleep -Seconds 1 } }
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
