# SecureBoot 2023 CA Toolkit

Interaktives PowerShell-Toolkit zur Inventarisierung, Diagnose und (optional) zum Auslösen des Secure Boot 2023 CA-Updates auf Windows Server. Funktioniert lokal, remote und auf Hyper-V-Hosts inklusive Failover Clustern.

## Hintergrund

Die Microsoft UEFI Secure Boot Zertifikate von 2011 laufen 2026 ab:

| Zertifikat | Ablauf | Nachfolger |
|------------|--------|------------|
| Microsoft Corporation KEK CA 2011 | Juni 2026 | KEK 2K CA 2023 |
| Microsoft UEFI CA 2011 | Juni 2026 | Microsoft UEFI CA 2023 + Option ROM UEFI CA 2023 |
| Microsoft Windows Production PCA 2011 | Oktober 2026 | Windows UEFI CA 2023 |

Anders als Windows-Clients erhalten Server die 2023 CAs **nicht automatisch** über Windows Update. Der Rollout muss manuell durch einen Administrator angestossen werden. Server brickt nicht beim Ablauf, aber neue DBX-Revocations, Boot Manager-Updates und Recovery-Szenarien funktionieren nicht mehr — die Security-Posture verfällt schleichend.

## Features

- **Lokaler Quick Status Check** mit Übersicht über alle relevanten Werte
- **Detaillierte Diagnose** mit Registry, Events und Bewertung
- **Remote Check** über mehrere Server via WinRM mit CSV-Export
- **Firmware-DB-Verifikation**: prüft tatsächliche Cert-Inhalte in DB/KEK plus Setup Mode vs User Mode
- **Hardware-Inventur**: BIOS-Stand mit Alters-Bewertung, OEM-spezifische Update-Hinweise (Dell/HPE/Lenovo/Cisco/Supermicro/Fujitsu/Huawei)
- **Patchstand-Analyse** mit Alter des letzten LCU
- **Event-Log Browser** für die relevanten Event-IDs (1795, 1797, 1800, 1801, 1803, 1808)
- **Action Plan**: kontext-spezifische, tailored Empfehlungen basierend auf erkanntem Zustand
- **Trigger-Funktion** mit doppelter Sicherheitsabfrage
- **Hyper-V VM Inventory** mit Submenü:
  - Standalone Host
  - Failover Cluster (alle Knoten)
  - Multi-Host (manuelle Liste)
  - Pro Modus eigener Workflow-Vorschlag (inkl. CAU/S2D bei Cluster)
- **Quick/RMM-Modus** für nicht-interaktive Ausführung mit Exit-Codes

## Voraussetzungen

- Windows Server 2016 / 2019 / 2022 / 2025 oder Windows 10/11
- PowerShell 5.1 oder 7+
- Administratorrechte
- Für Hyper-V-Optionen: Hyper-V-Modul installiert
- Für Cluster-Scans: FailoverClusters-Modul
- Für Remote-Scans: WinRM auf Zielsystemen aktiv

## Installation

Skript herunterladen und entpacken. Keine weitere Installation nötig:

```powershell
# Beispiel: Skript nach C:\Tools kopieren
Copy-Item .\SecureBoot2023-Toolkit.ps1 C:\Tools\
```

Falls Execution Policy ein Problem ist:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## Verwendung

### Interaktiver Modus (Menü)

```powershell
.\SecureBoot2023-Toolkit.ps1
```

Zeigt das Hauptmenü. Navigation über Zifferntasten / Buchstaben.

### Quick / RMM-Modus

Nicht-interaktiv, eine Status-Line + Exit-Code:

```powershell
.\SecureBoot2023-Toolkit.ps1 -Quick
```

Mit automatischem Trigger (umgeht Sicherheitsabfragen, nur in geprüften RMM-Workflows verwenden):

```powershell
.\SecureBoot2023-Toolkit.ps1 -Quick -AutoTrigger
```

**Exit-Codes:**

| Code | Bedeutung |
|------|-----------|
| 0 | OK oder N/A (Legacy BIOS, Gen1, Secure Boot deaktiviert) |
| 1 | Action needed |
| 2 | Error |
| 3 | Trigger gesetzt (nur bei `-AutoTrigger`) |

**Output-Format:**

```
HOSTNAME | STATUS | Details
```

## Menü-Übersicht

```
DIAGNOSE
 1) Quick Status Check (lokal)
 2) Detaillierte Info (lokal, inkl. Events & Registry)
 3) Remote Check für mehrere Server
 4) Firmware-DB prüfen (sind 2023 CAs aktiv?)

KONTEXT
 5) Hardware & Firmware Info (BIOS, OEM, TPM)
 6) Patchstand & OS-Build
 7) Event-Log Details

HYPER-V (nur auf Hyper-V Hosts sichtbar)
 V) Hyper-V VM Inventory
    ├ 1) Lokaler Host
    ├ 2) Failover Cluster
    └ 3) Spezifische Hosts

PLANUNG & AKTION
 8) Action Plan – was muss ich tun?
 9) Update auslösen (Trigger setzen)

INFO
 H) Hintergrund & Hilfe
 Q) Beenden
```

## Beispiele

### Einzelnen Server prüfen

```powershell
.\SecureBoot2023-Toolkit.ps1
# -> Option 8 (Action Plan)
```

### Inventar über alle AD-Server

```powershell
$servers = Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' |
           Select-Object -ExpandProperty Name

Invoke-Command -ComputerName $servers -FilePath .\SecureBoot2023-Toolkit.ps1 -ArgumentList $true |
    Sort-Object NeedsAction, HasError -Descending |
    Format-Table ComputerName, OS, CA2023Status, FirmwareHas2023CA, Summary -AutoSize
```

### RMM-Sammelabfrage

```powershell
$results = Invoke-Command -ComputerName $servers -FilePath .\SecureBoot2023-Toolkit.ps1 -ArgumentList $true 2>&1
$results | Where-Object { $_ -match '\| ACTION \|' }
```

### Hyper-V Cluster-Inventar

Auf einem Cluster-Knoten ausführen:

```powershell
.\SecureBoot2023-Toolkit.ps1
# -> Option V -> 2 (Failover Cluster)
```

## Hyper-V Workflows

Pro Scan-Modus generiert das Toolkit eine eigene, kontext-spezifische Vorgehensempfehlung.

### Standalone-Host

1. Host vorbereiten (LCU, Firmware, Host-CA-Update)
2. Pro Gen2-VM in Wellen: Snapshot → BitLocker suspenden (bei vTPM) → Toolkit in VM ausführen → Reboot → Verify

### Failover Cluster

**Phase 1 — Knoten:**

```powershell
Suspend-ClusterNode -Name <Knoten> -Drain
# Firmware/LCU + Reboot
Resume-ClusterNode -Name <Knoten> -Failback Immediate
```

Cluster Aware Updating (CAU) automatisiert diese Phase.

**Phase 2 — VMs (live, in Wellen):**

- Test/Dev zuerst
- Produktiv max. 25% gleichzeitig
- DCs einzeln
- Cluster-relevante VMs (Witness etc.) zuletzt

**Bei S2D / Hyperconverged**: Storage-Health vor Knoten-Maintenance prüfen.

```powershell
Get-StorageJob
Get-StorageSubSystem | Get-StorageHealthReport
```

### Linux Gen2-VMs

Verwenden in der Regel das Template "Microsoft UEFI Certificate Authority". Das Toolkit erkennt das automatisch und warnt — diese VMs **nicht** mit dem Microsoft-Trigger updaten, sondern via Distro-SHIM:

- Ubuntu / Debian: `apt install --reinstall shim-signed`
- RHEL / Rocky / Alma: `dnf reinstall shim-x64`

## Troubleshooting

### `UEFICA2023Status`-Key fehlt

Servicing-Stack ist noch nicht ready. Aktuellen Cumulative Update installieren, danach erneut prüfen. Bei WSUS-Umgebungen Approval prüfen.

### BIOS sagt "Secure Boot enabled", Windows sagt "disabled"

System ist im **Setup Mode** (PK fehlt oder gelöscht). Fix:

1. BIOS-Setup öffnen
2. Secure Boot Mode auf **Custom** stellen
3. **Restore Factory Keys** ausführen
4. Reboot
5. Secure Boot Mode auf **Standard** zurücksetzen

Option 4 im Toolkit zeigt den Setup Mode an.

### Event 1803 nach Trigger

`PK-signed KEK fehlt` — OEM kontaktieren oder Firmware-Update einspielen. Bei sehr alten Servern eventuell EOSL-Status prüfen.

### Event 1795 nach Trigger

Firmware kann die neuen Zertifikate nicht aufnehmen. OEM-BIOS-Update einspielen, dann erneut versuchen.

### `AvailableUpdates` bleibt auf `0x4104` hängen

Deployment kommt nicht über die KEK-Phase hinaus. Zeigt sich oft mit Event 1803 — siehe oben.

### Hyper-V Gen2 VM mit BitLocker geht nach Reboot in Recovery

vTPM-Messungen haben sich durch Cert-Update geändert, BitLocker-Recovery wurde nicht suspended. Recovery-Key bereithalten, einmalig recovern, BitLocker re-aktivieren. Beim nächsten Mal vorher:

```powershell
Suspend-BitLocker -MountPoint C: -RebootCount 1
```

## Wichtige Werte

**AvailableUpdates Bit-Werte:**

| Wert | Bedeutung |
|------|-----------|
| `0x5944` | Voller Rollout angestossen |
| `0x4104` | KEK-Phase |
| `0x4100` | Boot Manager-Phase ausstehend |
| `0x4000` | Komplett, evtl. noch Reboot |

**CA2023Status:** `NotStarted` / `InProgress` / `Updated`

**Event-IDs (System-Log):**

| ID | Bedeutung |
|----|-----------|
| 1795 | Firmware-Übergabe fehlgeschlagen |
| 1797 | Update fehlgeschlagen — 2023 CA fehlt in DB |
| 1800 | Reboot nötig |
| 1801 | Update läuft / nicht vollständig angewandt |
| 1803 | PK-signed KEK fehlt — OEM kontaktieren |
| 1808 | Erfolg: 2023 CAs in Firmware |

## Referenzen

**Microsoft KB:**

- [KB5062710](https://support.microsoft.com/de-de/help/5062710) — Übersicht (Einstiegspunkt, deutsch)
- [KB5062713](https://support.microsoft.com/help/5062713) — IT-Profi-Leitfaden
- [KB5068202](https://support.microsoft.com/help/5068202) — Registry Keys
- [KB5068198](https://support.microsoft.com/help/5068198) — GPO-Methode
- [KB5068197](https://support.microsoft.com/help/5068197) — WinCS APIs (Server 2022+)
- [KB5067177](https://support.microsoft.com/help/5067177) — OEM-Seiten Sammlung

**Microsoft Tech Community:**

- [Server Playbook](https://aka.ms/GetSecureBoot)
- [Refreshing the root of trust](https://blogs.windows.com/windowsexperience/) — Industriekollaboration

**Praxisnahe Community-Quellen:**

- Andy's Blog — "Secure Boot-Zertifikate laufen im Juni 2026 ab"
- Born City Blog — mehrere ausführliche Artikel
- GitHub: [cjee21/Check-UEFISecureBootVariables](https://github.com/cjee21/Check-UEFISecureBootVariables) — ergänzende Skripte

## Versionsstand

Dokumentation auf Stand von Mai 2026. Microsoft updated die Doku regelmässig — bei Unklarheiten immer die KB-Quellen prüfen.

## Lizenz / Disclaimer

Internes Tool. Bitte vor produktivem Einsatz auf einem Pilotsystem testen. Der Trigger zur Cert-Aktualisierung ist eine eingreifende Aktion — Backup/Snapshot vorher ist Pflicht.
