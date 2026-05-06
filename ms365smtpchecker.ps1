<#
.SYNOPSIS
    Testet SMTP-Submission an Microsoft 365 (smtp.office365.com:587).

.DESCRIPTION
    Schickt eine Testmail über M365 SMTP mit Basic Auth, prüft TCP-Reachability,
    misst Submission-Latenz und übersetzt häufige SMTP-Fehlercodes in
    Klartext-Diagnose mit konkreten Fix-Befehlen.

    Hinweis: Microsoft hat ab April 2026 begonnen Basic Auth für Client
    Submission stufenweise zurückzuweisen. Langfristig: OAuth2 / XOAUTH2.
    Dieses Skript ist als Verbindungs- und Konfigurations-Test gedacht.

.PARAMETER To
    Empfänger-Adresse (z.B. externes Test-Postfach).

.PARAMETER Credential
    PSCredential des M365-Postfachs. Username = UPN.

.PARAMETER From
    Optional. From-Adresse. Default: Username der Credential.
    Bei abweichender From-Adresse braucht der Auth-User Send-As-Permission.

.PARAMETER SmtpServer
    Default: smtp.office365.com

.PARAMETER Port
    Default: 587 (STARTTLS)

.EXAMPLE
    $cred = Get-Credential -UserName praxis-mailer@vetbern.ch
    .\Test-M365Smtp.ps1 -To rueegg@pcrepair.ch -Credential $cred

.EXAMPLE
    # Send-As-Test (info@ als From, Auth via praxis-mailer@):
    $cred = Get-Credential -UserName praxis-mailer@vetbern.ch
    .\Test-M365Smtp.ps1 -To rueegg@pcrepair.ch -From info@vetbern.ch -Credential $cred
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$To,

    [Parameter(Mandatory)]
    [pscredential]$Credential,

    [string]$From = $Credential.UserName,

    [string]$SmtpServer = 'smtp.office365.com',

    [int]$Port = 587,

    [string]$Subject = "M365 SMTP Test $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",

    [string]$Body
)

if (-not $Body) {
    $Body = @"
Automated SMTP submission test.

Server:    ${SmtpServer}:${Port}
Auth user: $($Credential.UserName)
From:      $From
To:        $To
Hostname:  $(hostname)
Timestamp: $(Get-Date -Format o)
"@
}

Write-Host ""
Write-Host "M365 SMTP Submission Test" -ForegroundColor White
Write-Host ("-" * 50) -ForegroundColor DarkGray

# === 1. TCP-Reachability ===
Write-Host ""
Write-Host "[1/2] TCP ${SmtpServer}:${Port}" -ForegroundColor Cyan

$tcp = Test-NetConnection -ComputerName $SmtpServer -Port $Port -WarningAction SilentlyContinue
if (-not $tcp.TcpTestSucceeded) {
    Write-Host "      FAIL — keine TCP-Verbindung." -ForegroundColor Red
    Write-Host "      Wahrscheinliche Ursache:" -ForegroundColor Yellow
    Write-Host "        - Outbound-Firewall blockt Port $Port" -ForegroundColor Yellow
    Write-Host "        - Proxy/Gateway zwingt zu Inspection (TLS-Strip)" -ForegroundColor Yellow
    Write-Host "        - DNS-Auflösung fehlgeschlagen" -ForegroundColor Yellow
    return
}
Write-Host "      OK   $($tcp.RemoteAddress)" -ForegroundColor Green

# === 2. SMTP submission ===
Write-Host ""
Write-Host "[2/2] Submission als $($Credential.UserName) -> $To" -ForegroundColor Cyan

$params = @{
    SmtpServer  = $SmtpServer
    Port        = $Port
    UseSsl      = $true
    Credential  = $Credential
    From        = $From
    To          = $To
    Subject     = $Subject
    Body        = $Body
    Encoding    = [System.Text.Encoding]::UTF8
    ErrorAction = 'Stop'
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    Send-MailMessage @params -WarningAction SilentlyContinue
    $sw.Stop()
    Write-Host "      OK   submitted in $($sw.ElapsedMilliseconds) ms" -ForegroundColor Green
    Write-Host ""
    Write-Host "Verify in Inbox UND Junk-Folder von $To" -ForegroundColor White
    Write-Host ""
    return
}
catch {
    $sw.Stop()
    $errMsg = $_.Exception.Message
    $errInner = if ($_.Exception.InnerException) { $_.Exception.InnerException.Message } else { '' }
    $errFull = "$errMsg $errInner"
    $authUser = $Credential.UserName

    Write-Host "      FAIL nach $($sw.ElapsedMilliseconds) ms" -ForegroundColor Red
    Write-Host ""
    Write-Host "Fehler:" -ForegroundColor Yellow
    Write-Host "  $errMsg" -ForegroundColor White
    if ($errInner) { Write-Host "  $errInner" -ForegroundColor White }

    # M365-spezifische SMTP-Fehlercodes übersetzen
    $diagnosis = switch -Regex ($errFull) {
        '5\.7\.30' {
            @"
550 5.7.30 - Basic Auth fuer Client Submission abgelehnt.
  - Microsoft baut Basic Auth seit April 2026 stufenweise ab.
  - Loesung 1: OAuth2 / XOAUTH2 implementieren.
  - Loesung 2 (temporaer): Authentication Policy mit AllowBasicAuthSmtp.
"@
            break
        }
        '5\.7\.57' {
            @"
5.7.57 - SMTP AUTH am Postfach deaktiviert.
  Fix:
    Connect-ExchangeOnline
    Set-CASMailbox -Identity '$authUser' -SmtpClientAuthenticationDisabled `$false
"@
            break
        }
        '5\.7\.139' {
            @"
5.7.139 - SMTP AUTH tenant-weit oder per Authentication Policy gesperrt.
  Check tenant-weit:
    Get-TransportConfig | fl SmtpClientAuthenticationDisabled
  Check Auth Policy:
    Get-User '$authUser' | fl AuthenticationPolicy
    Get-AuthenticationPolicy | fl Identity, AllowBasicAuthSmtp
"@
            break
        }
        '5\.7\.60' {
            @"
5.7.60 - Auth-User '$authUser' darf nicht als '$From' senden.
  Fix (Send-As-Permission):
    Add-RecipientPermission -Identity '$From' -Trustee '$authUser' -AccessRights SendAs
"@
            break
        }
        '5\.7\.708' {
            @"
5.7.708 - Authentication Policy oder Conditional Access blockt.
  Check:
    - Conditional Access Policies in Entra ID — Service-Account exkludieren
    - Authentication Policy auf User: Get-User '$authUser' | fl AuthenticationPolicy
"@
            break
        }
        '5\.7\.3' {
            @"
5.7.3 - Authentication unsuccessful (Auth nicht erfolgreich).
  - Basic Auth: Username/Passwort pruefen.
  - OAuth: ServicePrincipal in Exchange Online registriert? Object ID korrekt
    aus Enterprise Applications (NICHT App Registration)?
"@
            break
        }
        '535' {
            @"
535 - Auth fehlgeschlagen.
  - Passwort falsch?
  - MFA aktiv? Service-Accounts brauchen MFA-Exclusion via Conditional Access
    oder einen Auth-Policy-Bypass.
  - Account gesperrt? Check: Get-User '$authUser' | fl AccountDisabled
"@
            break
        }
        '550 5\.1\.[01]' {
            "550 5.1.x - Empfaenger '$To' ungueltig oder Postfach existiert nicht."
            break
        }
        '550' {
            "550 - Generische Ablehnung. Originalfehler oben fuer Details."
            break
        }
        default {
            "(keine spezifische Diagnose - Originalfehler oben pruefen)"
        }
    }

    Write-Host ""
    Write-Host "Diagnose:" -ForegroundColor Magenta
    Write-Host $diagnosis -ForegroundColor White
    Write-Host ""
}
