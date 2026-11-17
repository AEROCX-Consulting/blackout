# AEROCX Blackout installeren op Windows, zonder installatieprogramma, in een regel (PowerShell of Terminal):
#
#   irm https://blackout.aerocx.be/install.ps1 | iex
#
# Verwijderen (je gegevens blijven bewaard):
#
#   & ([scriptblock]::Create((irm https://blackout.aerocx.be/install.ps1))) -Remove
#
# Wat het doet: de app downloaden en controleren (SHA-256), per gebruiker installeren in
# %LOCALAPPDATA%\Programs\AEROCX Blackout, snelkoppeling in Start, automatisch starten bij aanmelden
# (register, Run-sleutel) en je browser openen. Geen beheerder (admin) nodig.
#
# Een nieuwe versie installeren: voer dezelfde regel opnieuw uit. Er is geen automatische update.
#
# Dit bestand bevat bewust alleen ASCII-tekens: "irm | iex" leest het anders soms met de verkeerde codering.
# Alles staat in een functie die pas op de laatste regel wordt aangeroepen. Komt dit script maar half
# binnen (verbinding verbroken), dan gebeurt er dus niets.

param(
    [switch]$Remove,
    [string]$BaseUrl = 'https://github.com/AEROCX-Consulting/blackout/releases/latest/download'
)

function Install-AerocxBlackout {
    param(
        [switch]$Remove,
        [string]$BaseUrl
    )
    Set-StrictMode -Version 2
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'

    if ($env:BLACKOUT_BASE_URL) { $BaseUrl = $env:BLACKOUT_BASE_URL }
    if ($env:BLACKOUT_REMOVE -eq '1') { $Remove = $true }

    $AppName  = 'AEROCX Blackout'
    $FileName = 'aerocx-blackout-windows.exe'
    $Dir      = Join-Path $env:LOCALAPPDATA 'Programs\AEROCX Blackout'
    $Exe      = Join-Path $Dir 'aerocx-blackout.exe'
    $StartDir = [Environment]::GetFolderPath('Programs')
    if (-not $StartDir) { $StartDir = Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs' }
    $Shortcut = Join-Path $StartDir 'AEROCX Blackout.lnk'
    $RunKey   = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    $Url      = 'http://localhost:8474'
    $DataDir  = Join-Path $env:APPDATA 'AEROCX Blackout'
    $SiteUrl  = 'https://blackout.aerocx.be'

    function Say([string]$Text) { Write-Host $Text }

    function Test-App {
        try {
            $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 2 -Uri 'http://127.0.0.1:8474/api/ping'
            return ($r.Content -match 'aerocx-blackout')
        } catch { return $false }
    }

    function Stop-App {
        try { Invoke-WebRequest -UseBasicParsing -TimeoutSec 3 -Method Post -Uri 'http://127.0.0.1:8474/api/quit' | Out-Null } catch { }
        Start-Sleep -Seconds 1
        Get-Process -Name 'aerocx-blackout' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 300
    }

    # Oudere Windows PowerShell (5.1) gebruikt soms nog geen TLS 1.2.
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    } catch { }

    if ($Remove) {
        Say 'AEROCX Blackout verwijderen...'
        Stop-App
        Remove-ItemProperty -LiteralPath $RunKey -Name $AppName -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Shortcut -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $Dir -Recurse -Force -ErrorAction SilentlyContinue
        Say 'Klaar. De app is verwijderd.'
        Say "Je gegevens en sleutels staan nog in: $DataDir"
        Say 'Wil je die ook weg, verwijder die map dan zelf in Verkenner.'
        return
    }

    Say ''
    Say 'AEROCX Blackout installeren...'

    $Tmp = Join-Path ([IO.Path]::GetTempPath()) ('aerocx-blackout-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $Tmp | Out-Null
    try {
        $Download = Join-Path $Tmp $FileName
        Say '  downloaden...'
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/$FileName" -OutFile $Download
        } catch {
            throw "Downloaden lukte niet. Is er internet? ($($_.Exception.Message))"
        }

        # Zonder geslaagde controle wordt er niets geinstalleerd.
        $Sums = Join-Path $Tmp 'SHA256SUMS.txt'
        try {
            Invoke-WebRequest -UseBasicParsing -Uri "$BaseUrl/SHA256SUMS.txt" -OutFile $Sums
        } catch {
            throw 'De controlegetallen (SHA256SUMS.txt) konden niet gedownload worden. Zonder controle installeren we niets. Probeer het later opnieuw.'
        }
        $Want = $null
        foreach ($line in Get-Content -LiteralPath $Sums) {
            $parts = $line.Trim() -split '\s+', 2
            if ($parts.Count -eq 2 -and $parts[1].TrimStart('*').Trim() -eq $FileName) { $Want = $parts[0].ToLower(); break }
        }
        if (-not $Want -or $Want -notmatch '^[0-9a-f]{64}$') {
            throw "In SHA256SUMS.txt staat geen geldig controlegetal voor $FileName. Zonder controle installeren we niets. Probeer het later opnieuw."
        }
        $Got = $null
        try { $Got = (Get-FileHash -Algorithm SHA256 -LiteralPath $Download).Hash.ToLower() } catch { }
        if (-not $Got) { throw 'Het controlegetal kon niet berekend worden. Er is niets geinstalleerd.' }
        if ($Got -ne $Want) { throw 'Het gedownloade bestand klopt niet (SHA-256). Er is niets geinstalleerd. Probeer het later opnieuw.' }
        Say '  controle in orde (SHA-256)'

        Stop-App
        New-Item -ItemType Directory -Path $Dir -Force | Out-Null
        Copy-Item -LiteralPath $Download -Destination $Exe -Force
        try { Unblock-File -LiteralPath $Exe -ErrorAction SilentlyContinue } catch { }
        Say "  geplaatst in $Dir"
    } finally {
        Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
    }

    # Snelkoppeling in het menu Start.
    try {
        $shell = New-Object -ComObject WScript.Shell
        $lnk = $shell.CreateShortcut($Shortcut)
        $lnk.TargetPath = $Exe
        $lnk.Arguments = '-open'
        $lnk.WorkingDirectory = $Dir
        $lnk.IconLocation = "$Exe,0"
        $lnk.Description = 'AEROCX Blackout openen in je browser'
        $lnk.Save()
        Say '  snelkoppeling in Start gemaakt'
    } catch {
        Say '  (snelkoppeling maken lukte niet)'
    }

    # Automatisch starten bij aanmelden. Let op: nooit New-Item -Force op de Run-sleutel, want dat
    # maakt de sleutel opnieuw aan en wist alle andere opstartprogramma's. Alleen onze WAARDE zetten.
    if (-not (Test-Path -LiteralPath $RunKey)) { New-Item -Path $RunKey | Out-Null }
    New-ItemProperty -LiteralPath $RunKey -Name $AppName -PropertyType String -Value ('"' + $Exe + '" -background') -Force | Out-Null
    Say '  start voortaan vanzelf als je je aanmeldt'

    # Starten en de browser openen.
    Start-Process -FilePath $Exe -ArgumentList '-open' -WorkingDirectory $Dir
    $ok = $false
    for ($i = 0; $i -lt 40; $i++) {
        if (Test-App) { $ok = $true; break }
        Start-Sleep -Milliseconds 500
    }

    Say ''
    if ($ok) {
        Say "Klaar. AEROCX Blackout draait en opent in je browser: $Url"
    } else {
        Say "De app is gestart, maar antwoordt nog niet. Open zo meteen zelf: $Url"
    }
    Say ''
    Say 'Vraagt Windows Firewall of de app op het netwerk mag? Vink "Particuliere netwerken" aan en klik op Toegang toestaan.'
    Say 'Later opnieuw openen: menu Start > AEROCX Blackout.'
    Say 'Op je iPad of telefoon gaat de verbinding met deze pc over gewone HTTP, niet versleuteld:'
    Say 'gebruik dat alleen op je eigen, beveiligde wifi.'
    Say 'Nieuwe versie: voer dezelfde installatieregel opnieuw uit (er is geen automatische update).'
    Say "Verwijderen: & ([scriptblock]::Create((irm $SiteUrl/install.ps1))) -Remove"
}

try { Install-AerocxBlackout -Remove:$Remove -BaseUrl $BaseUrl } catch { Write-Host ''; Write-Host ('Fout: ' + $_.Exception.Message) -ForegroundColor Red }
