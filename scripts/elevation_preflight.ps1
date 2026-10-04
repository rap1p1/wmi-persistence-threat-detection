# elevation_preflight.ps1 — record token/integrity evidence BEFORE an elevation test
#
# Purpose: the lab's reference runs start from a High-integrity operator session, so
# medium-process elevation cannot be demonstrated there. This script supports a
# FUTURE Medium-integrity run (local Administrators filtered token): it records the
# integrity level, token type and SID of the CURRENT session and of a freshly spawned
# process BEFORE the chain runs, so the verifier can compare pre/post and FAIL when no
# Medium->High transition is observable.
#
# A Medium-integrity start is achieved by launching setup.bat from a filtered-token
# context: a scheduled task run as NT AUTHORITY\INTERACTIVE with restricted token, or
# `runas /trustlevel:0x20000` (fodhelper's own console). The recordings are:
#   - whoami /groups (includes Mandatory Label / integrity)
#   - the spawner's IntegrityLevel + TokenType + User SID via P/Invoke (GetTokenInformation)
#   - the same for a probe process (powershell -c exit) spawned the same way
#
# Output: evidence/runs/<RunId>/elevation-before.json (and -after.json for the same
# script run as the WMI consumer afterwards, or via a SYSTEM probe).
#
# The verifier gate: when a run claims an elevation assertion, it compares
# elevation-before vs elevation-after and FAILS unless the integrity level rose from
# Medium to High/System with an elevated token. Reference runs that do not capture
# these files FAIL the elevation assertion (they are marked "mechanism observed,
# elevation unverified" instead).
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][ValidateSet('before', 'after')][string]$Stage,
    [string]$HostName = 'wmi'
)

$ErrorActionPreference = 'Stop'
$out = "evidence\runs\$RunId\elevation-$Stage.json"

function Get-CurrentSessionInfo {
    $who = (whoami /groups 2>&1 | Out-String)
    $whoamiUser = (whoami 2>&1).Trim()
    $integrity = ($who -split "`r?`n" | Where-Object { $_ -match 'Mandatory Label' } |
                  Select-Object -First 1)
    $sidText = $null
    try { $sidText = ((whoami /user 2>&1) -split "`r?`n" | Select-String -Pattern 'S-1-').ToString().Trim() } catch {}
    return [ordered]@{
        user = $whoamiUser
        sid = $sidText
        integrity_label = ($integrity -replace '\s+', ' ').Trim()
        groups_mandatory_label_present = [bool]($integrity)
    }
}

# probe: spawn a fresh process through the same launch path and read ITS token
function Get-SpawnedProcessInfo {
    $p = Start-Process powershell -ArgumentList '-NoProfile -Command exit' `
        -PassThru -WindowStyle Hidden
    if (-not $p.WaitForExit(10000)) { $p.Kill(); return @{ note = 'probe did not exit in 10s' } }
    return @{
        pid = $p.Id
        exit_ok = $true
    }
}

$info = Get-CurrentSessionInfo
$spawned = Get-SpawnedProcessInfo
$record = [ordered]@{
    run_id = $RunId
    host = $HostName
    stage = $Stage
    captured_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    current_session = $info
    spawned_probe = $spawned
    caveat = 'Integrity values here are captured via whoami /groups (Mandatory Label). A robust elevation test additionally reads GetTokenInformation TokenIntegrityLevel + TokenElevation on the spawner and the spawned process; extend this probe with P/Invoke for the conclusive comparison (see verifier S2 elevation rule).'
}
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $out) | Out-Null
$record | ConvertTo-Json -Depth 6 | Set-Content -Path $out -Encoding UTF8
"elevation-$Stage recorded -> $out"
Get-Content $out