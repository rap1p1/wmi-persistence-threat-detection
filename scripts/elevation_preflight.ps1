# elevation_preflight.ps1 — record token/integrity evidence for an elevation test
#
# Runs INSIDE the guest (the subject of the elevation test), NOT on the lab host.
# Produces a JSON measurement on the guest (default C:\Windows\Temp\elevation-<stage>.json)
# which the operator copies back to evidence/runs/<RunId>/ before verification.
#
# Two stages:
#   before  - run in the SAME context that starts the chain (a Medium-integrity
#             filtered token: runas /trustlevel:0x20000 or a restricted scheduled
#             task). Records integrity label + user SID of the current session.
#   after   - run in the ELEVATED context (e.g. the WMI consumer / elevated install),
#             or automatically by install.ps1 after registration. Records the same.
#
# The verifier's S2 gate reads evidence/runs/<RunId>/elevation-before.json and
# elevation-after.json and FAILS when no Medium->High/System rise is recorded (or the
# files are absent AND an elevation claim is made). Reference runs started from a
# High-integrity session have no before measurement and stay "mechanism observed,
# elevation unverified" (GAP, not a claim).
#
# Usage (guest):
#   powershell -ExecutionPolicy Bypass -File elevation_preflight.ps1 -RunId RUN-... -Stage before
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][ValidateSet('before', 'after')][string]$Stage
)

$ErrorActionPreference = 'Stop'
$out = Join-Path $env:TEMP "elevation-$Stage-$RunId.json"

function Get-ContextInfo {
    $groups = (whoami /groups 2>&1 | Out-String)
    $user = (whoami 2>&1).Trim()
    $sid = $null
    try {
        $userLine = ((whoami /user 2>&1) -split "`r?`n" | Where-Object { $_ -match 'S-1-' } |
                     Select-Object -First 1)
        $sid = ($userLine -replace '.*(S-1-[0-9-]+).*', '$1').Trim()
    } catch {}
    $integrity = ($groups -split "`r?`n" | Where-Object { $_ -match 'Mandatory Label' } |
                  Select-Object -First 1)
    # token elevation state, when readable (whoami /groups shows the label only)
    $record = [ordered]@{
        user = $user
        sid = $sid
        integrity_label = ($integrity -replace '\s+', ' ').Trim()
        mandatory_label_present = [bool]($integrity)
        groups_high = [bool]($groups -match 'High Mandatory Level')
        groups_medium = [bool]($groups -match 'Medium Mandatory Level')
    }
    return $record
}

$record = [ordered]@{
    run_id = $RunId
    stage = $Stage
    captured_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    current_session = Get-ContextInfo
    caveat = 'whoami /groups Mandatory Label is the recorded integrity basis; a conclusive comparison should additionally read GetTokenInformation (TokenIntegrityLevel + TokenElevation) on the same process - extend this probe if the P/Invoke path is available.'
}
[System.IO.File]::WriteAllText($out, ($record | ConvertTo-Json -Depth 6), (New-Object System.Text.UTF8Encoding($false)))
"elevation-$Stage -> $out (copy this file back to evidence/runs/$RunId/ on the host)"
Get-Content $out