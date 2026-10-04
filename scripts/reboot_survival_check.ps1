# reboot_survival_check.ps1 — check WMI subscription survival across a guest reboot
#
# Procedure (run from the lab host):
#   1. BEFORE reboot: run this with -Mode before  (records the installed objects + the
#      consumer file state).
#   2. Reboot the guest (vmrun reset / shutdown+start) and WAIT for boot to complete.
#   3. AFTER reboot: run with -Mode after. The script re-checks the same objects and
#      (optionally, -TriggerNotepad) fires the notepad trigger to prove the consumer
#      still executes.
#
# Honest bounds: this checks that the subscription OBJECTS live across a reboot and
# the trigger still fires under the CURRENT AV state of the guest. It is NOT a
# persistence-against-AV claim (that needs an AV-disabled run of the same procedure),
# NOT a bypass claim, and a failed check is a real finding (the runbook does not
# re-purge evidence).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/reboot_survival_check.ps1 \
#       -RunId RUN-20261003-04 -Mode after -TriggerNotepad
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][ValidateSet('before', 'after')][string]$Mode,
    [switch]$TriggerNotepad,
    [string]$HostName = 'wmi',
    [string]$OutFile = ''
)

$ErrorActionPreference = 'Continue'
if (-not $OutFile) { $OutFile = "evidence\runs\$RunId\reboot-survival-$Mode.json" }

$script:results = [ordered]@{
    run_id = $RunId
    host = $HostName
    mode = $Mode
    captured_utc = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    checks = @()
}

function Add-Check([string]$name, [string]$result, [string]$detail) {
    $script:results.checks += [ordered]@{ check = $name; result = $result; detail = $detail }
}

# objects the lab chain creates (strict namespace - never touches anything else)
$filterNames = @('NotepadFilter')
$consumerNames = @('SystemDumpConsumer')

$filters = @(Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
             Where-Object { $filterNames -contains $_.Name })
$consumers = @(Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
               Where-Object { $consumerNames -contains $_.Name })
$binds = @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
           Where-Object { $_.Filter -match 'NotepadFilter' -or $_.Consumer -match 'SystemDumpConsumer' })

if ($filters.Count -eq 0) {
    Add-Check "event filter ($($filterNames -join ','))" 'FAIL' 'object not present'
} else {
    Add-Check "event filter ($($filterNames -join ','))" 'PASS' "present: $($filters.Name -join ', ')"
}
if ($consumers.Count -eq 0) {
    Add-Check "consumer ($($consumerNames -join ','))" 'FAIL' 'object not present'
} else {
    Add-Check "consumer ($($consumerNames -join ','))" 'PASS' "present: $($consumers.Name -join ', ')"
}
if ($binds.Count -eq 0) {
    Add-Check 'binding' 'FAIL' 'no binding references the lab filter/consumer'
} else {
    Add-Check 'binding' 'PASS' "$($binds.Count) binding(s) present"
}

$consumerPath = 'C:\Windows\Temp\svhw.ps1'
if (Test-Path $consumerPath) {
    $h = (Get-FileHash $consumerPath -Algorithm SHA256).Hash
    Add-Check 'consumer file present' 'PASS' "svhw.ps1 sha256=$h"
} else {
    Add-Check 'consumer file present' 'FAIL' "$consumerPath missing"
}

if ($TriggerNotepad) {
    $pre = Get-Date
    Start-Process notepad -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 15   # allow the consumer to run
    $ran = Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' -MaxEvents 20000 -ErrorAction SilentlyContinue |
        Where-Object { $_.Id -eq 1 -and $_.TimeCreated -gt $pre -and $_.Message -match 'svhw.ps1' }
    if ($ran) {
        Add-Check 'trigger fires consumer after (re)boot' 'PASS' "consumer E1 at $($ran[0].TimeCreated)"
    } else {
        Add-Check 'trigger fires consumer after (re)boot' 'FAIL' 'no consumer E1 within 15s of notepad'
    }
}

$fail = @($script:results.checks | Where-Object { $_.result -eq 'FAIL' }).Count
$script:results | Out-File $OutFile -Encoding UTF8
"reboot-survival $Mode: $($script:results.checks.Count) checks, $fail FAIL -> $OutFile"
exit $(if ($fail -eq 0) { 0 } else { 1 })