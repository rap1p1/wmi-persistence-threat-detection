# prepare_run.ps1 — stage run-scoped payloads for a new run
#
# Substitutes __RUN_ID__ / __SINK_BASE__ / __HOST__ in payloads/* into a run-scoped
# copy under evidence/runs/<RunId>/payload/ and prints the raw sha256 of the staged
# consumer. Copy that payload\ folder into the guest (e.g. as payloads\) and run
# setup.bat there. The staged hashes are indexed in the run ledger (ART-01-01 /
# ART-01-02) and the S3 EID 11 Hash field of the materialized svhw.ps1 is
# cross-checked against the staged consumer hash (module integrity link).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/prepare_run.ps1 `
#       -RunId RUN-20261003-01 -SinkBase http://10.0.0.5:9180 -HostName VICTIM
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$SinkBase,
    [Parameter(Mandatory = $true)][string]$HostName
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ($RunId -notmatch '^RUN-[0-9]{8}-[0-9]{2,}$') { throw "invalid run id: $RunId" }
if ($SinkBase -notmatch '^http://') { throw "sink base must be http://..." }

$out = Join-Path $root "evidence\runs\$RunId\payload"
New-Item -ItemType Directory -Force -Path $out | Out-Null

foreach ($f in @('setup.bat', 'install.ps1', 'consumer.ps1')) {
    $src = Get-Content (Join-Path $root "payloads\$f") -Raw -Encoding UTF8
    if ($f -like '*.ps1' -and $src -notmatch '__RUN_ID__|__SINK_BASE__|__HOST__') {
        throw "placeholders missing in payloads\$f - staged copy unsafe"
    }
    $src = $src.Replace('__RUN_ID__', $RunId).Replace('__SINK_BASE__', $SinkBase).Replace('__HOST__', $HostName)
    [System.IO.File]::WriteAllText((Join-Path $out $f), $src,
        (New-Object System.Text.UTF8Encoding($false)))
}

$staged = Join-Path $out 'consumer.ps1'
$content = Get-Content $staged -Raw -Encoding UTF8
if (-not $content.Contains($RunId)) { throw 'run id missing in staged consumer' }
if (-not $content.Contains($SinkBase)) { throw 'sink base missing in staged consumer' }

$hash = (Get-FileHash $staged -Algorithm SHA256).Hash
"staged under evidence/runs/$RunId/payload"
"staged consumer sha256 = $hash (index as ART-01-02; compare with the S3 EID 11 Hash)"
"copy evidence/runs/$RunId/payload into the guest, then run setup.bat"