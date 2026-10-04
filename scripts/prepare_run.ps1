# prepare_run.ps1 — stage run-scoped payloads for a new run
#
# Substitutes __RUN_ID__ / __SINK_BASE__ / __HOST__ / __SINK_TOKEN__ in payloads/*
# into a run-scoped copy under evidence/runs/<RunId>/payload/, enforces that the sink
# endpoint is inside the lab network, and prints the raw sha256 of the staged
# consumer. Copy that payload\ folder into the guest (e.g. as payloads\) and run
# setup.bat there.
#
# Module-integrity note: the S3 EID 11 event on this stack carries NO Hashes, so the
# hash basis is the GUEST PROBE (Get-FileHash of C:\Windows\Temp\svhw.ps1) taken by
# the operator and recorded as a separate measurement (probe-svhw-hash.json); the
# acceptance verifier compares that measurement with the staged consumer hash
# (canonical CRLF->LF) - nothing is attributed to an EID 11 hash field.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts/prepare_run.ps1 `
#       -RunId RUN-20261003-04 -SinkBase http://192.168.106.1:9180 -HostName wmi `
#       -SinkToken <lab token, must match the SINK_TOKEN the sink runs with>
param(
    [Parameter(Mandatory = $true)][string]$RunId,
    [Parameter(Mandatory = $true)][string]$SinkBase,
    [Parameter(Mandatory = $true)][string]$HostName,
    [Parameter(Mandatory = $true)][string]$SinkToken
)

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if ($RunId -notmatch '^RUN-[0-9]{8}-[0-9]{2,}$') { throw "invalid run id: $RunId" }
if ($SinkBase -notmatch '^http://') { throw "sink base must be http://..." }

# Sink must be INSIDE the lab network (VMware NAT/host-only uses 192.168.x.x by
# design in this lab). A sink elsewhere (public address, any-interface) is refused so
# the transfer cannot be pointed at an unintended destination.
$uri = [System.Uri]$SinkBase
$hostAddr = $uri.Host
$labOk = $hostAddr -match '^192\.168\.' -or $hostAddr -eq '127.0.0.1' -or $hostAddr -eq 'localhost'
if (-not $labOk) { throw "sink host $hostAddr is outside the lab network (192.168.x.x required)" }
if ($uri.Port -ne 9180) { Write-Warning "sink port $($uri.Port) is not the default 9180" }
if ($SinkToken.Length -lt 16) { throw "sink token must be at least 16 chars (shared lab credential)" }

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

# The sink token is NOT embedded in any committed file. It must be placed on the GUEST
# as %TEMP%\lab-token.txt (same value the sink runs with) - the consumer reads it at
# runtime. Never commit the token.
"place the sink token on the guest as C:\Users\<user>\AppData\Local\Temp\lab-token.txt"

$hash = (Get-FileHash $staged -Algorithm SHA256).Hash
"staged under evidence/runs/$RunId/payload"
"staged consumer sha256 = $hash (index as ART-01-02; module integrity via the GUEST PROBE measurement, not an EID 11 hash)"
"copy evidence/runs/$RunId/payload into the guest, then run setup.bat"