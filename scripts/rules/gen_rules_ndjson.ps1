# gen_rules_ndjson.ps1 - deterministic Elastic EQL rule export for WMI-LAB-1
#
# Loads every query from detections/queries/*.eql plus the per-rule metadata below
# and writes detections/exports/wmi-rules.ndjson.
#
# Deterministic rule_id = SHA-256("WMI-LAB:" + rule name) rendered as a UUID (v5+nibble
# shaping), so re-imports overwrite instead of duplicating (playbook 3.1). Renaming a
# rule changes its id: delete the old rule server-side, then re-import.
#
# Building-block mode: every exported rule carries building_block_type="default"
# (hidden from the default alert view, used for correlation) so the export matches the
# documentation's "signal-level building blocks" claim.
#
# Usage:  powershell -ExecutionPolicy Bypass -File scripts/rules/gen_rules_ndjson.ps1
# Then:   curl.exe -s -u "$env:ES_USER:$env:ES_PASS" -H 'kbn-xsrf: true' ^
#           -F "file=@detections/exports/wmi-rules.ndjson" ^
#           'http://127.0.0.1:5601/api/detection_engine/rules/_import?overwrite=true'

$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$queryDir = Join-Path $root 'detections\queries'
$outDir = Join-Path $root 'detections\exports'
$outPath = Join-Path $outDir 'wmi-rules.ndjson'

$broadIndex = @('apm-*-transaction*', 'auditbeat-*', 'endgame-*', 'filebeat-*',
    'logs-*', 'packetbeat-*', 'traces-apm*', 'winlogbeat-*', '-*elastic-cloud-logs-*')

function New-RuleId([string]$name) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes("WMI-LAB:" + $name)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hex = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    # shape into a UUID with the SHA-256-derived nibbles 5/8
    $g = $hex.Substring(0, 32).ToCharArray()
    $g[12] = '5'
    $g[16] = '8'
    return ($g[0..7] -join '') + '-' + ($g[8..11] -join '') + '-' + ($g[12..15] -join '') +
        '-' + ($g[16..19] -join '') + '-' + ($g[20..31] -join '')
}

function Get-QueryFields([string]$query) {
    $plain = [regex]::Replace($query, '/\*.*?\*/', '', 'Singleline')
    $names = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($m in [regex]::Matches($plain,
        '\b(?:winlog|host|user|process|file|destination|event|registry)\.[A-Za-z0-9_.]+')) {
        [void]$names.Add($m.Value)
    }
    return $names
}

function New-MitreThreat($tactic, $techniques) {
    # $techniques: array of @{ id; name; sub = "T1546.003|Name;T1546.004|Other" | '' }
    $techList = New-Object System.Collections.ArrayList
    foreach ($t in $techniques) {
        if ($null -ne $t.sub -and $t.sub -ne '') {
            $subList = New-Object System.Collections.ArrayList
            foreach ($part in ($t.sub -split ';')) {
                $bits = $part -split '\|', 2
                [void]$subList.Add(@{ id = $bits[0].Trim(); name = $bits[1].Trim();
                                      reference = "https://attack.mitre.org/techniques/$($bits[0].Trim())/" })
            }
            [void]$techList.Add(@{
                id = $t.id; name = $t.name
                reference = "https://attack.mitre.org/techniques/$($t.id)/"
                subtechnique = $subList
            })
        }
        else {
            [void]$techList.Add(@{
                id = $t.id; name = $t.name
                reference = "https://attack.mitre.org/techniques/$($t.id)/"
            })
        }
    }
    $outer = New-Object System.Collections.ArrayList
    [void]$outer.Add(@{
        framework = 'MITRE ATT&CK'
        tactic = @{ id = $tactic[0]; name = $tactic[1];
                    reference = "https://attack.mitre.org/tactics/$($tactic[0])/" }
        technique = $techList
    })
    return $outer
}

function ConvertTo-CompactJson($obj) {
    return $obj | ConvertTo-Json -Depth 20 -Compress
}

# --- per-rule metadata --------------------------------------------------------
# Fields: file, id, name, desc, tags, severity, risk, tactic, techniques, interval,
#         from, event_ids, supp (group/duration/s), required_extra, notes, fp
$rules = @(
    @{
        file='r1-ms-settings-open-command-registry-hijack.eql'; id='R1'
        name='[R1] ms-settings Open Command Registry Hijack'
        desc='Sysmon 13: registry value set under HKCU\Software\Classes\ms-settings\Shell\Open\command (Default or DelegateExecute). Registry stage of the fodhelper UAC bypass; a registry signal only - it does not prove elevation.'
        tags=@('Signal','UAC Bypass','T1548.002','LOLBins','Registry')
        severity='medium'; risk=47
        tactic=@('TA0004','Privilege Escalation')
        techniques=@(
            @{ id='T1548'; name='Abuse Elevation Control Mechanism'
               sub='T1548.002|Bypass User Account Control' })
        interval='1m'; from='now-2m'
        event_ids=@('13')
        supp=@{ group=@('host.name'); dur=60 }
        required_extra=@('registry.path','registry.value')
        notes='Detection basis: Sigma registry_set_bypass_uac_using_delegateexecute (46dd5308-4572-4d12-aa43-8938f0184d4f), MITRE T1548.002 DET0388/AN1094 (registry half). Mapping verified: ECS registry.path/registry.value on the lab stack. See docs/correlation-architecture.md R1.'
        fp=@('Administration tooling could (rarely) touch the ms-settings handler; the key is written and deleted within seconds in this scenario. No measured false-positive rate is implied.')
    }
    @{
        file='c1-fodhelper-child-interpreter.eql'; id='C1'
        name='[C1] Fodhelper Child Interpreter'
        desc='Single process event: fodhelper is the parent of a listed shell/interpreter. Case-insensitive; suppression groups host + process entity so independent executions are not merged. Registry stage and privilege elevation are not established.'
        tags=@('Signal','UAC Bypass','T1548.002','LOLBins')
        severity='high'; risk=73
        tactic=@('TA0004','Privilege Escalation')
        techniques=@(
            @{ id='T1548'; name='Abuse Elevation Control Mechanism'
               sub='T1548.002|Bypass User Account Control' },
            @{ id='T1059'; name='Command and Scripting Interpreter'
               sub='T1059.005|Visual Basic;T1059.001|PowerShell' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name','process.entity_id'); dur=30 }
        required_extra=@('process.parent.name')
        notes='Detection basis: Sigma proc_creation_win_uac_bypass_fodhelper (7f741dcf-fc22-4759-87b4-9ae8376676a2), MITRE T1548.002 DET0388/AN1094 (process half). See docs/correlation-architecture.md C1.'
        fp=@('Fodhelper is rarely invoked legitimately; assess the child interpreter. No measured false-positive rate is implied.')
    }
    @{
        file='s1-script-host-fodhelper-cmd-parent.eql'; id='S1'
        name='[S1] Script Host With Fodhelper or Cmd Parent'
        desc='wscript/cscript process with fodhelper/cmd parent. Building block for script-host context; the fodhelper branch overlaps C1 on the same event (not an independent step) and the cmd-parent branch has lower specificity.'
        tags=@('Signal','VBScript','T1059.005','LOLBins')
        severity='medium'; risk=47
        tactic=@('TA0002','Execution')
        techniques=@(
            @{ id='T1059'; name='Command and Scripting Interpreter'
               sub='T1059.005|Visual Basic;T1059.001|PowerShell' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name','process.entity_id'); dur=30 }
        required_extra=@('process.parent.name')
        notes='Detection basis: Sigma proc_creation_win_uac_bypass_fodhelper family (overlaps C1); MITRE T1548.002 context. Building block; not an independent alert count.'
        fp=@('Script hosts launched by cmd are common; the cmd-parent branch is low specificity by design. No measured false-positive rate is implied.')
    }
    @{
        file='s2-powershell-hidden-bypass-patterns.eql'; id='S2'
        name='[S2] PowerShell Hidden and Bypass or Encoded Command Patterns'
        desc='PowerShell with hidden AND (bypass|unrestricted) command-line flags, OR an encoded command (the encoded branch does not require hidden). Parent-name exclusions were removed: a parent name does not prove provenance.'
        tags=@('Signal','PowerShell','T1059.001','Suspicious Flags')
        severity='medium'; risk=47
        tactic=@('TA0002','Execution')
        techniques=@(
            @{ id='T1059'; name='Command and Scripting Interpreter'
               sub='T1059.001|PowerShell' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name','user.name'); dur=60 }
        required_extra=@('process.command_line')
        notes='Detection basis: Sigma PowerShell flag corpus (name-referenced); MITRE T1059.001. A command-line/context signal, not proof of script contents; overlap with S3/R2 for the WMI consumer is documented (one event, two signals).'
        fp=@('Legitimate automation with hidden+bypass flags can match; re-baseline in the destination environment. No measured false-positive rate is implied.')
    }
    @{
        file='c2-wmi-subscription-registration-sequence.eql'; id='C2'
        name='[C2] WMI Subscription Registration Sequence'
        desc='Same-host ordered WMI creation sequence 19 -> 20 -> 21 within 30 seconds. Name-identity exclusions were removed (object names do not prove provenance); whether the binding references the recorded filter/consumer is cross-checked by the acceptance verifier.'
        tags=@('Signal','WMI Persistence','T1546.003')
        severity='high'; risk=73
        tactic=@('TA0003','Persistence')
        techniques=@(
            @{ id='T1546'; name='Event Triggered Execution'
               sub='T1546.003|Windows Management Instrumentation Event Subscription' })
        interval='1m'; from='now-2m'
        event_ids=@('19','20','21')
        supp=@{ group=@('host.name','winlog.computer_name'); dur=30 }
        required_extra=@('winlog.event_data.Operation')
        notes='Detection basis: Sigma sysmon_wmi_event_subscription (0f06a3a5-6a09-413f-8743-e6cf35561297), MITRE T1546.003 DET0086/AN0236 (registration half). Registration is not activation and not reboot survival. See docs/correlation-architecture.md C2.'
        fp=@('Approved management/monitoring WMI subscriptions will also produce 19/20/21; assess in the destination environment. No measured false-positive rate is implied.')
    }
    @{
        file='r2-wmi-subscription-registration-activation.eql'; id='R2'
        name='[R2] WMI Subscription Registration Followed by WMI-Hosted Interpreter'
        desc='Same host: WMI subscription registration (19/20/21 Created) followed within 10 minutes by a WMI-hosted interpreter (parent WmiPrvSE/scrcons). Deployment-agnostic (no trigger binary or script name required); host/time correlation - activation and ancestry are cross-checked by the verifier.'
        tags=@('Signal','WMI Execution','T1546.003','Persistence')
        severity='high'; risk=73
        tactic=@('TA0003','Persistence')
        techniques=@(
            @{ id='T1546'; name='Event Triggered Execution'
               sub='T1546.003|Windows Management Instrumentation Event Subscription' })
        interval='1m'; from='now-2m'
        event_ids=@('19','20','21','1')
        supp=@{ group=@('host.name'); dur=600 }
        required_extra=@('process.parent.name')
        notes='Detection basis: MITRE T1546.003 DET0086/AN0236 (registration -> activation correlation). HOST/TIME CANDIDATE ONLY: the query pairs any registration with any later WMI-hosted interpreter on the same host within 10 minutes; it does NOT prove that the interpreter was triggered by THIS subscription (Sysmon EID 19/20/21 carry no subscription object linkage in this telemetry). Registration is not activation, and activation is not reboot survival. See docs/correlation-architecture.md R2.'
        fp=@('A registration followed later by any WMI-hosted script/interpreter (including legitimate automation) matches; host/time correlation only, treated as a candidate, not a proven registration-to-activation link. No measured false-positive rate is implied.')
    }
    @{
        file='s3-system-shell-wmi-host-parent.eql'; id='S3'
        name='[S3] SYSTEM Shell or Tool With WMI Host Parent'
        desc='Listed shell/tool with WmiPrvSE/scrcons parent in SYSTEM context. SYSTEM-scoped signal (not every WMI execution); case-insensitive, executable fallback via the case-insensitive like~ operator.'
        tags=@('Signal','WMI Execution','T1546.003')
        severity='high'; risk=73
        tactic=@('TA0003','Persistence')
        techniques=@(
            @{ id='T1546'; name='Event Triggered Execution'
               sub='T1546.003|Windows Management Instrumentation Event Subscription' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name','process.entity_id'); dur=60 }
        required_extra=@('process.parent.executable','process.parent.name','user.name')
        notes='Detection basis: MITRE T1546.003 DET0086/AN0236 (anomalous WmiPrvSE children); Sigma sysmon_wmi_susp_scripting (name-referenced). See docs/correlation-architecture.md R2/S3.'
        fp=@('Legitimate WMI administration can spawn SYSTEM processes; the listed-tool scope reduces noise. No measured false-positive rate is implied.')
    }
    @{
        file='c3-wmi-hosted-interpreter-discovery.eql'; id='C3'
        name='[C3] WMI-Hosted Interpreter Followed by Discovery Process'
        desc='Ancestry-joined, same-host sequence: a WMI-hosted SYSTEM interpreter followed within 30 seconds by a listed SYSTEM discovery process whose PARENT entity is that interpreter (EQL per-clause by process.entity_id, host.name -> process.parent.entity_id, host.name). Cross-host false joins are impossible; the acceptance verifier re-checks the same ancestry from the ledger.'
        tags=@('Signal','WMI Execution','Discovery','T1546.003','T1082','T1016')
        severity='high'; risk=73
        tactic=@('TA0003','Persistence')
        techniques=@(
            @{ id='T1546'; name='Event Triggered Execution'
               sub='T1546.003|Windows Management Instrumentation Event Subscription' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name'); dur=60 }
        required_extra=@('process.parent.name','user.name')
        notes='Detection basis: MITRE T1546.003 DET0086/AN0236 (activation half) + T1082/T1016. Uses EQL PER-CLAUSE by (verified on ES 9.5.3): interpreter by process.entity_id AND host.name, discovery by process.parent.entity_id AND host.name - a same-host ancestry join, not a host/time guess. See docs/correlation-architecture.md C3.'
        fp=@('Unrelated same-host discovery within 30 s of WMI execution can correlate; ancestry is verifier-checked. No measured false-positive rate is implied.')
    }
    @{
        file='c4-single-process-staging-archive.eql'; id='C4'
        name='[C4] Staging and Archive Creation by a Single Process'
        desc='Same entity: a process creates a staging file, then creates an archive (EID 11 x2 joined by process.entity_id). Network split out (see S4); no lab folder/file names required; does not prove collection or transfer. In this chain the archiving entity is the WMI-hosted consumer (linked via the run ledger).'
        tags=@('Signal','Collection','T1005','T1074.001','T1560.001')
        severity='high'; risk=73
        tactic=@('TA0009','Collection')
        techniques=@(
            @{ id='T1005'; name='Data from Local System' },
            @{ id='T1074'; name='Data Staged'
               sub='T1074.001|Local Data Staging' },
            @{ id='T1560'; name='Archive Collected Data'
               sub='T1560.001|Archive via Utility' })
        interval='1m'; from='now-3m'
        event_ids=@('11')
        supp=@{ group=@('host.name','process.entity_id'); dur=120 }
        required_extra=@('file.extension','process.parent.name')
        notes='Detection basis: T1005/T1074.001/T1560.001 staging/archive telemetry joined by process.entity_id (E11 parent fields are absent on the lab stack, hence process-agnostic). See docs/correlation-architecture.md C4.'
        fp=@('A WMI-hosted process that happens to create a file then an archive matches; staging creates include generated manifests. No measured false-positive rate is implied.')
    }
    @{
        file='s4-script-spawned-curl-upload-args.eql'; id='S4'
        name='[S4] Script-Spawned Curl with Upload Arguments'
        desc='LAB ANALOGUE, single-event signal: a curl process launched by a script/interpreter (powershell/cmd/wscript/cscript) with upload-intent arguments. Proves upload INTENT by the invoking interpreter - not a connection, not a C2 channel, not a successful send. E1->E3 ownership is the verifier S6 join; transfer success is the sink receipt. No archive name, IP, port or hostname required.'
        tags=@('Signal','Exfiltration Analogue','Upload Intent','Lab Analogue')
        severity='high'; risk=73
        tactic=@('TA0010','Exfiltration')
        techniques=@(
            @{ id='T1041'; name='Exfiltration Over C2 Channel' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name','process.entity_id'); dur=60 }
        required_extra=@('process.command_line','process.parent.name')
        notes='LAB ANALOGUE: E1-only upload-intent signal (script-spawned curl with upload args). It does NOT prove a connection, a C2 channel or a completed transfer, so the ATT&CK mapping is limited to the exfiltration tactic as an analogue and T1041 is NOT asserted; transfer success is the sink receipt. A host/time E1-E3 join is deliberately NOT used. See docs/correlation-architecture.md S4.'
        fp=@('Scripts performing curl uploads (automation/CI) match the intent signal; the transfer claim requires the receipt. No measured false-positive rate is implied.')
    }
    @{
        file='c5-archive-created-then-deleted.eql'; id='C5'
        name='[C5] Archive Creation Followed by Archive Deletion'
        desc='Path-joined, same-host sequence: an archive is created (EID 11, zip) then deleted (EID 23, zip) on the SAME file.path on the SAME host within 2 minutes (EQL per-clause by file.path, host.name). No archive name is hard-coded; the acceptance verifier re-checks path equality; deletion does not imply transfer success.'
        tags=@('Signal','Defense Evasion','T1070.004')
        severity='high'; risk=73
        tactic=@('TA0005','Defense Evasion')
        techniques=@(
            @{ id='T1070'; name='Indicator Removal'
               sub='T1070.004|File Deletion' })
        interval='1m'; from='now-2m'
        event_ids=@('11','23')
        supp=@{ group=@('host.name'); dur=60 }
        required_extra=@('file.extension')
        notes='Detection basis: T1070.004 deletion telemetry chained to archive creation. Uses EQL PER-CLAUSE by (verified on ES 9.5.3): both steps key on file.path AND host.name, so the deletion is joined to the creation of the SAME archive path on the SAME host - a same-path cross-host false join is impossible. The acceptance verifier re-checks the path equality from the ledger. See docs/correlation-architecture.md C5.'
        fp=@('Zip-create then zip-delete within 2 minutes is uncommon in normal PC use; assess in the destination environment. No measured false-positive rate is implied.')
    }
)

# --- build -------------------------------------------------------------------
$lines = @()
foreach ($r in $rules) {
    $queryPath = Join-Path $queryDir $r.file
    if (-not (Test-Path $queryPath)) { throw "missing query file: $($r.file)" }
    $query = (Get-Content $queryPath -Raw -Encoding UTF8).TrimEnd("`r", "`n")

    $fields = @('@timestamp', 'host.name', 'winlog.channel', 'winlog.event_id')
    $used = Get-QueryFields $query
    if ($used.Contains('event.category') -or $query -match '(process|file|network|registry) where') {
        $fields += 'event.category'
    }
    foreach ($f in ($r.required_extra + @($used | Sort-Object))) {
        if ($fields -notcontains $f) { $fields += $f }
    }
    $requiredFields = @()
    $typeMap = @{ 'ip' = @('destination.ip'); 'long' = @('destination.port');
                  'date' = @('@timestamp'); 'wildcard' = @('process.command_line') }
    foreach ($f in $fields) {
        $t = 'keyword'
        foreach ($k in $typeMap.Keys) { if ($typeMap[$k] -contains $f) { $t = $k; break } }
        $requiredFields += @{ name = $f; type = $t }
    }

    $ids = ($r.event_ids -join ', ')
    if ($r.id -eq 'S4') {
        $blockline = 'This rule is NOT a building block: it represents the upload-intent / exfil-analogue signal analysts should see, so its alerts appear under the default Alerts view (no building-block filter required).'
    } else {
        $blockline = 'Building block (building_block_type=default): hidden from the default alert view, feeds correlation; no signal alone asserts an incident.'
    }
    $setup = @(
        "## Data requirements - $($r.id)",
        '',
        "- Sysmon event IDs consumed by the query: $ids.",
        '- Channel: Microsoft-Windows-Sysmon/Operational.',
        '- Detection basis: ' + $r.notes,
        '',
        $blockline,
        'Verify the installed integration: event.category, field types, casing, null handling and source-to-ECS mapping against actual events. required_fields is descriptive metadata, not a mapping check. The public export retains the original broad index patterns - scope them to verified data streams in the destination environment.',
        'Query interpretation and evidence boundaries: ' +
            'docs/telemetry-contract.md, docs/correlation-architecture.md, docs/attack-chain-plan.md.',
        'Validate every alert against its source events and the run ledger as described in ' +
            'docs/attack-detection-mapping.md or detections/README.md.'
    ) -join "`n"

    $alertSupp = @{
        group_by = $r.supp.group
        duration = @{ value = $r.supp.dur; unit = 's' }
        missing_fields_strategy = 'suppress'
    }

    $threat = @(New-MitreThreat $r.tactic @($r.techniques))

    $obj = [ordered]@{
        rule_id = New-RuleId $r.name
        name = $r.name
        immutable = $false
        rule_source = @{ type = 'internal' }
        version = 1
        revision = 1
        enabled = $true
        interval = $r.interval
        from = $r.from
        to = 'now'
        description = $r.desc
        tags = $r.tags
        author = @()
        license = ''
        threat = $threat
        related_integrations = @()
        required_fields = $requiredFields
        setup = $setup
        note = 'Validate the alert against its source events and the run ledger; see docs/telemetry-contract.md and docs/correlation-architecture.md.'
        false_positives = $r.fp
        references = @()
        risk_score = $r.risk
        risk_score_mapping = @()
        severity = $r.severity
        severity_mapping = @()
        output_index = ''
        max_signals = 100
        exceptions_list = @()
        actions = @()
        type = 'eql'
        language = 'eql'
        index = $broadIndex
        query = $query
        filters = @()
        alert_suppression = $alertSupp
    }
    # Building-block mode: every rule defaults to building_block_type=default
    # (hidden from the default alert view, feeds correlation; no single signal asserts
    # an incident). S4 is the one rule analysts must SEE (the upload-intent /
    # exfil-analogue signal), so its building_block_type field is REMOVED from the
    # export - its alerts surface under default Kibana filters.
    if ($r.id -ne 'S4') { $obj.building_block_type = 'default' }
    $lines += (ConvertTo-CompactJson $obj)
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
[System.IO.File]::WriteAllLines($outPath, $lines,
    (New-Object System.Text.UTF8Encoding($false)))
Write-Host "wrote $($lines.Count) rules -> $outPath"