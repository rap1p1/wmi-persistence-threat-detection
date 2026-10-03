# gen_rules_ndjson.ps1 - deterministic Elastic EQL rule export for WMI-LAB-1
#
# Loads every query from detections/queries/*.eql plus the per-rule metadata below
# and writes detections/exports/wmi-rules.ndjson.
#
# Deterministic rule_id = SHA-256("WMI-LAB:" + rule name) rendered as a UUID (v5+nibble
# shaping), so re-imports overwrite instead of duplicating (playbook 3.1). Renaming a
# rule changes its id: delete the old rule server-side, then re-import.
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
    # strip block comments, then collect field tokens used by predicates/suppression
    $plain = [regex]::Replace($query, '/\*.*?\*/', '', 'Singleline')
    $names = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($m in [regex]::Matches($plain,
        '\b(?:winlog|host|user|process|file|destination|event)\.[A-Za-z0-9_.]+')) {
        [void]$names.Add($m.Value)
    }
    return $names
}

function New-MitreThreat($tactic, $techniques) {
    # $techniques: array of @{ id; name; sub = "T1546.003|Name;T1546.004|Other" | '' }
    # ArrayLists are used instead of @() literals: the array-subexpression operator
    # flattens nested arrays and enumerates hashtables, corrupting the JSON shape.
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
    # stable compact serialisation (Keys order preserved; no trailing spaces)
    return $obj | ConvertTo-Json -Depth 20 -Compress
}

# --- per-rule metadata --------------------------------------------------------
# Fields: file, id, name, desc, tags, severity, risk, tactic, techniques, interval,
#         from, event_ids, supp (group/duration/s), required_extra, notes, fp
$rules = @(
    @{
        file='r1-ms-settings-open-command-registry-hijack.eql'; id='R1'
        name='[R1] ms-settings Open Command Registry Hijack'
        desc='Sysmon 13: registry value set under HKCU\Software\Classes\ms-settings\Shell\Open\command (default or DelegateExecute). Registry stage of the fodhelper UAC bypass; the key is written and removed within seconds. Does not prove elevation.'
        tags=@('Signal','UAC Bypass','T1548.002','LOLBins','Registry')
        severity='medium'; risk=47
        tactic=@('TA0004','Privilege Escalation')
        techniques=@(
            @{ id='T1548'; name='Abuse Elevation Control Mechanism'
               sub='T1548.002|Bypass User Account Control' })
        interval='1m'; from='now-2m'
        event_ids=@('13')
        supp=@{ group=@('host.name'); dur=60 }
        required_extra=@('winlog.event_data.TargetObject')
        notes='Detection basis: Sigma registry_set_bypass_uac_using_delegateexecute (46dd5308-4572-4d12-aa43-8938f0184d4f), MITRE T1548.002 DET0388/AN1094 (registry half). See docs/correlation-architecture.md R1.'
        fp=@('Approved administration, installation, monitoring, backup or automation may overlap the selected conditions. Assess in the destination environment; no measured false-positive rate is implied.')
    }
    @{
        file='c1-fodhelper-child-interpreter.eql'; id='C1'
        name='[C1] Fodhelper Child Interpreter'
        desc='Single process event: fodhelper is the parent of a listed shell/interpreter. Registry stage and privilege elevation are not established.'
        tags=@('Signal','UAC Bypass','T1548.002','LOLBins','Correlation')
        severity='high'; risk=73
        tactic=@('TA0004','Privilege Escalation')
        techniques=@(
            @{ id='T1548'; name='Abuse Elevation Control Mechanism'
               sub='T1548.002|Bypass User Account Control' },
            @{ id='T1059'; name='Command and Scripting Interpreter'
               sub='T1059.005|Visual Basic;T1059.001|PowerShell' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name'); dur=30 }
        required_extra=@('process.parent.name')
        notes='Detection basis: Sigma proc_creation_win_uac_bypass_fodhelper (7f741dcf-fc22-4759-87b4-9ae8376676a2), MITRE T1548.002 DET0388/AN1094 (process half). See docs/correlation-architecture.md C1.'
        fp=@('Approved administration, installation, monitoring, backup or automation may overlap the selected conditions. Assess in the destination environment; no measured false-positive rate is implied.')
    }
    @{
        file='s1-script-host-fodhelper-cmd-parent.eql'; id='S1'
        name='[S1] Script Host With Fodhelper or Cmd Parent'
        desc='wscript/cscript process with fodhelper/cmd parent. Does not require a PowerShell child; overlaps C1 on the same event.'
        tags=@('Signal','VBScript','T1059.005','LOLBins','Early Warning')
        severity='medium'; risk=47
        tactic=@('TA0002','Execution')
        techniques=@(
            @{ id='T1059'; name='Command and Scripting Interpreter'
               sub='T1059.005|Visual Basic;T1059.001|PowerShell' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name'); dur=30 }
        required_extra=@('process.parent.name')
        notes='Detection basis: Sigma proc_creation_win_uac_bypass_fodhelper family (C1 overlaps); MITRE T1548.002 context. Building block: not an independent stage count.'
        fp=@('Approved administration, installation, monitoring, backup or automation may overlap the selected conditions. Assess in the destination environment; no measured false-positive rate is implied.')
    }
    @{
        file='s2-powershell-hidden-bypass-patterns.eql'; id='S2'
        name='[S2] PowerShell Hidden and Bypass or Encoded Command Patterns'
        desc='PowerShell process with selected hidden and bypass/encoded command-line patterns, subject to parent exclusions.'
        tags=@('Signal','PowerShell','T1059.001','Suspicious Flags')
        severity='medium'; risk=47
        tactic=@('TA0002','Execution')
        techniques=@(
            @{ id='T1059'; name='Command and Scripting Interpreter'
               sub='T1059.005|Visual Basic;T1059.001|PowerShell' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name','user.name'); dur=60 }
        required_extra=@('process.command_line','winlog.event_data.CommandLine','process.parent.executable','process.parent.name','user.name')
        notes='Detection basis: Sigma PowerShell flag corpus (name-referenced); MITRE T1059.001. A command-line/context signal, not proof of script contents.'
        fp=@('Approved administration, installation, monitoring, backup or automation may overlap the selected conditions. Assess in the destination environment; no measured false-positive rate is implied.')
    }
    @{
        file='c2-wmi-subscription-registration-sequence.eql'; id='C2'
        name='[C2] WMI Subscription Registration Sequence'
        desc='Same-host sequence of WMI creation events 19, 20, 21 within 30 seconds. Binding/object identity is cross-checked by the verifier, not by this query.'
        tags=@('Signal','WMI Persistence','T1546.003','Correlation')
        severity='high'; risk=73
        tactic=@('TA0003','Persistence')
        techniques=@(
            @{ id='T1546'; name='Event Triggered Execution'
               sub='T1546.003|Windows Management Instrumentation Event Subscription' })
        interval='1m'; from='now-2m'
        event_ids=@('19','20','21')
        supp=@{ group=@('host.name','winlog.computer_name'); dur=30 }
        required_extra=@('winlog.event_data.Name','winlog.event_data.Operation')
        notes='Detection basis: Sigma sysmon_wmi_event_subscription (0f06a3a5-6a09-413f-8743-e6cf35561297), MITRE T1546.003 DET0086/AN0236 (registration half). Registration is not activation and not reboot survival. See docs/correlation-architecture.md C2.'
        fp=@('Vetted, approved WMI event subscriptions by management/monitoring tooling should be excluded with a name allowlist in the destination environment; no measured false-positive rate is implied.')
    }
    @{
        file='c3-wmi-parented-powershell-discovery.eql'; id='C3'
        name='[C3] WMI-Parented PowerShell Followed by Discovery Process'
        desc='Same-host WMI-parented SYSTEM PowerShell followed by a listed SYSTEM discovery process within 30 seconds. No process-ancestry join; TEMPORAL/CONTEXTUAL only.'
        tags=@('Signal','WMI Execution','Discovery','T1546.003','T1082','T1016','Correlation')
        severity='high'; risk=73
        tactic=@('TA0003','Persistence')
        techniques=@(
            @{ id='T1546'; name='Event Triggered Execution'
               sub='T1546.003|Windows Management Instrumentation Event Subscription' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name'); dur=60 }
        required_extra=@('process.command_line','process.parent.name','user.name')
        notes='Detection basis: MITRE T1546.003 DET0086/AN0236 (activation half) combined with T1082/T1016 discovery. See docs/correlation-architecture.md C3.'
        fp=@('Approved administration, installation, monitoring, backup or automation may overlap the selected conditions. Assess in the destination environment; no measured false-positive rate is implied.')
    }
    @{
        file='r2-wmi-consumer-activation-sequence.eql'; id='R2'
        name='[R2] WMI Consumer Activation After Notepad Trigger'
        desc='Sequence: notepad.exe process creation followed within 60 seconds by a WmiPrvSE-parented SYSTEM powershell running the scripted consumer (svhw.ps1). Activation of the registered subscription; not reboot survival.'
        tags=@('Signal','WMI Execution','T1546.003','Persistence','Correlation')
        severity='high'; risk=73
        tactic=@('TA0003','Persistence')
        techniques=@(
            @{ id='T1546'; name='Event Triggered Execution'
               sub='T1546.003|Windows Management Instrumentation Event Subscription' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name'); dur=60 }
        required_extra=@('process.parent.name','process.command_line','user.name')
        notes='Detection basis: MITRE T1546.003 DET0086/AN0236 (trigger -> consumer activation); closes the activation coverage gap. Subscription-to-execution attribution stays TEMPORAL/CONTEXTUAL; the process ancestry WmiPrvSE -> powershell is verified by the verifier. See docs/correlation-architecture.md R2.'
        fp=@('A notepad.exe launch on a host with a registered WMI subscription is the intended trigger; environments without such subscriptions will not produce the second event. Assess in the destination environment.')
    }
    @{
        file='s3-system-shell-wmi-host-parent.eql'; id='S3'
        name='[S3] SYSTEM Shell or Tool With WMI Host Parent'
        desc='Listed shell/tool with WmiPrvSE/scrcons parent in SYSTEM context. Permanent subscription provenance must be verified separately.'
        tags=@('Signal','WMI Execution','T1546.003')
        severity='high'; risk=73
        tactic=@('TA0003','Persistence')
        techniques=@(
            @{ id='T1546'; name='Event Triggered Execution'
               sub='T1546.003|Windows Management Instrumentation Event Subscription' })
        interval='1m'; from='now-2m'
        event_ids=@('1')
        supp=@{ group=@('host.name'); dur=60 }
        required_extra=@('process.parent.executable','process.parent.name','user.name')
        notes='Detection basis: MITRE T1546.003 DET0086/AN0236 (anomalous WmiPrvSE children); Sigma sysmon_wmi_susp_scripting (name-referenced). See docs/correlation-architecture.md R2/S3.'
        fp=@('Approved administration, installation, monitoring, backup or automation may overlap the selected conditions. Assess in the destination environment; no measured false-positive rate is implied.')
    }
    @{
        file='c4-powershell-staging-zip-network.eql'; id='C4'
        name='[C4] PowerShell Staging Files, ZIP Creation and Network Activity'
        desc='Same-host sequence of a qualifying PowerShell staging file, ZIP creation and SYSTEM PowerShell network activity within two minutes. Generated manifest/info files can satisfy the first stage. Does not establish source-file collection, archive contents or successful transfer; the transfer process is curl, which this sequence does not select.'
        tags=@('Signal','Data Exfiltration','T1005','T1560.001','Collection','Correlation')
        severity='high'; risk=73
        tactic=@('TA0009','Collection')
        techniques=@(
            @{ id='T1005'; name='Data from Local System' },
            @{ id='T1560'; name='Archive Collected Data'
               sub='T1560.001|Archive via Utility' },
            @{ id='T1041'; name='Exfiltration Over C2 Channel' })
        interval='1m'; from='now-3m'
        event_ids=@('11','3')
        supp=@{ group=@('host.name'); dur=120 }
        required_extra=@('file.extension','file.path','process.name','user.name','destination.ip','destination.port')
        notes='Detection basis: T1005/T1074.001/T1560.001 staging/archive telemetry; the PowerShell network stage most plausibly matches the status channel, not the curl transfer. Transfer success is established only by the sink receipt. See docs/correlation-architecture.md C4.'
        fp=@('Generated info.txt/_manifest.txt satisfy the first stage; assess matches against the ledger before attribution. No measured false-positive rate is implied.')
    }
    @{
        file='s4-system-powershell-curl-web-ports.eql'; id='S4'
        name='[S4] SYSTEM PowerShell or Curl Network Activity on Web Ports'
        desc='SYSTEM PowerShell or curl connection to selected web ports outside listed network ranges. Does not prove protocol, maliciousness, or successful transfer.'
        tags=@('Signal','Exfiltration','T1041','Egress')
        severity='high'; risk=73
        tactic=@('TA0010','Exfiltration')
        techniques=@(
            @{ id='T1041'; name='Exfiltration Over C2 Channel' })
        interval='1m'; from='now-2m'
        event_ids=@('3')
        supp=@{ group=@('host.name'); dur=60 }
        required_extra=@('destination.ip','destination.port','process.name','user.name')
        notes='Detection basis: generic web-port egress (T1041/T1567-analog); port filters are not protocol verification. See docs/correlation-architecture.md E3.'
        fp=@('Any SYSTEM process using web ports qualifies; no protocol or intent is established. No measured false-positive rate is implied.')
    }
    @{
        file='c5-system-powershell-network-deletion.eql'; id='C5'
        name='[C5] SYSTEM PowerShell Network Activity Followed by File Deletion'
        desc='Same-host SYSTEM PowerShell network activity followed by qualifying SYSTEM file deletion within 120 seconds. Deletion accepts a ZIP extension OR a listed path. Does not establish that the deleted file was transferred; the transfer process is curl, which this sequence does not select.'
        tags=@('Signal','Defense Evasion','T1070.004','Correlation')
        severity='high'; risk=73
        tactic=@('TA0005','Defense Evasion')
        techniques=@(
            @{ id='T1070'; name='Indicator Removal'
               sub='T1070.004|File Deletion' },
            @{ id='T1041'; name='Exfiltration Over C2 Channel' })
        interval='1m'; from='now-2m'
        event_ids=@('3','23')
        supp=@{ group=@('host.name'); dur=30 }
        required_extra=@('destination.ip','destination.port','file.extension','file.path','process.name','user.name')
        notes='Detection basis: T1070.004 deletion telemetry; deletion after outbound activity does not prove transfer success (receipt is the proof). See docs/correlation-architecture.md C5.'
        fp=@('Approved administration, installation, monitoring, backup or automation may overlap the selected conditions. Assess in the destination environment; no measured false-positive rate is implied.')
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
                  'date' = @('@timestamp'); 'wildcard' = @('process.command_line',
                      'winlog.event_data.CommandLine') }
    foreach ($f in $fields) {
        $t = 'keyword'
        foreach ($k in $typeMap.Keys) { if ($typeMap[$k] -contains $f) { $t = $k; break } }
        $requiredFields += @{ name = $f; type = $t }
    }

    $ids = ($r.event_ids -join ', ')
    # fields that must exist per the pipeline; at least one value name for C2/R1-style events
    $setup = @(
        "## Data requirements - $($r.id)",
        '',
        "- Sysmon event IDs consumed by the query: $ids.",
        '- Channel: Microsoft-Windows-Sysmon/Operational.',
        '- Detection basis: ' + $r.notes,
        '',
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

    # New-MitreThreat emits one object through the pipeline, which PowerShell
    # unrolls to a scalar; @(...) re-wraps so the export keeps an array.
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
    $lines += (ConvertTo-CompactJson $obj)
}

New-Item -ItemType Directory -Force -Path $outDir | Out-Null
[System.IO.File]::WriteAllLines($outPath, $lines,
    (New-Object System.Text.UTF8Encoding($false)))
Write-Host "wrote $($lines.Count) rules -> $outPath"