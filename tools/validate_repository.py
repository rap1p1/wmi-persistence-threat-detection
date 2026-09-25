#!/usr/bin/env python3
"""Offline packaging checks; does not execute scenario code or validate EQL."""
import hashlib
import json
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]


def rule_metadata_errors(rule):
    """Check this repository's documented dependencies, not EQL execution."""
    errors = []
    query = re.sub(r'/\*.*?\*/', '', rule['query'], flags=re.S)
    plain = re.sub(r'"(?:\\.|[^"\\])*"', '""', query)
    fields = set(re.findall(r'\b(?:winlog|host|user|process|file|destination)\.[A-Za-z0-9_.]+', plain))
    fields.update(rule.get('alert_suppression', {}).get('group_by', []))
    fields.add('@timestamp')
    if re.search(r'\b(?:process|file|network)\s+where', plain):
        fields.add('event.category')
    declared = rule.get('required_fields', [])
    names = {item.get('name') for item in declared if isinstance(item, dict)}
    if fields - names:
        errors.append('Undocumented query/suppression fields: ' + ', '.join(sorted(fields - names)))
    if len(names) != len(declared) or any(not item.get('type') for item in declared if isinstance(item, dict)):
        errors.append('Invalid or duplicate required_fields entries')
    event_ids = set(re.findall(r'winlog\.event_id\s*(?:==|:)\s*"(\d+)"', query))
    setup = rule.get('setup', '')
    match = re.search(r'Sysmon event IDs consumed by the query: ([0-9, ]+)\.', setup)
    if not match or set(re.findall(r'\d+', match.group(1))) != event_ids:
        errors.append('Setup event sources differ from the query')
    text = '\n'.join([rule.get('name', ''), rule.get('description', ''), setup, rule['query']]).casefold()
    obsolete_claims = ('fp rate: ~0%', 'không có legitimate use case',
                       'invariant cua wmi execution', 'anchor event — exfil confirmation',
                       'binding — persistence activated',
                       'step 2 có fallback bắt bất kỳ child process nào')
    if any(phrase in text for phrase in obsolete_claims):
        errors.append('Historical unsupported claim has reappeared')
    if 'docs/telemetry-contract.md' not in setup:
        errors.append('Setup lacks the telemetry interpretation reference')
    return errors


def validate():
    errors = []
    try:
        ET.parse(ROOT / 'config/sysmon-config.xml')
    except ET.ParseError as exc:
        errors.append(f'Sysmon XML: {exc}')

    rules = []
    for number, line in enumerate((ROOT / 'rules/rules_wmi.ndjson').read_text(encoding='utf-8').splitlines(), 1):
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            errors.append(f'Invalid JSON on rule line {number}')
            continue
        if not isinstance(item, dict):
            errors.append(f'Expected rule object on line {number}')
            continue
        if not isinstance(item.get('query'), str) or item.get('type') != 'eql':
            errors.append(f'Unexpected non-EQL object on rule line {number}')
            continue
        rules.append(item)
        if item.get('actions') != []:
            errors.append(f'Public rule line {number} contains notification actions')
        if item.get('language') != 'eql' or not item.get('rule_id'):
            errors.append(f'Missing rule identity/language on line {number}')
        if any(field in item for field in ('created_by', 'updated_by', 'meta')):
            errors.append(f'Environment metadata on rule line {number}')
        errors.extend(f'Rule line {number}: {error}' for error in rule_metadata_errors(item))

    names = {r.get('name', '').split(']')[0].lstrip('[') for r in rules}
    expected = {'C1', 'C2', 'C3', 'C4', 'C5', 'S1', 'S2', 'S3', 'S4'}
    if len(rules) != 9 or names != expected:
        errors.append('Expected exactly C1-C5 and S1-S4')
    if len({r.get('rule_id') for r in rules}) != len(rules):
        errors.append('Duplicate rule IDs')
    sequences = sum(r['query'].lstrip().startswith('sequence ') for r in rules)
    if sequences != 4:
        errors.append('Expected four sequence rules')

    # A narrow hygiene check, not a comprehensive secret scanner. Never print matches.
    token_pattern = re.compile(r'\b\d{6,12}:[A-Za-z0-9_-]{30,}\b')
    text_paths = [ROOT / 'README.md', ROOT / 'CHANGELOG.md']
    for folder in ('docs', 'rules', 'config', 'scripts', 'phishing'):
        text_paths.extend(x for x in (ROOT / folder).rglob('*')
                          if x.suffix.lower() in {'.md', '.ndjson', '.xml', '.ps1', '.bat', '.html'})
    for path in text_paths:
        if token_pattern.search(path.read_text(encoding='utf-8')):
            errors.append(f'Potential bot credential in {path.relative_to(ROOT)} (value suppressed)')

    for path in [ROOT / 'README.md', ROOT / 'CHANGELOG.md',
                 *sorted((ROOT / 'docs').rglob('*.md')),
                 *sorted((ROOT / 'scripts').rglob('*.md'))]:
        for target in re.findall(r'\[[^\]]*\]\(([^\s)]+)\)', path.read_text(encoding='utf-8')):
            if target.startswith(('https://', 'http://', 'mailto:', '#')):
                continue
            if not (path.parent / target.split('#')[0]).exists():
                errors.append(f'Broken local link in {path.relative_to(ROOT)}: {target}')

    evidence_dir = ROOT / 'docs/evidence'
    try:
        manifest = json.loads((evidence_dir / 'manifest.json').read_text(encoding='utf-8'))
        entries = manifest['images']
        filenames = [entry['file'] for entry in entries]
        actual = {path.name for path in evidence_dir.glob('*.png')}
        if len(set(filenames)) != len(filenames) or set(filenames) != actual:
            errors.append('Evidence manifest does not match the image inventory')
        for entry in entries:
            name = entry['file']
            if Path(name).name != name:
                errors.append('Evidence manifest contains a non-local filename')
                continue
            path = evidence_dir / name
            if not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != entry['sha256']:
                errors.append(f'Evidence hash mismatch or missing file: {name}')
    except (OSError, ValueError, KeyError, TypeError):
        errors.append('Evidence manifest is missing or malformed')

    if errors:
        for error in errors:
            print(f'FAIL: {error}')
        return 1
    print('PASS: XML, nine EQL rule objects, four sequences, field/setup consistency, known-claim regressions, export hygiene, local links, evidence hashes.')
    print('NOT VALIDATED: Sysmon runtime/schema, Elastic import/EQL execution, detection quality, document images, Git-history secrets.')
    return 0


if __name__ == '__main__':
    sys.exit(validate())
