from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Tuple
from collections import defaultdict
import datetime, json, os, re


@dataclass
class ReportItem:
    ts: str
    category: str           # 'scan' | 'modbus' | ...
    inputs: Dict[str, Any]  # tool inputs (as you pass them)
    output: str             # raw output string

REPORT_INBOX: List[ReportItem] = []

def add_to_report(category: str, inputs: Dict[str, Any], output: str) -> None:
    REPORT_INBOX.append(
        ReportItem(
            ts=datetime.datetime.utcnow().isoformat() + "Z",
            category=category,
            inputs=inputs or {},
            output=output or ""
        )
    )

def get_report_items() -> List[Dict[str, Any]]:
    return [asdict(i) for i in REPORT_INBOX]

def clear_report_items() -> None:
    REPORT_INBOX.clear()


# =========================
# Scan parsing (RustScan/Nmap-style)
# =========================
_nmap_target_re   = re.compile(r'^Nmap scan report for (.+?)(?: \(([\d\.]+)\))?\s*$', re.IGNORECASE)
_nmap_port_re     = re.compile(r'^(\d+)\/(\w+)\s+(\w+)\s+([^\s]+)', re.IGNORECASE)
_rustscan_open_re = re.compile(r'^\s*Open\s+([0-9A-Fa-f\.:]+):(\d+)\s*$', re.IGNORECASE)

def extract_scan_facts(raw_output: str):
    """
    -> dict[target] = {'open': [ {port, proto, service, state}... ],
                       'closed': [...], 'other': [...]}
    """
    facts = defaultdict(lambda: {'open': [], 'closed': [], 'other': []})
    current_target = None
    for line in (raw_output or '').splitlines():
        s = line.strip()

        m_rs = _rustscan_open_re.match(s)
        if m_rs:
            host = m_rs.group(1); port = int(m_rs.group(2))
            current_target = host
            facts[current_target]['open'].append({'port': port, 'proto': 'tcp', 'service': 'unknown', 'state': 'open'})
            continue

        m_t = _nmap_target_re.match(s)
        if m_t:
            host = m_t.group(1).strip()
            ip   = (m_t.group(2) or '').strip()
            current_target = ip or host
            continue

        m_p = _nmap_port_re.match(s)
        if m_p and current_target:
            port   = int(m_p.group(1))
            proto  = m_p.group(2).lower()
            state  = m_p.group(3).lower()
            service= m_p.group(4).lower()
            bucket = 'open' if state == 'open' else ('closed' if state == 'closed' else 'other')
            facts[current_target][bucket].append({'port': port, 'proto': proto, 'service': service, 'state': state})
    return facts


# =========================
# Modbus summarization 
# =========================

def _norm(s): return (s or "").strip()

# scan_units output lines and summary
ACTIVE_UNIT_LINE_RE   = re.compile(r'\[✓\]\s*Unit ID\s+(\d+)\s*:\s*ACTIVE', re.IGNORECASE)
SUMMARY_ACTIVE_COUNT  = re.compile(r'Active Units Found:\s*(\d+)', re.IGNORECASE)
SUMMARY_UNIT_IDS_LINE = re.compile(r'Unit IDs:\s*([0-9,\s]+)', re.IGNORECASE)

# scan_registers output lines and summary
ADDR_OK_LINE_RE       = re.compile(r'^\[✓\]\s*Address\s+(\d+)\s*:\s*(.+)$', re.IGNORECASE | re.MULTILINE)
SUMMARY_REGS_COUNT    = re.compile(r'Accessible Registers:\s*(\d+)', re.IGNORECASE)
SUMMARY_FIRST_ADDR    = re.compile(r'First Address:\s*(\d+)', re.IGNORECASE)
SUMMARY_LAST_ADDR     = re.compile(r'Last Address:\s*(\d+)', re.IGNORECASE)

def _looks_successful(out: str) -> bool:
    out = _norm(out)
    if not out:
        return False
    return bool(re.search(r'\b(Read response|Write successful|\[✓\])\b', out, re.IGNORECASE))

def _parse_unit_ids(out: str) -> List[int]:
    ids = set(int(m.group(1)) for m in ACTIVE_UNIT_LINE_RE.finditer(out or ''))
    m = SUMMARY_UNIT_IDS_LINE.search(out or '')
    if m:
        for tok in m.group(1).split(','):
            tok = tok.strip()
            if tok.isdigit():
                ids.add(int(tok))
    return sorted(ids)

def _counts_for_scan_units(out: str) -> Dict[str, Any]:
    count = 0
    m = SUMMARY_ACTIVE_COUNT.search(out or '')
    if m and m.group(1).isdigit():
        count = int(m.group(1))
    else:
        count = len(list(ACTIVE_UNIT_LINE_RE.finditer(out or '')))
    return {"active_units": count, "unit_ids_found": _parse_unit_ids(out or '')}

def _counts_for_scan_registers(out: str) -> Dict[str, Any]:
    count = 0
    m = SUMMARY_REGS_COUNT.search(out or '')
    if m and m.group(1).isdigit():
        count = int(m.group(1))
    else:
        count = len(list(ADDR_OK_LINE_RE.finditer(out or '')))
    first_addr = None; last_addr = None
    m1 = SUMMARY_FIRST_ADDR.search(out or '')
    m2 = SUMMARY_LAST_ADDR.search(out or '')
    if m1 and m1.group(1).isdigit(): first_addr = int(m1.group(1))
    if m2 and m2.group(1).isdigit(): last_addr  = int(m2.group(1))
    return {
        "accessible_registers": count,
        "first_address_found": first_addr,
        "last_address_found": last_addr
    }

def _summarize_modbus_item(item: dict) -> dict:
    """Return facts for a single modbus entry based on inputs + output (no raw dumps)."""
    ins = item.get("inputs") or {}
    out = item.get("output") or ""

    action   = _norm(ins.get("action"))
    function = _norm(ins.get("function")) or None  # not used by scan_units
    target   = _norm(ins.get("target")) or "unknown-target"
    port     = ins.get("port", 502)
    unit_id  = ins.get("unit_id", None)
    address  = ins.get("address", None)
    count    = ins.get("count", None)
    value    = ins.get("value", None)

    unit_start = ins.get("unit_start", None)
    unit_end   = ins.get("unit_end", None)

    success = _looks_successful(out)

    # defaults
    active_units = 0
    accessible_registers = 0
    unit_ids_found: List[int] = []
    first_addr_found = None
    last_addr_found = None

    if action == "scan_units":
        c = _counts_for_scan_units(out)
        active_units = c["active_units"]
        unit_ids_found = c["unit_ids_found"]
    elif action in ("scan_registers", "scan_register_range"):
        c = _counts_for_scan_registers(out)
        accessible_registers = c["accessible_registers"]
        first_addr_found = c["first_address_found"]
        last_addr_found  = c["last_address_found"]
    else:
        accessible_registers = len(list(ADDR_OK_LINE_RE.finditer(out or '')))

    summary = {
        "action": action,
        "function": function,
        "target": target,
        "port": port,
        "unit_id": unit_id,
        "address": address,
        "count": count,
        "value": value,
        "unit_start": unit_start,
        "unit_end": unit_end,
        "range_start": address,
        "range_end": (address + count - 1) if (isinstance(address, int) and isinstance(count, int)) else None,
        "result": {
            "success": success,
            "active_units": active_units,
            "accessible_registers": accessible_registers,
            "unit_ids_found": unit_ids_found if unit_ids_found else None,
            "first_address_found": first_addr_found,
            "last_address_found": last_addr_found,
        }
    }
    return summary


# =========================
# MITRE ATT&CK for ICS mitigations
# =========================
# Reference: https://attack.mitre.org/matrices/ics/
_MITRE = {
    "M0930": {"id": "M0930", "name": "Network Segmentation", "url": "https://attack.mitre.org/mitigations/M0930/"},
    "M0937": {"id": "M0937", "name": "Filter Network Traffic", "url": "https://attack.mitre.org/mitigations/M0937/"},
    "M0807": {"id": "M0807", "name": "Network Allowlists", "url": "https://attack.mitre.org/mitigations/M0807/"},
    "M0800": {"id": "M0800", "name": "Authorization Enforcement", "url": "https://attack.mitre.org/mitigations/M0800/"},
    "M0808": {"id": "M0808", "name": "Encrypt Network Traffic", "url": "https://attack.mitre.org/mitigations/M0808/"},
    "M0935": {"id": "M0935", "name": "Limit Access to Resource Over Network", "url": "https://attack.mitre.org/mitigations/M0935/"},
}

_SERVICE_TO_MITIGATIONS = {
    # ICS protocols
    "modbus":   ["M0930", "M0937", "M0807", "M0800", "M0808", "M0935"],
    "dnp3":     ["M0930", "M0937", "M0807", "M0800", "M0808", "M0935"],
    "s7":       ["M0930", "M0937", "M0807", "M0800", "M0808", "M0935"],
    "opcua":    ["M0930", "M0937", "M0807", "M0800", "M0808", "M0935"],
    "opc":      ["M0930", "M0937", "M0807", "M0800", "M0935"],
    # remote admin / mgmt
    "rdp":      ["M0930", "M0937", "M0800", "M0935"],
    "vnc":      ["M0930", "M0937", "M0800", "M0935"],
    "ssh":      ["M0930", "M0937", "M0800"],
    "telnet":   ["M0930", "M0937", "M0800", "M0935"],
    "snmp":     ["M0930", "M0937", "M0800", "M0935"],
    # web stacks
    "http":     ["M0930", "M0937", "M0800"],
    "https":    ["M0930", "M0937", "M0800"],
    # databases
    "mssql":    ["M0930", "M0937", "M0800"],
    "oracle":   ["M0930", "M0937", "M0800"],
    "mysql":    ["M0930", "M0937", "M0800"],
    "postgres": ["M0930", "M0937", "M0800"],
    # default when we only know “open/unknown”
    "_default": ["M0930", "M0937", "M0935"],
}

_MODBUS_ACTION_TO_MITIGATIONS = {
    "read":                 ["M0930", "M0937", "M0807", "M0800", "M0808", "M0935"],
    "write":                ["M0930", "M0937", "M0807", "M0800", "M0808", "M0935"],
    "enumerate":            ["M0930", "M0937", "M0807", "M0800", "M0935"],
    "scan_units":           ["M0930", "M0937", "M0807", "M0800", "M0935"],
    "scan_registers":       ["M0930", "M0937", "M0807", "M0800", "M0935"],
    "scan_register_range":  ["M0930", "M0937", "M0807", "M0800", "M0935"],
}

def _mitigations_for_service(service_str: str):
    s = (service_str or "").lower()
    for key, mids in _SERVICE_TO_MITIGATIONS.items():
        if key != "_default" and key in s:
            return [_MITRE[m] for m in mids]
    return [_MITRE[m] for m in _SERVICE_TO_MITIGATIONS["_default"]]

def _mitigations_for_modbus_action(action: str):
    a = (action or "").lower()
    mids = _MODBUS_ACTION_TO_MITIGATIONS.get(a, _MODBUS_ACTION_TO_MITIGATIONS["enumerate"])
    return [_MITRE[m] for m in mids]

def _dedup_mitigations(mit_list: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Flatten + deduplicate mitigation dicts by ID, keep a stable order."""
    seen = set()
    out = []
    for m in mit_list:
        mid = m.get("id")
        if mid and mid not in seen:
            seen.add(mid)
            out.append(m)
    return out


# =========================
# OpenAI client
# =========================
def _get_openai_client():
    from openai import OpenAI
    key = os.getenv("OPENAI_API_KEY")
    if not key:
        raise RuntimeError("OPENAI_API_KEY not set")
    return OpenAI(api_key=key)


# =========================
# Dataset builders (shared by both audiences)
# =========================
def _build_targets_and_modbus(items: List[Dict[str, Any]]):
    """Create per-target open-service facts and per-target modbus activity summaries."""
    targets = defaultdict(lambda: {'open': [], 'closed': [], 'other': []})
    modbus_by_target = defaultdict(list)

    # scans
    for it in items:
        if it.get('category') == 'scan':
            facts = extract_scan_facts(it.get('output', '') or '')
            for tgt, buckets in facts.items():
                targets[tgt]['open'].extend(buckets['open'])
                targets[tgt]['closed'].extend(buckets['closed'])
                targets[tgt]['other'].extend(buckets['other'])

    # modbus
    for it in items:
        if it.get('category') != 'modbus':
            continue
        msum = _summarize_modbus_item(it)
        modbus_by_target[msum["target"]].append(msum)

        if msum["result"]["success"]:
            if msum["target"] not in targets:
                targets[msum["target"]] = {'open': [], 'closed': [], 'other': []}
            already = any((e.get('service','') or '').lower().startswith('modbus')
                          for e in targets[msum["target"]]['open'])
            if not already:
                targets[msum["target"]]['open'].append({
                    'port': 502, 'proto': 'tcp', 'service': 'modbus (validated)', 'state': 'open'
                })

    exec_targets = []
    for tgt, buckets in targets.items():
        open_services = [
            {
                'port': e['port'],
                'proto': e.get('proto', 'tcp'),
                'service': e.get('service', 'unknown'),
            }
            for e in buckets['open']
        ]
        exec_targets.append({
            'name': tgt,
            'totals': {
                'open': len(buckets['open']),
                'closed_or_filtered': len(buckets['closed']) + len(buckets['other']),
            },
            'open_services': open_services,
            'modbus_activities': modbus_by_target.get(tgt, [])
        })

    return exec_targets, modbus_by_target


# =========================
# Report generation
# =========================
def generate_report(audience: str, title: str, model: str) -> Tuple[str, int]:
    """
    Returns (markdown, items_used_count)
    """
    items = get_report_items()
    if not items:
        return ("", 0)

    audience = (audience or "technical").lower()
    title = title or "ICS/OT Security Test Report"
    model = model or "gpt-4o-mini"

    MAX_ITEMS = 100
    raw_items = items[-MAX_ITEMS:]

    exec_targets, modbus_by_target = _build_targets_and_modbus(raw_items)

    aggregated_mitigations: List[Dict[str, Any]] = []
    
    for t in exec_targets:
        for svc in t['open_services']:
            aggregated_mitigations.extend(_mitigations_for_service(svc.get('service', '')))
    
    for t in exec_targets:
        for act in t['modbus_activities']:
            aggregated_mitigations.extend(_mitigations_for_modbus_action(act.get('action', 'enumerate')))
    recommended_mitigations = _dedup_mitigations(aggregated_mitigations)[:12]

    # ========== EXECUTIVE  ==========
    if audience == "executive":
        targets_count = len(exec_targets)
        total_open_ports = sum(t['totals']['open'] for t in exec_targets)
        ics_keywords = ('modbus','dnp3','s7','opc','opcua')
        ics_protocols_present = sorted({
            svc['service']
            for t in exec_targets
            for svc in t['open_services']
            if any(k in (svc['service'] or '').lower() for k in ics_keywords)
        })
        modbus_actions_count = sum(len(modbus_by_target.get(t['name'], [])) for t in exec_targets)
        modbus_targets = sorted([t['name'] for t in exec_targets if modbus_by_target.get(t['name'])])

        executive_dataset = {
            'rollup': {
                'targets_count': targets_count,
                'targets': [t['name'] for t in exec_targets],
                'total_open_ports': total_open_ports,
                'ics_protocols_present': ics_protocols_present,
                'modbus_actions_count': modbus_actions_count,
                'modbus_targets': modbus_targets,
            },
            'targets': exec_targets,  
            'final_mitigations': recommended_mitigations,
            'notes': "Facts only; no commands or raw dumps. Provide mitigations only in the final section."
        }

        payload = json.dumps(executive_dataset, ensure_ascii=False, indent=2)
        used = targets_count

        system_msg = (
            "You are a senior ICS/OT penetration tester writing an executive-level report for non-technical stakeholders. "
            "Use ONLY the provided dataset. Do NOT invent vulnerabilities or details. "
            "Do NOT include command lines or raw dumps."
        )
        guidance = (
            "Audience: Executive\n"
            "Write a concise narrative with these sections:\n"
            "1) Scope & Approach – high-level scope only.\n"
            "2) Activities Performed – summarize (e.g., scanning, Modbus interactions); no commands.\n"
            "3) Key Findings – high-level discoveries across targets (exposed services; validated Modbus access).\n"
            "4) Recommended Mitigations – present ONLY here, using the provided 'final_mitigations' list (ID + name + 1-line rationale). "
            "   Do NOT attach mitigations to each service or action elsewhere in the report.\n"
            "5) 30/60/90-Day Plan – prioritized steps.\n"
            "Constraints: no raw evidence; no per-action/service mitigation lists; only the consolidated final section."
        )

    # ========== TECHNICAL ==========
    else:
        technical_dataset = {
            'targets': exec_targets,
            'final_mitigations': recommended_mitigations,
            'notes': (
                "Structured technical summary derived from executed scans and Modbus interactions. "
                "Mitigations are consolidated at the end; no per-action/service mitigation lists."
            )
        }
        payload = json.dumps(technical_dataset, ensure_ascii=False, indent=2)
        used = len(exec_targets)

        system_msg = (
            "You are a senior ICS/OT penetration tester producing a structured technical report. "
            "Use ONLY the provided dataset. Do NOT include command lines or raw output."
        )
        guidance = (
            "Audience: Technical\n"
            "Write a clear report with:\n"
            "1) Overview – brief context.\n"
            "2) Exposure Overview – per target: totals and open services (port/proto/service).\n"
            "3) Modbus Activity – per target: list each action with fields {action, function, target, port, unit_id, "
            "   address, count, value, unit_start, unit_end, range_start, range_end} and a short result (success/counters). "
            "4) Consolidated Mitigations – ONLY here, use the provided 'final_mitigations' list (ID + name + short rationale). "
            "Constraints: no raw evidence; no per-action/service mitigation lists elsewhere."
        )

    # ========== LLM call ==========
    client = _get_openai_client()
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_msg},
            {"role": "user", "content":
                f"# {title}\nUse the following data.\n\n{guidance}\n\n=== BEGIN DATA ===\n{payload}\n=== END DATA ===\n"
            }
        ],
        temperature=0.2
    )
    md = resp.choices[0].message.content.strip()
    return (md, used)
