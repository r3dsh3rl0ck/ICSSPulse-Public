"""
Universal reporting engine for ICSSPulse.

Reporting is controller-agnostic: every controller pushes activity into a shared
inbox using the same schema ({category, inputs, output}) via add_to_report().
The engine then normalizes those raw records into a single universal activity
model — inferring target/action/port, sanitizing sensitive inputs, summarizing
output and guessing success — without any per-protocol report logic.

Scan parsing is kept ONLY as an optional enrichment for the "scan" category;
it is not the backbone of the model. Adding a new controller requires no changes
here: it just lands in the inbox and is normalized like everything else.

Public API (imported by app.py — keep these signatures stable):
    add_to_report(category, inputs, output)
    get_report_items()
    clear_report_items()
    generate_report(audience, title, model)
"""

from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Tuple, Optional
from collections import defaultdict, Counter
import datetime, json, os, re


# =========================
# Inbox storage (generic)
# =========================
@dataclass
class ReportItem:
    ts: str
    category: str           # controller name, e.g. 'scan' | 'modbus' | 'opcua' | ...
    inputs: Dict[str, Any]  # controller-specific inputs, stored verbatim
    output: str             # raw output string

REPORT_INBOX: List[ReportItem] = []


def add_to_report(category: str, inputs: Dict[str, Any], output: str) -> None:
    """Append a generic controller activity record to the inbox."""
    REPORT_INBOX.append(
        ReportItem(
            ts=datetime.datetime.utcnow().isoformat() + "Z",
            category=(category or "unknown").strip().lower(),
            inputs=inputs or {},
            output=output or "",
        )
    )


def get_report_items() -> List[Dict[str, Any]]:
    """Return the raw inbox (verbatim inputs/output) for inbox management UIs."""
    return [asdict(i) for i in REPORT_INBOX]


def clear_report_items() -> None:
    REPORT_INBOX.clear()


# =========================
# Generic normalization helpers
# =========================
MAX_OUTPUT_CHARS = 4000   # cap raw output forwarded to the model
EXCERPT_CHARS    = 600    # short preview kept per activity

_ANSI_RE = re.compile(r'\x1b\[[0-9;]*[A-Za-z]')
_IPV4_RE = re.compile(r'\b(\d{1,3}(?:\.\d{1,3}){3})\b')
_HOST_PORT_RE = re.compile(r'\b((?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9.\-]+):(\d{1,5})\b')

# Keys whose values must never reach the model in raw form.
_SENSITIVE_KEY_RE = re.compile(
    r'(pass|pwd|secret|token|api[_-]?key|apikey|credential|cert|key|auth|session|cookie)',
    re.IGNORECASE,
)
_REDACTED = "***REDACTED***"

# Heuristic success/failure signals (generic across controllers).
_FAILURE_RE = re.compile(
    r'\b(error|errno|failed|failure|timed?\s*out|timeout|refused|unreachable|'
    r'no response|unable|cannot|denied|unauthor|forbidden|exception|traceback|'
    r'\[✗\]|\[x\]|not found)\b',
    re.IGNORECASE,
)
_SUCCESS_RE = re.compile(
    r'\b(success|successful|read response|write successful|connected|established|'
    r'discovered|enumerated|active|accessible|found \d+|\[✓\])\b',
    re.IGNORECASE,
)


def _norm(s: Any) -> str:
    return (str(s) if s is not None else "").strip()


def _normalize_text(text: str) -> str:
    """Strip ANSI colour codes and normalize line endings/trailing whitespace."""
    if not text:
        return ""
    text = _ANSI_RE.sub("", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [ln.rstrip() for ln in text.split("\n")]
    return "\n".join(lines).strip()


def _clip(text: str, limit: int) -> Tuple[str, bool]:
    """Return (clipped_text, was_truncated)."""
    if len(text) <= limit:
        return text, False
    return text[:limit].rstrip() + f"\n…[truncated, {len(text)} chars total]", True


def _sanitize_inputs(inputs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Redact sensitive values (passwords, tokens, cert/key material, API keys…)
    while preserving the key so the structure stays useful for the report.
    """
    clean: Dict[str, Any] = {}
    for k, v in (inputs or {}).items():
        if _SENSITIVE_KEY_RE.search(str(k)):
            clean[k] = _REDACTED if v not in (None, "", []) else v
        elif isinstance(v, dict):
            clean[k] = _sanitize_inputs(v)
        elif isinstance(v, str) and len(v) > 500:
            clean[k] = v[:500] + "…[truncated]"
        else:
            clean[k] = v
    return clean


def _infer_action(category: str, inputs: Dict[str, Any]) -> str:
    action = _norm(inputs.get("action")) or _norm(inputs.get("command"))
    if action:
        # collapse a full command line down to its first token for a label
        return action.split()[0] if " " in action and category == "scan" else action
    return "scan" if category == "scan" else "execute"


def _infer_target(inputs: Dict[str, Any], output: str) -> str:
    target = _norm(inputs.get("target")) or _norm(inputs.get("host"))
    if target:
        return target
    # Fall back to the first IP seen in args or output.
    for source in (inputs.get("args"), inputs.get("command"), output):
        if not source:
            continue
        text = " ".join(source) if isinstance(source, list) else str(source)
        m = _IPV4_RE.search(text)
        if m:
            return m.group(1)
    return "unknown-target"


def _infer_port(inputs: Dict[str, Any], output: str) -> Optional[int]:
    raw = inputs.get("port")
    if raw not in (None, ""):
        try:
            return int(raw)
        except (TypeError, ValueError):
            pass
    m = _HOST_PORT_RE.search(output or "")
    if m:
        try:
            return int(m.group(2))
        except ValueError:
            return None
    return None


def _guess_success(output: str) -> str:
    """Heuristically classify an activity as 'success' | 'failure' | 'unknown'."""
    text = output or ""
    if not text.strip():
        return "unknown"
    has_fail = bool(_FAILURE_RE.search(text))
    has_ok = bool(_SUCCESS_RE.search(text))
    if has_ok and not has_fail:
        return "success"
    if has_fail and not has_ok:
        return "failure"
    if has_ok and has_fail:
        # Mixed signals: trust an explicit success marker over generic noise.
        return "success" if "[✓]" in text else "unknown"
    return "unknown"


def _normalize_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """
    Turn one raw inbox record into a universal, model-safe activity record.
    This is the single place every controller's data passes through.
    """
    category = _norm(item.get("category")).lower() or "unknown"
    raw_inputs = item.get("inputs") or {}
    clean_output = _normalize_text(item.get("output") or "")

    excerpt, _ = _clip(clean_output, EXCERPT_CHARS)
    bounded_output, truncated = _clip(clean_output, MAX_OUTPUT_CHARS)

    record = {
        "ts": item.get("ts"),
        "controller": category,
        "action": _infer_action(category, raw_inputs),
        "target": _infer_target(raw_inputs, clean_output),
        "port": _infer_port(raw_inputs, clean_output),
        "inputs": _sanitize_inputs(raw_inputs),
        "output": bounded_output,
        "result": {
            "success_guess": _guess_success(clean_output),
            "excerpt": excerpt,
            "output_size": len(clean_output),
            "truncated": truncated,
        },
    }

    # Optional scan-specific enrichment — does not change the core model.
    if category == "scan":
        facts = extract_scan_facts(item.get("output") or "")
        if facts:
            record["scan_facts"] = {host: buckets for host, buckets in facts.items()}

    # Richer interpretation/metrics layer (uses full, unclipped clean output so
    # trailing summary lines are never lost to truncation).
    _enrich_and_interpret(record, clean_output)

    return record


# =========================
# Scan parsing (optional enrichment for category == 'scan')
# =========================
_nmap_target_re   = re.compile(r'^Nmap scan report for (.+?)(?: \(([\d\.]+)\))?\s*$', re.IGNORECASE)
_nmap_port_re     = re.compile(r'^(\d+)\/(\w+)\s+(\w+)\s+([^\s]+)', re.IGNORECASE)
_rustscan_open_re = re.compile(r'^\s*Open\s+([0-9A-Fa-f\.:]+):(\d+)\s*$', re.IGNORECASE)


def extract_scan_facts(raw_output: str) -> Dict[str, Dict[str, list]]:
    """
    Parse RustScan/Nmap-style output into per-target port facts.
    -> dict[target] = {'open': [{port, proto, service, state}...], 'closed': [...], 'other': [...]}
    """
    facts: Dict[str, Dict[str, list]] = defaultdict(lambda: {'open': [], 'closed': [], 'other': []})
    current_target = None
    for line in (raw_output or '').splitlines():
        s = _ANSI_RE.sub("", line).strip()

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
            port    = int(m_p.group(1))
            proto   = m_p.group(2).lower()
            state   = m_p.group(3).lower()
            service = m_p.group(4).lower()
            bucket  = 'open' if state == 'open' else ('closed' if state == 'closed' else 'other')
            facts[current_target][bucket].append({'port': port, 'proto': proto, 'service': service, 'state': state})
    return dict(facts)


# =========================
# MITRE ATT&CK for ICS mitigations catalogue
# Reference: https://attack.mitre.org/matrices/ics/
# This stays the authoritative framework — the scoring engine only ever selects
# mitigations from this catalogue (the LLM may not add/relabel them).
# =========================
def _mitre(mid: str, name: str) -> Dict[str, str]:
    return {"id": mid, "name": name, "url": f"https://attack.mitre.org/mitigations/{mid}/"}

_MITRE = {
    "M0930": _mitre("M0930", "Network Segmentation"),
    "M0937": _mitre("M0937", "Filter Network Traffic"),
    "M0931": _mitre("M0931", "Network Intrusion Prevention"),
    "M0807": _mitre("M0807", "Network Allowlists"),
    "M0800": _mitre("M0800", "Authorization Enforcement"),
    "M0801": _mitre("M0801", "Access Management"),
    "M0802": _mitre("M0802", "Communication Authenticity"),
    "M0808": _mitre("M0808", "Encrypt Network Traffic"),
    "M0813": _mitre("M0813", "Software Process and Device Authentication"),
    "M0814": _mitre("M0814", "Static Network Configuration"),
    "M0935": _mitre("M0935", "Limit Access to Resource Over Network"),
}


# =========================
# Interpretation & enrichment layer
# =========================
# Goal: give every activity a much richer, structured explanation instead of a
# generic one-liner. Each record gains:
#   metrics        – numbers/values parsed from the output (counts, ranges, …)
#   evidence       – a few short, meaningful excerpt lines (not a raw dump)
#   interpretation – {activity, observation, implication, significance}
#
# A generic interpreter handles any controller; per-controller enrichers add
# protocol-aware detail. Adding a new controller still works without one — it
# simply falls back to the generic interpretation.

def _to_int(v) -> Optional[int]:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _scope(rec: Dict[str, Any]) -> str:
    return rec["target"] + (f":{rec['port']}" if rec.get("port") else "")


def _parse_value_list(blob: str) -> list:
    """Parse a Python-ish list literal like '[True, False, 123]' tolerantly."""
    out = []
    for tok in blob.strip().strip("[]").split(","):
        t = tok.strip()
        if not t:
            continue
        if t in ("True", "False"):
            out.append(t == "True")
        else:
            iv = _to_int(t)
            out.append(iv if iv is not None else t)
    return out


def _evidence_lines(output: str, limit: int = 8) -> List[str]:
    """Pick a few informative lines as evidence (short, deduped — not a dump)."""
    keys = ("[✓]", "[+]", "[!]", "[SUCCESS]", "[FAIL]", "[ERROR]", "Found ",
            "Read ", "Write", "Value:", "State", "Level", "Firmware",
            "Active Units", "Accessible", "Discovered", "ns=", " = ", ": ")
    picked, seen = [], set()
    for raw in output.splitlines():
        line = raw.strip()
        if not line or line.startswith("===") or set(line) <= {"─", "-", "="}:
            continue
        if any(k in line for k in keys):
            if line not in seen:
                seen.add(line)
                picked.append(line[:160])
        if len(picked) >= limit:
            break
    return picked


# ---- per-controller enrichers: return a metrics dict --------------------------
def _enrich_modbus(rec, out) -> Dict[str, Any]:
    ins = rec["inputs"]
    m: Dict[str, Any] = {"function": ins.get("function")}
    addr, count = _to_int(ins.get("address")), _to_int(ins.get("count"))
    if addr is not None:
        m["address"] = addr
        if count:
            m["count"] = count
            m["range"] = [addr, addr + count - 1]

    rr = re.search(r"Read response:\s*(\[.*?\])", out)
    vals = []
    if rr:
        vals = _parse_value_list(rr.group(1))
    else:
        vals = [_parse_value_list(v)[0] if _parse_value_list(v) else v
                for v in re.findall(r"^[A-Za-z ]+\s+\d+:\s*(.+)$", out, re.M)]
    if vals:
        m["values_count"] = len(vals)
        m["values_preview"] = vals[:16]
        if all(isinstance(v, bool) for v in vals):
            m["true_count"] = sum(1 for v in vals if v)
            m["false_count"] = sum(1 for v in vals if not v)
        elif all(isinstance(v, int) for v in vals):
            m["value_min"], m["value_max"] = min(vals), max(vals)

    au = re.search(r"Active Units Found:\s*(\d+)", out)
    if au:
        m["active_units"] = int(au.group(1))
    ids = re.search(r"Unit IDs?:\s*([0-9,\s]+)", out)
    if ids:
        m["unit_ids"] = [int(x) for x in re.findall(r"\d+", ids.group(1))]
    ar = re.search(r"Accessible Registers:\s*(\d+)", out)
    if ar:
        m["accessible_registers"] = int(ar.group(1))
    for label, key in (("First Address", "first_address"), ("Last Address", "last_address")):
        mm = re.search(rf"{label}:\s*(\d+)", out)
        if mm:
            m[key] = int(mm.group(1))
    if re.search(r"Write successful", out, re.IGNORECASE):
        m["write_ok"] = True
    return m


def _enrich_opcua(rec, out) -> Dict[str, Any]:
    m: Dict[str, Any] = {}
    d = re.search(r"Discovered (\d+) endpoint", out)
    if d:
        m["endpoints"] = int(d.group(1))
    modes = re.findall(r"SecurityMode:\s*(\w+)", out)
    if modes:
        m["security_modes"] = sorted(set(modes))
    m["namespaces"] = len(re.findall(r"ns\[\d+\]\s*=", out))
    for label, key in (("Readable Variables", "readable_view"),
                       ("Writable Variables", "writable_view")):
        if label in out:
            m[key] = True
    if re.search(r"No (variables|readable|writable).*found", out, re.IGNORECASE):
        m["variables_found"] = 0
    else:
        # Approximate node count from NodeId-bearing lines.
        nodes = [ln for ln in out.splitlines() if "ns=" in ln and "=" in ln]
        if nodes:
            m["variables_listed"] = len(nodes)
    rd = re.search(r"Read (ns=.+?):\s*(.+)", out)
    if rd:
        m["read_node"], m["read_value"] = rd.group(1).strip(), rd.group(2).strip()[:80]
    wr = re.search(r"Write OK\.\s*(ns=.+?)\s*<=\s*(.+?)\s*\(now:\s*(.+?)\)", out)
    if wr:
        m["write_node"] = wr.group(1).strip()
        m["write_value"] = wr.group(2).strip()[:80]
        m["write_readback"] = wr.group(3).strip()[:80]
    return m


def _enrich_mqtt(rec, out) -> Dict[str, Any]:
    m: Dict[str, Any] = {}
    m["connected"] = bool(re.search(r"\[\+\] Connected to|\[SUCCESS\] Connected", out))
    for pat, key in ((r"Received (\d+) system messages", "sys_messages"),
                     (r"Found (\d+) unique topics", "unique_topics"),
                     (r"Found (\d+) retained message", "retained_messages"),
                     (r"Received (\d+) message", "received_messages")):
        mm = re.search(pat, out)
        if mm:
            m[key] = int(mm.group(1))
    auth = re.search(r"\[SUCCESS\] Connected as (\w+)", out)
    if auth:
        m["auth"] = f"accepted ({auth.group(1)})"
    elif re.search(r"\[FAIL\] Connection refused as", out):
        m["auth"] = "rejected"
    if re.search(r"\[SUCCESS\] Published to", out):
        m["published"] = True
    return m


def _enrich_s7comm(rec, out) -> Dict[str, Any]:
    m: Dict[str, Any] = {}
    for label, key in (("Module Type", "module_type"), ("Module Name", "module_name"),
                       ("Serial Number", "serial"), ("Order Code", "order_code")):
        mm = re.search(rf"{label}\s*:\s*(.+)", out)
        if mm:
            m[key] = mm.group(1).strip()
    fw = re.search(r"Firmware\s*:\s*(V[\d.]+)", out)
    if fw:
        m["firmware"] = fw.group(1)
    st = re.search(r"State\s*:\s*(.+)", out)
    if st:
        m["cpu_state"] = st.group(1).strip()
    lv = re.search(r"Level\s*:\s*(\d+)\s*—\s*(.+)", out)
    if lv:
        m["protection_level"] = int(lv.group(1))
        m["protection_desc"] = lv.group(2).strip()
    if "Protection Level 0" in out:
        m["unauthenticated_access"] = True
    db = re.search(r"Found (\d+) DB", out)
    if db:
        m["data_blocks"] = int(db.group(1))
    val = re.search(r"Value:\s*(.+)", out)
    if val:
        m["read_value"] = val.group(1).strip()[:80]
    if re.search(r"Write OK", out):
        m["write_ok"] = True
    return m


def _enrich_ethernetip(rec, out) -> Dict[str, Any]:
    m: Dict[str, Any] = {}
    for pat, key in ((r"Found (\d+) device", "devices"),
                     (r"Found (\d+) tag", "tags_listed"),
                     (r"Read (\d+) tag", "tags_read")):
        mm = re.search(pat, out)
        if mm:
            m[key] = int(mm.group(1))
    for label, key in (("Product Name", "product_name"), ("Vendor", "vendor"),
                       ("Revision", "revision"), ("Device Type", "device_type")):
        mm = re.search(rf"{label}\s*:\s*(.+)", out)
        if mm:
            m[key] = mm.group(1).strip()
    wr = re.search(r"\[SUCCESS\]\s*(.+?)\s*=\s*(.+)", out)
    if wr:
        m["write_tag"], m["write_value"] = wr.group(1).strip(), wr.group(2).strip()[:80]
    return m


def _enrich_scan(rec, out) -> Dict[str, Any]:
    m: Dict[str, Any] = {}
    facts = rec.get("scan_facts") or {}
    open_ports, services = [], set()
    for buckets in facts.values():
        for svc in buckets.get("open", []):
            open_ports.append(svc["port"])
            if svc.get("service") and svc["service"] != "unknown":
                services.add(svc["service"])
    if open_ports:
        m["open_ports"] = sorted(set(open_ports))
        m["open_count"] = len(open_ports)
    if services:
        m["services"] = sorted(services)
    return m


_ENRICHERS = {
    "modbus": _enrich_modbus,
    "opcua": _enrich_opcua,
    "mqtt": _enrich_mqtt,
    "s7comm": _enrich_s7comm,
    "ethernetip": _enrich_ethernetip,
    "enip": _enrich_ethernetip,
    "scan": _enrich_scan,
}


# ---- interpretation builders --------------------------------------------------
def _join(parts: List[str]) -> str:
    return " ".join(p for p in parts if p).strip()


def _interpret_modbus(rec, m) -> Dict[str, str]:
    action, func, scope = rec["action"], m.get("function"), _scope(rec)
    fn = f"{func} " if func else ""
    if action in ("read", "enumerate"):
        rng = f"addresses {m['range'][0]}–{m['range'][1]}" if m.get("range") else \
              (f"address {m['address']}" if "address" in m else "the requested address(es)")
        activity = f"Read {m.get('values_count', '')} {fn}value(s) from {rng} on {scope} (unit {rec['inputs'].get('unit_id','?')})."
        if "true_count" in m:
            obs = (f"Returned {m['true_count']} asserted (true) and {m['false_count']} de-asserted (false) "
                   f"{fn}states.")
            impl = ("These coil/discrete states reflect live process control bits — the device answered "
                    "unauthenticated read requests and exposed actual I/O state.")
        elif "value_min" in m:
            obs = f"Returned numeric register values ranging {m['value_min']}–{m['value_max']} (preview: {m.get('values_preview')})."
            impl = ("Holding/input register contents represent live setpoints, sensor readings or "
                    "configuration words readable without authentication.")
        else:
            obs = f"Captured values: {m.get('values_preview')}." if m.get("values_preview") else "Data was returned."
            impl = "The register/coil area is readable over Modbus without authentication."
        sig = ("Modbus/TCP has no native authentication or encryption; readable process data enables "
               "reconnaissance and, where writable, manipulation of the physical process.")
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action == "scan_units":
        activity = f"Enumerated Modbus unit/slave IDs on {scope} over range {rec['inputs'].get('unit_start','?')}–{rec['inputs'].get('unit_end','?')}."
        obs = (f"Found {m.get('active_units', 0)} active unit(s)"
               + (f" (IDs: {m['unit_ids']})." if m.get("unit_ids") else "."))
        impl = ("Each active unit ID is an independently addressable PLC/slave behind the same endpoint, "
                "expanding the reachable attack surface.")
        sig = "Knowing live unit IDs lets an attacker target real devices directly rather than guessing."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action in ("scan_registers", "scan_register_range"):
        activity = f"Swept the {fn}address space on {scope} for accessible registers."
        span = (f" spanning {m['first_address']}–{m['last_address']}"
                if "first_address" in m and "last_address" in m else "")
        obs = f"Mapped {m.get('accessible_registers', 0)} accessible register(s){span}."
        impl = "Accessible registers reveal the device memory map and which areas respond to reads."
        sig = "A known-good register map accelerates targeted reads/writes against the process."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action == "write":
        activity = f"Wrote to {fn}address {m.get('address','?')} on {scope}."
        obs = "Write was accepted by the device." if m.get("write_ok") else "Write outcome was not confirmed."
        impl = "A successful write means the process variable can be altered remotely and unauthenticated."
        sig = "Unauthorized writes to a live PLC can directly affect physical process safety and integrity."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    return {}


def _interpret_opcua(rec, m) -> Dict[str, str]:
    action, scope = rec["action"], _scope(rec)
    if action == "discover":
        activity = f"Discovered OPC UA endpoints advertised by {scope}."
        obs = f"Server returned {m.get('endpoints', 0)} endpoint(s)" + \
              (f" with security modes {m['security_modes']}." if m.get("security_modes") else ".")
        impl = ("Endpoints advertising SecurityMode 'None' accept unauthenticated, unencrypted sessions; "
                "such an endpoint exposes the address space to anonymous clients.")
        sig = "An exposed/anonymous endpoint is the entry point for browsing and manipulating server nodes."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action in ("browse", "enumerate", "read_only", "write_only"):
        activity = f"{action.replace('_', ' ').title()} of the {scope} address space."
        if m.get("variables_found") == 0:
            obs = "No matching variables were returned."
        else:
            obs = f"Listed ~{m.get('variables_listed', 'multiple')} node(s)" + \
                  (" filtered to writable variables." if m.get("writable_view")
                   else " filtered to readable variables." if m.get("readable_view") else ".")
        impl = ("Enumerable nodes expose the server's data model — tags, types and access levels — to "
                "any client that completed a session.")
        sig = ("Writable nodes are especially sensitive: they map directly to controllable process points. "
               "Full enumeration is high-value reconnaissance.")
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action == "read":
        activity = f"Read a single OPC UA node ({m.get('read_node','?')}) on {scope}."
        obs = f"Current value: {m.get('read_value','(not captured)')}."
        impl = "The node value was readable, confirming live data exposure for that point."
        sig = "Confirms a concrete, addressable data point an attacker could monitor."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action == "write":
        activity = f"Wrote to OPC UA node {m.get('write_node','?')} on {scope}."
        obs = (f"Value set to {m.get('write_value')} (read-back: {m.get('write_readback')})."
               if m.get("write_node") else "Write outcome not confirmed.")
        impl = "A successful write proves the node is remotely controllable through the server."
        sig = "Writable nodes can change process behaviour; this is a direct integrity/safety risk."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    return {}


def _interpret_mqtt(rec, m) -> Dict[str, str]:
    action, scope = rec["action"], _scope(rec)
    if action == "broker_info":
        activity = f"Fingerprinted the MQTT broker at {scope} via $SYS/#."
        obs = f"Connected and collected {m.get('sys_messages', 0)} system message(s)." if m.get("connected") \
              else "Could not establish a session."
        impl = "$SYS data leaks broker software, version, uptime and client statistics to any subscriber."
        sig = "Broker metadata and open $SYS access indicate weak access control on the messaging fabric."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action == "check_auth":
        activity = f"Tested authentication on the MQTT broker at {scope}."
        obs = f"Broker {m.get('auth', 'response unclear')} the connection attempt."
        impl = ("'Accepted (anonymous)' means the broker allows unauthenticated clients to subscribe and "
                "publish.")
        sig = "An open broker lets anyone read telemetry and inject commands onto control topics."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action in ("enumerate", "subscribe"):
        activity = f"Subscribed to topics on {scope} (scope: {rec['inputs'].get('topic', '#')})."
        obs = _join([f"Observed {m['unique_topics']} unique topic(s)." if "unique_topics" in m else "",
                     f"Captured {m['received_messages']} message(s)." if "received_messages" in m else ""]) \
              or "No messages observed in the window."
        impl = "Visible topics and payloads reveal device names, telemetry and command channels in use."
        sig = "Topic/payload visibility maps the OT process and exposes channels suitable for injection."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action == "retained_dump":
        activity = f"Dumped retained messages from {scope}."
        obs = f"Retrieved {m.get('retained_messages', 0)} retained message(s)."
        impl = "Retained messages persist the last known state of each device, even without live traffic."
        sig = "Retained state gives an attacker an immediate snapshot of the process without waiting."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action == "publish":
        activity = f"Published a message to '{rec['inputs'].get('topic','?')}' on {scope}."
        obs = "Publish was accepted by the broker." if m.get("published") else "Publish not confirmed."
        impl = "Accepted publishes mean arbitrary clients can inject messages onto that topic."
        sig = "Command injection on control topics can directly drive actuators/process logic."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    return {}


def _interpret_s7comm(rec, m) -> Dict[str, str]:
    action, scope = rec["action"], _scope(rec)
    if action == "plc_info":
        activity = f"Fingerprinted the S7 PLC at {scope}."
        ident = _join([f"{m.get('module_type','')}", f"{m.get('module_name','')}",
                       f"firmware {m['firmware']}" if m.get("firmware") else "",
                       f"state {m['cpu_state']}" if m.get("cpu_state") else ""])
        obs = f"Identified: {ident or 'device responded'}." + \
              (f" Protection level {m['protection_level']} ({m.get('protection_desc','')})." if "protection_level" in m else "")
        impl = ("Module/firmware identity enables matching against known CVEs; protection level reveals "
                "whether read/write is gated.")
        if m.get("unauthenticated_access"):
            impl += " Protection level 0 means unauthenticated read/write is permitted."
        sig = "PLC fingerprinting drives exploit selection; weak/absent protection enables direct control."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action in ("db_list", "list_blocks"):
        activity = f"Enumerated program blocks/DBs on the S7 PLC at {scope}."
        obs = f"Found {m['data_blocks']} data block(s)." if "data_blocks" in m else "Block inventory returned."
        impl = "Block and DB inventory exposes the structure of the control program."
        sig = "Knowing DB layout guides targeted reads/writes of process data."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action in ("db_read", "area_read", "szl_read"):
        activity = f"Read PLC memory ({action}) on {scope}."
        obs = f"Decoded value: {m['read_value']}." if m.get("read_value") else "Memory contents returned."
        impl = "Readable DB/area memory exposes live process values and configuration."
        sig = "Direct memory read confirms unauthenticated data exposure on the controller."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action in ("db_write", "area_write"):
        activity = f"Wrote PLC memory ({action}) on {scope}."
        obs = "Write accepted by the PLC." if m.get("write_ok") else "Write not confirmed."
        impl = "Writing DB/area memory alters control logic inputs/outputs."
        sig = "Unauthorized PLC writes can manipulate the physical process — a critical safety risk."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    return {}


def _interpret_ethernetip(rec, m) -> Dict[str, str]:
    action, scope = rec["action"], _scope(rec)
    if action == "discover":
        activity = f"Broadcast a CIP ListIdentity discovery from {scope}."
        obs = f"Discovered {m.get('devices', 0)} EtherNet/IP device(s) on the subnet."
        impl = "Discovery reveals all CIP-speaking devices, their vendors and product types on the segment."
        sig = "An inventory of reachable controllers is the first step in targeting OT assets."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action == "device_info":
        activity = f"Read the CIP Identity object of {scope}."
        ident = _join([m.get("vendor", ""), m.get("product_name", ""),
                       f"rev {m['revision']}" if m.get("revision") else ""])
        obs = f"Identity: {ident or 'device responded'}."
        impl = "Vendor/product/revision enables CVE matching and exploit selection for that controller."
        sig = "Precise device fingerprinting narrows the path to a working exploit."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action == "list_tags":
        activity = f"Enumerated controller tags on {scope}."
        obs = f"Listed {m['tags_listed']} tag(s)." if "tags_listed" in m else "Tag list returned."
        impl = "The tag namespace is effectively the controller's full memory map and variable layout."
        sig = "Tag enumeration is high-value recon enabling precise targeted reads/writes."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action == "read_tag":
        activity = f"Read named tag(s) on {scope}."
        obs = f"Read {m['tags_read']} tag(s) successfully." if "tags_read" in m else "Tag value(s) returned."
        impl = "Readable tags expose live process variables by name without authentication."
        sig = "Confirms concrete controllable/observable process points on the PLC."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    if action == "write_tag":
        activity = f"Wrote tag '{m.get('write_tag','?')}' on {scope}."
        obs = f"Set to {m.get('write_value')}." if m.get("write_tag") else "Write not confirmed."
        impl = "A successful tag write proves the variable is remotely controllable."
        sig = "Writing live tags can drive actuators and alter the process — a direct safety risk."
        return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}
    return {}


def _interpret_scan(rec, m) -> Dict[str, str]:
    scope = rec["target"]
    activity = f"Performed a network port scan against {scope}."
    if m.get("open_ports"):
        svc = f" Services: {', '.join(m['services'])}." if m.get("services") else ""
        obs = f"Found {m['open_count']} open port(s): {m['open_ports']}.{svc}"
        impl = ("Each open port is a reachable service; ICS protocol ports (e.g. 502 Modbus, 102 S7, "
                "44818/2222 EtherNet/IP, 4840 OPC UA, 1883/8883 MQTT) indicate exposed control interfaces.")
        sig = ("Exposure of OT service ports to the scanning host shows insufficient network segmentation — "
               "these services should not be reachable from general networks.")
    else:
        obs = "No open ports were parsed from the scan output."
        impl = "No reachable services were confirmed for this target in the captured output."
        sig = "Absence of exposed ports is the desired state for segmented OT assets."
    return {"activity": activity, "observation": obs, "implication": impl, "significance": sig}


_INTERPRETERS = {
    "modbus": _interpret_modbus,
    "opcua": _interpret_opcua,
    "mqtt": _interpret_mqtt,
    "s7comm": _interpret_s7comm,
    "ethernetip": _interpret_ethernetip,
    "enip": _interpret_ethernetip,
    "scan": _interpret_scan,
}


def _generic_interpretation(rec) -> Dict[str, str]:
    """Fallback interpretation for any controller without a specific builder."""
    outcome = rec["result"]["success_guess"]
    scope = _scope(rec)
    activity = f"Performed '{rec['action']}' via the {rec['controller']} controller against {scope}."
    observation = {
        "success": "The operation completed and the device returned data.",
        "failure": "The operation did not complete; errors or timeouts were observed.",
        "unknown": "The outcome was inconclusive from the captured output.",
    }[outcome]
    implication = ("The target responded to the request over an OT/industrial protocol, confirming the "
                   "service is reachable and interacting as expected.")
    significance = ("Reachable industrial services without strong authentication/segmentation are a "
                    "recurring ICS risk and warrant review.")
    return {"activity": activity, "observation": observation,
            "implication": implication, "significance": significance}


def _enrich_and_interpret(rec: Dict[str, Any], full_output: str) -> None:
    """Attach metrics, evidence and a 4-part interpretation to a record in place."""
    controller = rec["controller"]
    enricher = _ENRICHERS.get(controller)
    metrics = enricher(rec, full_output) if enricher else {}
    metrics = {k: v for k, v in metrics.items() if v not in (None, "", [], {})}

    interp = {}
    builder = _INTERPRETERS.get(controller)
    if builder:
        try:
            interp = builder(rec, metrics) or {}
        except Exception:
            interp = {}
    # Fill any missing section from the generic interpretation.
    base = _generic_interpretation(rec)
    interp = {**base, **{k: v for k, v in interp.items() if v}}

    rec["metrics"] = metrics
    rec["evidence"] = _evidence_lines(full_output)
    rec["interpretation"] = interp


# =========================
# Hybrid mitigation engine
# =========================
# This is the deterministic "code = source of truth" half of the hybrid model.
# Pipeline:  findings  ->  signals (cross-finding aware)  ->  scored mitigations.
# The LLM later only writes prose around the ranked output below; it never
# selects, adds or relabels mitigations.

# Service / protocol classification helpers.
_ICS_SERVICES = {
    "modbus": ("modbus", 502), "s7comm": ("s7comm", 102), "s7": ("s7comm", 102),
    "opcua": ("opcua", 4840), "mqtt": ("mqtt", 1883),
    "ethernetip": ("ethernet/ip", 44818), "enip": ("ethernet/ip", 44818),
    "dnp3": ("dnp3", 20000), "bacnet": ("bacnet", 47808),
}
_REMOTE_ADMIN = ("rdp", "vnc", "ssh", "telnet", "snmp")
# ICS protocols that are unencrypted by design (plaintext on the wire).
_PLAINTEXT_ICS = {"modbus", "s7comm", "ethernet/ip", "dnp3", "bacnet"}

_WRITE_ACTIONS  = {"write", "db_write", "area_write", "write_tag", "write_only", "publish"}
_READ_ACTIONS   = {"read", "db_read", "area_read", "read_tag", "read_only"}
_ENUM_ACTIONS   = {"enumerate", "scan_units", "scan_registers", "scan_register_range",
                   "list_tags", "list_blocks", "db_list", "browse", "subscribe",
                   "retained_dump", "check_auth"}
_DISCO_ACTIONS  = {"discover", "device_info", "plc_info", "broker_info", "scan",
                   "szl_read", "fingerprint"}


def _posture(action: str) -> str:
    if action in _WRITE_ACTIONS:  return "write"
    if action in _READ_ACTIONS:   return "read"
    if action in _ENUM_ACTIONS:   return "enumerate"
    if action in _DISCO_ACTIONS:  return "discover"
    return "interact"


def _is_validated(rec: Dict[str, Any]) -> bool:
    """Validated = real protocol interaction returned data, not just exposure."""
    if rec["result"]["success_guess"] == "success":
        return True
    m = rec.get("metrics", {})
    concrete = ("values_count", "active_units", "accessible_registers", "endpoints",
                "variables_listed", "tags_listed", "tags_read", "devices",
                "read_value", "read_node", "write_ok", "write_node", "write_tag",
                "published", "data_blocks", "sys_messages", "unique_topics",
                "retained_messages", "received_messages", "module_type")
    return any(k in m for k in concrete)


def _write_succeeded(rec: Dict[str, Any]) -> bool:
    m = rec.get("metrics", {})
    return _posture(rec["action"]) == "write" and bool(
        m.get("write_ok") or m.get("write_node") or m.get("write_tag") or m.get("published")
    )


def _enum_breadth(rec: Dict[str, Any]) -> int:
    m = rec.get("metrics", {})
    return max([0] + [int(m[k]) for k in
                      ("accessible_registers", "active_units", "variables_listed",
                       "tags_listed", "unique_topics", "devices", "values_count")
                      if isinstance(m.get(k), int)])


def _security_props(rec: Dict[str, Any]) -> List[str]:
    """Protocol-specific weak-posture signals parsed from the activity."""
    m, c, props = rec.get("metrics", {}), rec["controller"], []
    if m.get("unauthenticated_access") or m.get("protection_level") == 0:
        props.append("no_device_protection")
    if isinstance(m.get("security_modes"), list) and "None" in m["security_modes"]:
        props.append("security_mode_none")
    if str(m.get("auth", "")).startswith("accepted"):
        props.append("anonymous_auth_accepted")
    # Plaintext unless TLS was explicitly used (MQTT) or a secure OPC UA mode is present.
    svc = _ICS_SERVICES.get(c, (c, None))[0]
    if c == "mqtt" and str(rec.get("inputs", {}).get("tls", "")).lower() != "true":
        props.append("plaintext_protocol")
    elif svc in _PLAINTEXT_ICS:
        props.append("plaintext_protocol")
    elif c == "opcua" and "security_mode_none" in props:
        props.append("plaintext_protocol")
    return props


def _build_findings(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalized cross-controller finding model used by the signal/scoring layers."""
    findings: List[Dict[str, Any]] = []
    fid = 0
    for r in records:
        fid += 1
        controller = r["controller"]
        svc = _ICS_SERVICES.get(controller, (controller, None))[0]
        validated = _is_validated(r)
        f = {
            "id": f"F{fid}",
            "controller": controller,
            "target": r["target"],
            "action": r["action"],
            "service": svc,
            "port": r.get("port"),
            "posture": _posture(r["action"]),
            "validated": validated,
            "exposure_type": "validated_interaction" if validated else "exposure_only",
            "write_succeeded": _write_succeeded(r),
            "enum_breadth": _enum_breadth(r),
            "security_props": _security_props(r),
            "counts": {k: v for k, v in r.get("metrics", {}).items() if isinstance(v, (int, list))},
            "evidence": (r.get("interpretation", {}).get("observation") or "")[:240],
            "ts": r.get("ts"),
            "is_ics": controller in _ICS_SERVICES or svc in _PLAINTEXT_ICS or svc == "opcua",
        }
        findings.append(f)

        # A scan expands into one service-exposure finding per discovered open port,
        # so concentration/repetition correlations work across protocols too.
        if controller == "scan":
            f["is_ics"] = False
            for host, buckets in (r.get("scan_facts") or {}).items():
                for s in buckets.get("open", []):
                    fid += 1
                    name = (s.get("service") or "unknown").lower()
                    is_ics = any(k in name for k in _ICS_SERVICES) or s.get("port") in {502, 102, 44818, 4840, 1883, 20000, 47808}
                    is_admin = any(k in name for k in _REMOTE_ADMIN)
                    findings.append({
                        "id": f"F{fid}", "controller": "scan", "target": host,
                        "action": "port_exposure", "service": name, "port": s.get("port"),
                        "posture": "discover", "validated": False,
                        "exposure_type": "exposure_only", "write_succeeded": False,
                        "enum_breadth": 0, "security_props": [],
                        "counts": {}, "evidence": f"Open {host}:{s.get('port')} ({name})",
                        "ts": r.get("ts"), "is_ics": is_ics, "is_remote_admin": is_admin,
                    })
    return findings


# ---- Signal layer (explicit, inspectable) ------------------------------------
def _derive_signals(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Turn findings into explicit security signals, including cross-finding
    correlations (concentration on a host, repetition across hosts).
    Each signal: {signal, targets, findings, magnitude, detail}.
    """
    signals: List[Dict[str, Any]] = []

    def emit(name, fs, detail=""):
        fs = list(fs)
        if not fs:
            return
        signals.append({
            "signal": name,
            "targets": sorted({f["target"] for f in fs}),
            "findings": [f["id"] for f in fs],
            "magnitude": len({f["target"] for f in fs}),
            "detail": detail,
        })

    emit("ics_protocol_exposed", [f for f in findings if f.get("is_ics")],
         "ICS protocol services are reachable.")
    emit("remote_admin_exposed", [f for f in findings if f.get("is_remote_admin")],
         "Remote administration services are reachable.")
    emit("validated_protocol_interaction",
         [f for f in findings if f["validated"] and f["controller"] != "scan"],
         "Protocol interaction succeeded (beyond mere visibility).")
    emit("write_capable_interaction", [f for f in findings if f["write_succeeded"]],
         "Write/command operations were accepted by a device.")
    emit("broad_enumeration",
         [f for f in findings if f["posture"] == "enumerate" and f["validated"] and f["enum_breadth"] >= 5],
         "Large-scale enumeration of resources succeeded.")
    emit("plaintext_protocol",
         [f for f in findings if "plaintext_protocol" in f["security_props"]],
         "Unencrypted protocols carry control data.")
    emit("weak_protocol_posture",
         [f for f in findings if any(p in f["security_props"]
                                     for p in ("no_device_protection", "security_mode_none", "anonymous_auth_accepted"))],
         "Weak or absent authentication posture observed.")
    emit("broad_network_access",
         [f for f in findings if f["posture"] in ("enumerate", "discover") and (f["validated"] or f["controller"] == "scan")],
         "Broad access to resources over the network.")

    # Concentration: multiple distinct risky services on a single host.
    by_host: Dict[str, set] = defaultdict(set)
    host_findings: Dict[str, list] = defaultdict(list)
    for f in findings:
        if f.get("is_ics") or f.get("is_remote_admin"):
            by_host[f["target"]].add((f["service"], f["port"]))
            host_findings[f["target"]].append(f)
    for host, svcs in by_host.items():
        if len(svcs) >= 2:
            emit("multiple_risky_services_on_host", host_findings[host],
                 f"{host} exposes {len(svcs)} distinct risky services.")

    # Repetition: the same service exposed/validated across >= 2 hosts.
    by_service: Dict[str, list] = defaultdict(list)
    for f in findings:
        if f.get("is_ics") or f.get("is_remote_admin"):
            by_service[f["service"]].append(f)
    for svc, fs in by_service.items():
        if len({f["target"] for f in fs}) >= 2:
            emit("repeated_across_targets", fs,
                 f"'{svc}' is exposed on multiple hosts.")

    # Confidence: findings with no validation and tiny/empty evidence.
    emit("limited_evidence_low_confidence",
         [f for f in findings if not f["validated"] and f["controller"] != "scan" and not f["counts"]],
         "Some findings rest on limited evidence.")

    return signals


# ---- Scored mitigation engine -------------------------------------------------
# Each signal contributes weighted scores to one or more MITRE ICS mitigations,
# plus a short machine-readable reason. Breadth (number of affected hosts) scales
# the contribution. This is the authoritative selection — LLM cannot override it.
_SIGNAL_RULES = {
    "ics_protocol_exposed":        {"M0930": 2.0, "M0937": 2.0, "M0935": 1.5,
                                    "_reason": "ICS protocol exposed on the network"},
    "remote_admin_exposed":        {"M0937": 2.0, "M0930": 1.5, "M0800": 1.5, "M0935": 1.5,
                                    "_reason": "Remote administration service exposed"},
    "validated_protocol_interaction": {"M0935": 2.0, "M0807": 1.5, "M0800": 1.5, "M0813": 1.5,
                                    "_reason": "Validated protocol interaction (not just exposure)"},
    "write_capable_interaction":   {"M0800": 3.0, "M0801": 2.5, "M0802": 2.0, "M0813": 2.0, "M0935": 2.0,
                                    "_reason": "Write/command operation accepted by a device"},
    "broad_enumeration":           {"M0807": 2.5, "M0935": 2.0, "M0937": 1.5, "M0930": 1.0,
                                    "_reason": "Broad enumeration of resources succeeded"},
    "multiple_risky_services_on_host": {"M0930": 3.0, "M0937": 2.5, "M0935": 1.5,
                                    "_reason": "Multiple risky services concentrated on one host"},
    "repeated_across_targets":     {"M0930": 2.0, "M0937": 2.0, "M0807": 1.5,
                                    "_reason": "Same exposure repeated across multiple hosts"},
    "plaintext_protocol":          {"M0808": 3.0, "M0802": 2.0, "M0931": 1.0,
                                    "_reason": "Plaintext (unencrypted) control protocol in use"},
    "weak_protocol_posture":       {"M0800": 2.5, "M0801": 2.0, "M0813": 2.0, "M0802": 1.5,
                                    "_reason": "Weak/absent authentication posture"},
    "broad_network_access":        {"M0935": 2.0, "M0807": 1.5, "M0930": 1.5, "M0814": 1.0,
                                    "_reason": "Broad access to resources over the network"},
}


def _priority(score: float) -> str:
    if score >= 9.0:  return "critical"
    if score >= 5.5:  return "high"
    if score >= 2.5:  return "medium"
    return "low"


def _score_mitigations(signals: List[Dict[str, Any]], findings_count: int) -> List[Dict[str, Any]]:
    """Aggregate signal weights into ranked, evidence-backed MITRE mitigation objects."""
    acc: Dict[str, Dict[str, Any]] = {}
    low_confidence = any(s["signal"] == "limited_evidence_low_confidence" for s in signals)

    for sig in signals:
        rule = _SIGNAL_RULES.get(sig["signal"])
        if not rule:
            continue
        # Breadth scaling: more affected hosts => stronger contribution (capped).
        scale = min(1.0 + 0.25 * (sig["magnitude"] - 1), 2.0)
        reason = rule["_reason"]
        for mid, weight in rule.items():
            if mid == "_reason":
                continue
            slot = acc.setdefault(mid, {
                **_MITRE[mid], "score": 0.0, "reasons": [],
                "supporting_targets": set(), "supporting_findings": set(),
            })
            slot["score"] += weight * scale
            if reason not in slot["reasons"]:
                slot["reasons"].append(reason)
            slot["supporting_targets"].update(sig["targets"])
            slot["supporting_findings"].update(sig["findings"])

    mitigations = []
    for mid, slot in acc.items():
        score = slot["score"] * (0.85 if low_confidence else 1.0)
        targets = sorted(slot["supporting_targets"])
        reasons = slot["reasons"]
        rationale_seed = (
            f"Recommended because: {'; '.join(reasons[:3])}. "
            f"Supported by {len(slot['supporting_findings'])} finding(s) across "
            f"{len(targets)} target(s)."
        )
        mitigations.append({
            "id": slot["id"], "name": slot["name"], "url": slot["url"],
            "score": round(score, 2), "priority": _priority(score),
            "reasons": reasons,
            "supporting_targets": targets,
            "supporting_findings": sorted(slot["supporting_findings"]),
            "rationale_seed": rationale_seed,
        })

    mitigations.sort(key=lambda m: (-m["score"], m["id"]))
    return mitigations[:12]


# =========================
# Universal dataset builder
# =========================
def _build_dataset(records: List[Dict[str, Any]], title: str, audience: str) -> Dict[str, Any]:
    """
    Assemble the universal, model-safe dataset from normalized activity records:
    metadata, rollup, activities, grouped-by-target/controller, plus the
    deterministic findings -> signals -> ranked MITRE mitigations chain.
    """
    controllers = sorted({r["controller"] for r in records})
    targets     = sorted({r["target"] for r in records})
    ports       = sorted({r["port"] for r in records if r["port"] is not None})
    success_counts = Counter(r["result"]["success_guess"] for r in records)

    by_target: Dict[str, list] = defaultdict(list)
    by_controller: Dict[str, list] = defaultdict(list)
    for r in records:
        by_target[r["target"]].append(r)
        by_controller[r["controller"]].append(r)

    # Hybrid mitigation chain (deterministic, authoritative).
    findings    = _build_findings(records)
    signals     = _derive_signals(findings)
    mitigations = _score_mitigations(signals, len(findings))

    return {
        "metadata": {
            "title": title,
            "audience": audience,
            "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
            "activities_count": len(records),
            "findings_count": len(findings),
        },
        "rollup": {
            "controllers": controllers,
            "targets": targets,
            "ports": ports,
            "success_counts": dict(success_counts),
            "signals": sorted({s["signal"] for s in signals}),
        },
        "activities": records,
        "by_target": {t: recs for t, recs in by_target.items()},
        "by_controller": {c: recs for c, recs in by_controller.items()},
        "findings": findings,
        "signals": signals,
        "ranked_mitigations": mitigations,
        "notes": "Facts only; derived from the inbox. Do not invent findings. "
                 "'ranked_mitigations' is the authoritative, code-selected MITRE list — "
                 "explain it; do not add, drop or relabel mitigations.",
    }


def _executive_view(record: Dict[str, Any]) -> Dict[str, Any]:
    """Trim a technical activity record down to high-level facts for executives."""
    interp = record.get("interpretation", {})
    return {
        "controller": record["controller"],
        "action": record["action"],
        "target": record["target"],
        "port": record["port"],
        "outcome": record["result"]["success_guess"],
        "summary": interp.get("activity"),
        "why_it_matters": interp.get("significance"),
    }


# =========================
# Technical appendix (deterministic — built in Python, not by the model)
# =========================
def _fmt_inputs(inputs: Dict[str, Any]) -> str:
    """Render the most useful (already-sanitized) inputs compactly."""
    skip = {"protocol"}
    parts = [f"{k}={v}" for k, v in inputs.items()
             if k not in skip and v not in (None, "", [], {})]
    return ", ".join(parts[:12]) if parts else "(none)"


def _fmt_metrics(metrics: Dict[str, Any]) -> str:
    """Render parsed result counts/ranges/values compactly."""
    if not metrics:
        return "(no structured metrics parsed)"
    return ", ".join(f"{k}={v}" for k, v in metrics.items())


def _render_mitigation_basis(mitigations: List[Dict[str, Any]]) -> List[str]:
    """Deterministic, authoritative mitigation-selection table for the appendix."""
    if not mitigations:
        return []
    lines = ["### Mitigation Basis (deterministic MITRE ATT&CK for ICS selection)", "",
             "This is the code-computed, authoritative ranking. The narrative above explains it.", ""]
    for m in mitigations:
        lines.append(f"- **{m['id']} {m['name']}** — priority **{m['priority']}** (score {m['score']})")
        lines.append(f"  - Reasons: {'; '.join(m['reasons'])}")
        if m["supporting_targets"]:
            lines.append(f"  - Supporting targets: {', '.join(m['supporting_targets'])}")
        if m["supporting_findings"]:
            lines.append(f"  - Supporting findings: {', '.join(m['supporting_findings'])}")
        lines.append(f"  - Reference: {m['url']}")
    lines.append("")
    return lines


def _render_technical_appendix(records: List[Dict[str, Any]],
                               mitigations: List[Dict[str, Any]] = None,
                               signals: List[Dict[str, Any]] = None) -> str:
    """
    Structured supporting results per activity — compact, not a raw dump.
    Includes action, target, timestamp, key inputs, parsed counts/ranges/values,
    a short evidence excerpt, and the deterministic mitigation-selection basis.
    """
    lines = ["", "---", "", "## Technical Appendix — Supporting Results", "",
             "Structured per-activity evidence captured during testing. "
             "Sensitive inputs are redacted; output is excerpted, not dumped.", ""]
    for i, r in enumerate(records, 1):
        scope = r["target"] + (f":{r['port']}" if r.get("port") else "")
        interp = r.get("interpretation", {})
        lines.append(f"### A{i}. {r['controller']} — {r['action']} @ {scope}")
        lines.append(f"- **Time (UTC):** {r.get('ts', 'n/a')}")
        lines.append(f"- **Outcome:** {r['result']['success_guess']} "
                     f"(output {r['result']['output_size']} chars)")
        lines.append(f"- **Key inputs:** {_fmt_inputs(r.get('inputs', {}))}")
        lines.append(f"- **Parsed results:** {_fmt_metrics(r.get('metrics', {}))}")
        if interp.get("observation"):
            lines.append(f"- **Observation:** {interp['observation']}")
        if interp.get("implication"):
            lines.append(f"- **Technical meaning:** {interp['implication']}")
        evidence = r.get("evidence") or []
        if evidence:
            lines.append("- **Evidence excerpt:**")
            lines.append("")
            lines.append("  ```")
            lines.extend(f"  {e}" for e in evidence)
            lines.append("  ```")
        lines.append("")

    # Derived risk signals (deterministic), then the authoritative mitigation basis.
    if signals:
        lines.append("### Derived Risk Signals")
        lines.append("")
        for s in signals:
            tgts = f" — targets: {', '.join(s['targets'])}" if s.get("targets") else ""
            lines.append(f"- **{s['signal']}** ({s['magnitude']} host(s)): {s['detail']}{tgts}")
        lines.append("")
    lines.extend(_render_mitigation_basis(mitigations or []))
    return "\n".join(lines)


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
# Report generation
# =========================
def generate_report(audience: str, title: str, model: str) -> Tuple[str, int]:
    """
    Build a universal normalized dataset from the inbox and ask the model to
    write a technical or executive report from it.

    Returns (markdown, items_used_count).
    """
    items = get_report_items()
    if not items:
        return ("", 0)

    audience = (audience or "technical").lower()
    title = title or "ICS/OT Security Test Report"
    model = model or "gpt-4o-mini"

    MAX_ITEMS = 100
    raw_items = items[-MAX_ITEMS:]
    records = [_normalize_item(it) for it in raw_items]
    used = len(records)

    dataset = _build_dataset(records, title, audience)

    # The ranked mitigations are the authoritative, code-selected MITRE list shared
    # by both audiences. The LLM explains them; it must not alter the selection.
    mitigation_rule = (
        "MITIGATION RULES (strict): 'ranked_mitigations' is the authoritative, code-computed "
        "MITRE ATT&CK for ICS selection. You MUST use exactly these mitigations — do NOT add, "
        "remove, merge, reorder by your own judgement, or change any id/name/url. Present them in "
        "the given order (already ranked by score/priority). For each, write polished rationale "
        "from its 'reasons', 'rationale_seed', 'priority' and 'supporting_targets'. Do NOT invent "
        "findings or mitigations beyond the provided data."
    )

    if audience == "executive":
        # Executives get high-level facts only — no inputs, excerpts or raw output.
        exec_mitigations = [
            {"id": m["id"], "name": m["name"], "url": m["url"], "priority": m["priority"],
             "reasons": m["reasons"], "supporting_targets": m["supporting_targets"]}
            for m in dataset["ranked_mitigations"]
        ]
        exec_dataset = {
            "metadata": dataset["metadata"],
            "rollup": dataset["rollup"],
            "activities": [_executive_view(r) for r in records],
            "by_target": {t: [_executive_view(r) for r in recs]
                          for t, recs in dataset["by_target"].items()},
            "ranked_mitigations": exec_mitigations,
            "notes": dataset["notes"],
        }
        payload = json.dumps(exec_dataset, ensure_ascii=False, indent=2)

        system_msg = (
            "You are a senior ICS/OT penetration tester writing an executive-level report "
            "for non-technical stakeholders. Use ONLY the provided dataset. Do NOT invent "
            "vulnerabilities or details. Do NOT include command lines or raw output."
        )
        guidance = (
            "Audience: Executive\n"
            "Write a concise, business-oriented narrative with these sections:\n"
            "1) Scope & Approach – high-level scope (targets and controllers exercised).\n"
            "2) Activities Performed – summarize per controller; no commands.\n"
            "3) Key Findings – high-level discoveries across targets, framed by outcome counts "
            "   and the derived 'rollup.signals' (e.g., validated access, write-capable, repeated "
            "   exposure) in plain business language.\n"
            "4) Recommended Mitigations – present ONLY here, from 'ranked_mitigations' in order. "
            "   Group/describe them by 'priority' and give a one-line business rationale each.\n"
            "5) 30/60/90-Day Plan – prioritized steps driven by mitigation priority.\n"
            f"{mitigation_rule}\n"
            "Constraints: no raw evidence; no per-activity mitigation lists."
        )
    else:
        payload = json.dumps(dataset, ensure_ascii=False, indent=2)
        system_msg = (
            "You are a senior ICS/OT penetration tester producing a structured technical report. "
            "Use ONLY the provided dataset, which contains normalized activity records, derived "
            "security 'signals', normalized 'findings', and a code-ranked MITRE mitigation list. "
            "Sensitive inputs are already redacted. Do NOT reproduce raw command dumps verbatim."
        )
        guidance = (
            "Audience: Technical\n"
            "Each activity carries an 'interpretation' {activity, observation, implication, "
            "significance} and 'metrics'. The dataset also includes 'signals' (derived, "
            "evidence-linked security signals) and 'ranked_mitigations' (the authoritative MITRE "
            "selection with scores/priority/reasons/supporting evidence).\n"
            "Write a clear report with:\n"
            "1) Overview – context: controllers used, targets, outcome rollup, and which 'signals' fired.\n"
            "2) Exposure by Target – for each target in 'by_target', walk its activities using their "
            "   interpretation + metrics; include scan_facts open services when present.\n"
            "3) Controller Activity – for each controller in 'by_controller', explain actions and "
            "   findings, citing concrete metrics and the implication/significance for each.\n"
            "4) Risk Signals – briefly explain the derived 'signals' and what evidence drove them "
            "   (cross-host repetition, concentration, validated/write access, plaintext, etc.).\n"
            "5) Consolidated Mitigations – ONLY here, from 'ranked_mitigations' in order. For each: "
            "   id + name + priority + score, a rationale built from its 'reasons'/'rationale_seed', "
            "   and the 'supporting_targets'/'supporting_findings' that justify it.\n"
            f"{mitigation_rule}\n"
            "Do NOT write a 'Technical Appendix' section yourself — one is appended automatically. "
            "Constraints: no raw command dumps; no per-activity mitigation lists elsewhere."
        )

    client = _get_openai_client()
    resp = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_msg},
            {"role": "user", "content":
                f"# {title}\nUse the following data.\n\n{guidance}\n\n"
                f"=== BEGIN DATA ===\n{payload}\n=== END DATA ===\n"
            },
        ],
        temperature=0.2,
    )
    md = resp.choices[0].message.content.strip()

    # Technical reports get a deterministic, structured supporting-evidence appendix
    # plus the authoritative mitigation-selection basis.
    if audience != "executive":
        md += "\n" + _render_technical_appendix(
            records, dataset["ranked_mitigations"], dataset["signals"])

    return (md, used)
