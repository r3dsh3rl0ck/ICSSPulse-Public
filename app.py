import subprocess
import shlex
from flask import Flask, render_template, request, jsonify, redirect, url_for
from ansi2html import Ansi2HTMLConverter
import os
from pathlib import Path
from dotenv import load_dotenv
from  report_gen import add_to_report, get_report_items, clear_report_items, generate_report
import tempfile
from ethernetip_handler import handle_ethernetip

env_path = Path(__file__).with_name('f.env')
load_dotenv(dotenv_path=env_path)

api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise RuntimeError("OPENAI_API_KEY not set (check your .env or environment)")

# Modbus handler
try:
    from modbus_handler import handle_modbus
except ImportError:
    def handle_modbus(args):
        return f"--- DUMMY MODBUS HANDLER ---\nTarget: {args.target}:{args.port}"


# OPC UA handler
try:
    from opcua_handler import handle_opcua
except ImportError:
    def handle_opcua(args):
        return f"--- DUMMY OPC UA HANDLER ---\nTarget: {args.target}:{args.port}"
    
try:
    from s7comm_handler import handle_s7comm
except ImportError:
    def handle_opcua(args):
        return f"--- DUMMY s7comm HANDLER ---\nTarget: {args.target}:{args.port}"
    
try:
    from mqtt_handler import handle_mqtt
except ImportError:
    def handle_modbus(args):
        return f"--- DUMMY MQTT HANDLER ---\nTarget: {args.target}:{args.port}"


app = Flask(__name__)


# -------------------------
# Home
# -------------------------
@app.route('/')
def home():
    return render_template('index.html')


# -------------------------
# Modbus
# -------------------------
@app.route('/modbus', methods=['GET', 'POST'])
def modbus_page():
    output = ''
    form_values = {}
    if request.method == 'POST':
        form_values = request.form


        class Args:
            def __init__(self):
                self.protocol = form_values.get('protocol')
                self.action = form_values.get('action')
                self.target = form_values.get('target')
                self.port = int(form_values.get('port', 502))
                self.unit_id = int(form_values.get('unit_id', 1))
                self.address = int(form_values.get('address')) if form_values.get('address') else None
                self.count = int(form_values.get('count', 1))
                self.value = int(form_values.get('value')) if form_values.get('value') else None
                self.function = form_values.get('function')
                self.timeout = int(form_values.get('timeout', 3))
                self.retries = int(form_values.get('retries', 3))
                # NEW: Scan-specific parameters
                self.unit_start = int(form_values.get('unit_start', 1))
                self.unit_end = int(form_values.get('unit_end', 10))


        args = Args()
        if args.protocol == 'modbus':
            output = handle_modbus(args)

    return render_template('modbus.html', output=output, values=form_values)

@app.route('/s7comm', methods=['GET', 'POST'])
def s7comm_page():
    output      = ''
    form_values = {}

    if request.method == 'POST':
        form_values = request.form.to_dict()

        class Args:
            def __init__(self):
                self.action    = form_values.get('action', 'plc_info')
                self.target    = form_values.get('target', '')
                self.port      = int(form_values.get('port', 102))
                self.rack      = int(form_values.get('rack', 0))
                self.slot      = int(form_values.get('slot', 1))
                self.timeout   = int(form_values.get('timeout', 5))
                self.retries   = int(form_values.get('retries', 2))
                self.db_number = form_values.get('db_number', '1')
                self.start     = int(form_values.get('start', 0))
                self.size      = int(form_values.get('size', 64))
                self.data_type = form_values.get('data_type', 'RAW')
                self.value     = form_values.get('value', '')
                self.area      = form_values.get('area', 'M')
                self.max_dbs   = int(form_values.get('max_dbs', 100))
                self.szl_id    = form_values.get('szl_id', '')

        output = handle_s7comm(Args())

    return render_template('s7comm.html', output=output, values=form_values)

# -------------------------
# MQTT Controller
# -------------------------
@app.route('/mqtt', methods=['GET', 'POST'])
def mqtt_page():
    output      = ''
    form_values = {}

    if request.method == 'POST':
        form_values = request.form.to_dict()

        class Args:
            def __init__(self):
                self.action       = form_values.get('action', 'broker_info')
                self.target       = form_values.get('target', '')
                self.port         = int(form_values.get('port', 1883))
                self.username     = form_values.get('username', '')
                self.password     = form_values.get('password', '')
                self.tls          = form_values.get('tls', 'false') == 'true'
                self.client_id    = form_values.get('client_id', '')
                self.topic        = form_values.get('topic', '#')
                self.payload      = form_values.get('payload', '')
                self.qos          = int(form_values.get('qos', 0))
                self.retain       = form_values.get('retain', 'false')
                self.timeout      = int(form_values.get('timeout', 10))
                self.max_messages = int(form_values.get('max_messages', 200))

        output = handle_mqtt(Args())

    return render_template('mqtt.html', output=output, values=form_values)

# -------------------------
# EtherNet/IP
# -------------------------

@app.route('/ethernetip', methods=['GET', 'POST'])
def ethernetip_page():
    output      = ''
    form_values = {}

    if request.method == 'POST':
        form_values = request.form.to_dict()

        class Args:
            def __init__(self):
                self.action   = form_values.get('action', 'device_info')
                self.target   = form_values.get('target', '')
                self.slot     = form_values.get('slot', '0')
                self.tag_name = form_values.get('tag_name', '')
                self.value    = form_values.get('value', '')
                self.max_tags = int(form_values.get('max_tags', 200))

        output = handle_ethernetip(Args())

    return render_template('ethernetip.html', output=output, values=form_values)

# -------------------------
# OPC UA
# -------------------------

# ── Persistent certificate storage ───────────────────────────────────────────
# Files live here across every request until the user explicitly removes them.
CERT_DIR  = os.path.join(os.path.dirname(__file__), 'opcua_certs')
CERT_FILE = os.path.join(CERT_DIR, 'client_cert.der')
KEY_FILE  = os.path.join(CERT_DIR, 'client_key.pem')
os.makedirs(CERT_DIR, exist_ok=True)


# ── Helper ────────────────────────────────────────────────────────────────────
def _cert_status():
    """Return (cert_exists, key_exists, cert_size_kb, key_size_kb)."""
    def _info(path):
        if os.path.exists(path):
            return True, round(os.path.getsize(path) / 1024, 1)
        return False, 0
    ce, cs = _info(CERT_FILE)
    ke, ks = _info(KEY_FILE)
    return ce, ke, cs, ks


# ── Main OPC UA page ──────────────────────────────────────────────────────────
@app.route('/opcua', methods=['GET', 'POST'])
def opcua_page():
    output      = ''
    form_values = {}

    if request.method == 'POST':
        form_values = request.form.to_dict()

        class Args:
            def __init__(self):
                self.protocol      = form_values.get('protocol')
                self.action        = form_values.get('action')
                self.target        = form_values.get('target')
                self.port          = int(form_values.get('port', 4840))
                self.endpoint_path = form_values.get('endpoint_path', 'freeopcua/server/')
                self.username      = form_values.get('username', '') or None
                self.password      = form_values.get('password', '') or None
                self.nodeid        = form_values.get('nodeid')
                self.value         = form_values.get('value')
                self.max_depth     = int(form_values.get('max_depth', 3))
                self.max_nodes     = int(form_values.get('max_nodes', 200))
                self.namespace     = form_values.get('namespace')
                self.timeout       = int(form_values.get('timeout', 3))
                self.retries       = int(form_values.get('retries', 3))
                self.security_mode = int(form_values.get('security_mode', 0) or 0)
                self.app_uri       = form_values.get('app_uri', 'urn:ctf:python-opcua-client')
                self.cert_path     = None
                self.key_path      = None

        args = Args()

        # ── Save newly uploaded files to the persistent location ──────────
        cert_upload = request.files.get('cert_file')
        key_upload  = request.files.get('key_file')

        if cert_upload and cert_upload.filename:
            cert_upload.save(CERT_FILE)

        if key_upload and key_upload.filename:
            key_upload.save(KEY_FILE)

        # ── Always point args at the persistent files (if they exist) ─────
        if os.path.exists(CERT_FILE):
            args.cert_path = CERT_FILE
        if os.path.exists(KEY_FILE):
            args.key_path = KEY_FILE

        if args.security_mode in (2, 3) and (not args.cert_path or not args.key_path):
            output = ('[Config Error] Security mode requires both client_cert.der '
                      'and client_key.pem. Please upload them in the Security section.')
        elif args.protocol == 'opcua':
            output = handle_opcua(args)

    cert_exists, key_exists, cert_kb, key_kb = _cert_status()

    return render_template(
        'opcua.html',
        output=output,
        values=form_values,
        cert_exists=cert_exists,
        key_exists=key_exists,
        cert_kb=cert_kb,
        key_kb=key_kb,
    )


# ── Certificate delete endpoint (called via JS fetch, no page reload) ─────────
@app.route('/opcua/delete_cert', methods=['POST'])
def opcua_delete_cert():
    """
    Body JSON: {"file": "cert"}  or  {"file": "key"}
    Returns:   {"ok": true}  or  {"ok": false, "error": "..."}
    """
    data      = request.get_json(force=True, silent=True) or {}
    file_type = data.get('file')

    target_map = {'cert': CERT_FILE, 'key': KEY_FILE}
    target = target_map.get(file_type)

    if not target:
        return jsonify({'ok': False, 'error': 'Unknown file type'}), 400

    if os.path.exists(target):
        try:
            os.unlink(target)
        except Exception as e:
            return jsonify({'ok': False, 'error': str(e)}), 500

    return jsonify({'ok': True})


# -------------------------
# RustScan
# -------------------------
@app.route('/scan')
def scan_page():
    return render_template('scan.html')


@app.route('/run-scan', methods=['POST'])
def run_scan():
    try:
        data = request.get_json()
        user_args_str = data.get('args', '')
        user_args_list = shlex.split(user_args_str)
        base_command = ['docker', 'run', '-t', '--rm', 'rustscan/rustscan:2.1.1']
        full_command = base_command + user_args_list


        result = subprocess.run(
            full_command,
            capture_output=True,
            text=True,
            check=False,
            encoding='utf-8'
        )
        raw_output = result.stdout + result.stderr
        converter = Ansi2HTMLConverter()
        html_output = converter.convert(raw_output)

        add_flag = bool(data.get('add_to_report', False)) 
        if add_flag:
            add_to_report(
                "scan",
                inputs={"command": " ".join(full_command), "args": user_args_list},
                output=raw_output
            )

        return jsonify({'output': html_output, 'raw_output': raw_output})


    except Exception as e:
        return jsonify({'error': str(e)}), 500


# -------------------------
# Reporting
# -------------------------
@app.route('/api/report', methods=['GET', 'DELETE'])
def api_report():
    if request.method == 'DELETE':
        clear_report_items()
        return ('', 204)
    return jsonify(get_report_items())

@app.route('/generate-report', methods=['POST'])
def generate_report_route():
    data = request.get_json(silent=True) or {}
    md, used = generate_report(
        audience=data.get("audience", "technical"),
        title=data.get("title", "ICS/OT Security Test Report"),
        model=data.get("model", "gpt-4o-mini"),
    )
    if not md and used == 0:
        return jsonify({"error": "Report inbox is empty."}), 400
    return jsonify({"report_markdown": md, "items_used": used})

@app.route('/add-scan-to-report', methods=['POST'])
def add_scan_to_report():
    try:
        data = request.get_json() or {}
        user_args_str = (data.get('args') or '').strip()
        raw_output = data.get('raw_output') or ''
        if not user_args_str or not raw_output:
            return jsonify({"error": "Missing args or raw_output from last run."}), 400

        user_args_list = shlex.split(user_args_str)
        base_command = ['docker', 'run', '-t', '--rm', 'rustscan/rustscan:2.1.1']
        full_command = base_command + user_args_list

        add_to_report(
            "scan",
            inputs={"command": " ".join(full_command), "args": user_args_list},
            output=raw_output
        )
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({'error': str(e)}), 500



@app.route('/add-modbus-to-report', methods=['POST'])
def add_modbus_to_report():
    """
    POST JSON:
      {
        "inputs": {
          "protocol": "modbus",
          "action": "...",
          "target": "...",
          "port": 502,
          "unit_id": 1,
          "function": "holding_registers",
          "address": 40001,
          "count": 1,
          "value": null,
          "timeout": 3,
          "retries": 3
        },
        "output": "<raw textual output from the last run>"
      }
    """
    try:
        data = request.get_json() or {}
        inputs = data.get("inputs") or {}
        output = data.get("output") or ""

        if not output.strip():
            return jsonify({"error": "No output provided to add."}), 400
        if inputs.get("protocol") != "modbus":
            return jsonify({"error": "Invalid or missing Modbus inputs."}), 400

        # normalize numeric fields
        for k in ("port", "unit_id", "address", "count", "value", "timeout", "retries"):
            if k in inputs and inputs[k] not in (None, ""):
                try:
                    inputs[k] = int(inputs[k])
                except Exception:
                    pass

        add_to_report("modbus", inputs, output)
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/report', methods=['GET'])
def report_page():
    return render_template('report.html')
    
# -------------------------
# Main
# -------------------------
if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0')
