import subprocess
import shlex
from flask import Flask, render_template, request, jsonify, redirect, url_for
from ansi2html import Ansi2HTMLConverter
import os
from pathlib import Path
from dotenv import load_dotenv
from  report_gen import add_to_report, get_report_items, clear_report_items, generate_report

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


# -------------------------
# OPC UA
# -------------------------
@app.route('/opcua', methods=['GET', 'POST'])
def opcua_page():
    output = ''
    form_values = {}
    if request.method == 'POST':
        form_values = request.form


        class Args:
            def __init__(self):
                self.protocol = form_values.get('protocol')
                self.action = form_values.get('action')
                self.target = form_values.get('target')
                self.port = int(form_values.get('port', 4840))
                self.endpoint_path = form_values.get('endpoint_path', 'freeopcua/server/')
                self.username = form_values.get('username', '')  # optional
                self.password = form_values.get('password', '')  # optional
                self.nodeid = form_values.get('nodeid')
                self.value = form_values.get('value')
                self.max_depth = int(form_values.get('max_depth', 3))
                self.max_nodes = int(form_values.get('max_nodes', 200))
                self.namespace = form_values.get('namespace')
                self.timeout = int(form_values.get('timeout', 3))
                self.retries = int(form_values.get('retries', 3))


        args = Args()
        if args.protocol == 'opcua':
            output = handle_opcua(args)


    return render_template('opcua.html', output=output, values=form_values)


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
