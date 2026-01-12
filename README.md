# ICSSPulse

ICSSPulse is an open-source, modular, web-based ICS penetration testing platform that unifies network scanning, protocol-aware Modbus and OPC UA interaction, and LLM-assisted reporting in one lightweight ecosystem.
It is designed for safe and reproducible experimentation in labs and cyber-range style environments using simulated industrial services.

## What it does

- Orchestrates an ICS penetration testing workflow via a web GUI: planning, scanning/enumeration, protocol interaction (Modbus/OPC UA), and reporting.
- Supports protocol-level discovery and controlled read/write interactions while keeping outputs transparent and reproducible.
- Generates executive and technical reports using an LLM-assisted reporting module, with mitigation guidance aligned to MITRE ATT&CK for ICS.

## Requirements

- Python 3.x.
- Python dependencies from `requirements.txt`.
- Docker installed (required for the integrated network scanning module).
- RustScan must run with normal user privileges (non-root).

## Project structure (high level)

- `app.py`: Flask application entrypoint and routing/controller logic.
- `templates/`: Web UI pages (e.g., scan, protocol handlers, report views).
- `static/`: Static frontend assets (CSS, etc.).
- `modbus_handler.py`: Modbus PT module (enumeration + read/write + unit discovery).
- `opcua_handler.py`: OPC UA PT module (endpoint/security discovery + browse/enumeration + read/write).
- `report_gen.py`: LLM-assisted report generation logic (executive/technical modes).
- `test-servers/`: Local test servers for Modbus and OPC UA to support training and experimentation.

## Modules (what they do)

### Web GUI (Flask)

- Provides a unified interface to configure targets (IP/ports), choose protocol modules, run actions, and view results. 
- Uses server-side routes per PT module (scan, Modbus, OPC UA, reporting) and renders dynamic content via templating.

### Network scanning (RustScan via Docker)

- Performs host/port discovery using RustScan executed inside a Docker container for consistent behavior and simplified dependency handling.
- Captures stdout/diagnostic output and returns it to the web UI for transparency and troubleshooting.
- Can forward scan results (as JSON + metadata like timestamp/command) into the reporting pipeline when requested.

### Modbus handler (`pymodbus`)

- Supports the four Modbus data types: coils, discrete inputs, holding registers, and input registers.
- Provides reconnaissance and exploitation operations:
  - Unit ID discovery by probing multiple unit identifiers. 
  - Address-range enumeration in chunks to identify accessible regions and values. 
  - Targeted read/write operations to validate impact and device behavior. 
- Uses a multi-offset probing strategy (e.g., 0/1/100/1000 and Modicon-style offsets like 40001/30001) to improve discovery across different device conventions.

### OPC UA handler (`python-opcua`)

- Retrieves endpoints and security posture details, including security policy/mode and supported identity token types (e.g., Anonymous, Username/Password).
- Browses the OPC UA address space (node tree traversal) with configurable depth and node limits via the GUI.
- Enumerates variable nodes and captures metadata such as NodeId, data type, access levels, and current values.
- Supports direct read/write to specified NodeIds and reports success/failure back in the UI.
### LLM-assisted reporting (`report_gen.py`)

- Produces two report modes:
  - Executive report: high-level overview for decision-makers. 
  - Technical report: structured detail for analysts/practitioners.
- Uses an “inbox” concept to collect evidence from scans and protocol interactions (parameters, timestamps, outputs) during the PT session.
- Aggregates findings per target (hosts/ports/services; Modbus unit IDs/register access; OPC UA node/variable access) and generates mitigations mapped to MITRE ATT&CK for ICS, consolidated into a dedicated section.
- Renders the final report in Markdown through the GUI and supports download.
- Add your API KEY to the `f.env` file.

## Installation

```bash
git clone <YOUR_REPO_URL>
cd ICSSpulse
pip install -r requirements.txt
python3 app.py
```
