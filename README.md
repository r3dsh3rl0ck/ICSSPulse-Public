<div align="center">

<img src="static/images/icsspulse-logo-white-bg.png" alt="logo" style="border-radius: 50%; width: 400px; object-fit: cover;"/>


### A Modular LLM-Assisted Platform for Industrial Control System Penetration Testing


> **A web-based platform that unifies network scanning, protocol-aware interaction, and LLM-assisted reporting in a single lightweight ICS pentesting ecosystem.**

</div>


## 🚀 Installation - Full Version

```bash
# 1. Clone the repository
git clone https://github.com/r3dsh3rl0ck/ICSSPulse-Public.git
cd ICSSPulse-Public

# 2. Create and activate a virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux / macOS
# venv\Scripts\activate           # Windows

# 3. Install Python dependencies
pip install -r requirements.txt

# 4. Pull the RustScan Docker image (required for network scanning)
docker pull rustscan/rustscan:latest

# 5. Set your OpenAI API key (required for LLM reporting, Optional)
export OPENAI_API_KEY="sk-..."    # Linux / macOS
# set OPENAI_API_KEY=sk-...       # Windows

# 6. Launch ICSSPulse
python app.py
```

Then open your browser at **`http://127.0.0.1:5000`**.

---

## 🐳 ICSSPulse Light — Docker Edition

A minimal, self-contained containerised version of ICSSPulse. No Python environment setup required — just Docker.

> **Includes:** Modbus TCP Handler, OPC UA Handler, s7comm Handler, MQTT Handler, EhterNet/IP Handler

> **Excludes:** Network Scanner · LLM Reporting

```bash
cd icsspulse-light
# Follow the instructions there
```

## 🔒 OPC UA Certificate Setup

To use **Sign** or **SignAndEncrypt** security modes, generate a self-signed client certificate:

```bash
# Step 1 — Generate private key and self-signed certificate
# The subjectAltName URI must match the "Application URI" field in the GUI
openssl req -x509 -newkey rsa:2048 \
  -keyout client_key.pem \
  -out client_cert.pem \
  -days 365 -nodes \
  -addext "subjectAltName = URI:urn:ctf:python-opcua-client"

# Step 2 — Convert certificate to DER format (required by the OPC UA handler)
openssl x509 -outform der -in client_cert.pem -out client_cert.der
```

Then in the **ICSSPulse GUI**:

1. Select **Security Mode** → `Sign` or `SignAndEncrypt`
2. Upload `client_cert.der` via the **Client Certificate** field
3. Upload `client_key.pem` via the **Private Key** field
4. Set **Application URI** to match the `subjectAltName` used above

> **Certificates are stored persistently on the server** and reused across sessions until you click **✕ Remove**. The server must trust your certificate (add it to the server's trust store beforehand).



---

## 📄 Research Paper

📎 **Paper:** [ICSSPulse: A Modular LLM-Assisted Platform for Industrial Control System Penetration Testing](https://link.springer.com/chapter/10.1007/978-3-032-27993-4_17)

---

## ⚠️ Disclaimer

> **ICSSPulse is intended strictly for authorised security testing, academic research, and educational use in controlled laboratory environments.**
>
> Running ICSSPulse against systems you do not own or lack explicit written permission to test is **illegal** and may violate computer fraud and abuse laws in your jurisdiction. The authors and contributors accept no liability for misuse of this tool. Always obtain proper authorisation before conducting any penetration test.
>
> ICSSPulse does **not** model physical disruptions, controller reprogramming, multi-stage ICS kill chains, or denial-of-service attacks. It is designed for safe, transparent, and reproducible protocol-level experimentation only.

---

