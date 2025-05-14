# Offline CVSS Calculator (with Optional OpenAI Integration)

A GUI-based offline CVSS v3.1 calculator built in Python, designed for cybersecurity students, researchers, and red/blue teams. This tool enables real-time vulnerability scoring and optionally integrates with OpenAI's GPT-4 to generate explanations, remediations, and simulated attack scenarios based on the metrics you select.

![screenshot](assets/screenshot.png)

---

## ✨ Features

- 🔐 **CVSS v3.1 Base Score Calculation** (fully standards-compliant)
- 🎛️ **Tkinter-based GUI** with real-time score display
- 🧠 **Optional ChatGPT Integration** for AI-driven insights:
  - Explanation of the CVSS score
  - Security best practice recommendations
  - Hypothetical attack simulation
- ⚙️ Fully **offline-capable**
- 🧪 Lightweight and dependency-free (except for `tkinter` and `openai`)

---

## 📊 Supported CVSS Metrics

This calculator uses the following CVSS v3.1 **Base Metrics**:

| Metric                     | Options                                |
|----------------------------|----------------------------------------|
| Access Vector (AV)         | Network (N), Adjacent (A), Local (L), Physical (P) |
| Access Complexity (AC)     | Low (L), High (H)                      |
| Privileges Required (PR)   | None (N), Low (L), High (H)            |
| Confidentiality (C)        | None (N), Low (L), High (H)            |
| Integrity (I)              | None (N), Low (L), High (H)            |
| Availability (A)           | None (N), Low (L), High (H)            |

---

## 🤖 ChatGPT Modes

If OpenAI integration is enabled and a valid API key is provided, the app can:

- 🧠 **Explain** the CVSS metrics and score
- 🛡️ **Recommend** mitigations (e.g., MFA, access control, patching)
- 🧨 **Simulate** an attack scenario based on metric values

You can toggle the AI assistant behavior using the "ChatGPT Mode" dropdown in the GUI.

---

## 🖥️ How to Use

### 1. Install Python Dependencies

```bash
pip install openai pillow
```

> `tkinter` should be installed by default on most systems. On Ubuntu:
```bash
sudo apt install python3-tk
```

### 2. Run the Calculator

```bash
python GPTCVSS.py
```

---

## 🔒 Offline Mode

The calculator is fully functional offline for CVSS scoring. OpenAI usage is **optional** and only triggered if a valid API key is provided in `CVSSGPT.py`:

```python
openai.api_key = "your-key-here"
```

If the key is omitted, only the score will be displayed.

---

## 🛠️ Architecture Overview

Here’s how the system is organized:

- `GPTCVSS.py`: Main GUI and event loop
- `CVSSGPT.py`: Handles OpenAI integration
- `CVSSOC.py`: Optional command-line variant or scoring module

---

## 🧪 Example Use Cases

| Scenario                        | Expected Score | Notes                                   |
|--------------------------------|----------------|-----------------------------------------|
| Public S3 Bucket Exposure      | 7.5 – 9.1      | High confidentiality, no integrity      |
| Local Privilege Escalation     | ~7.8           | High C+I, Local AV                      |
| DoS via Malformed Packet       | ~4.0           | Low availability, requires auth         |
| RCE via Web Admin Panel        | 9.8            | Network AV, High C+I+A, no auth         |

---

## 🚧 Limitations

- No temporal or environmental scoring (yet)
- Scope field not currently supported
- Requires manual API key input for GPT-4

---

## 📂 Folder Structure

```
📁 Offline-CVSS-Calculator/
│
├── GPTCVSS.py        # GUI entry point
├── CVSSGPT.py        # OpenAI integration
├── CVSSOC.py         # Optional CLI scoring logic
├── README.md         # This file
├── LICENSE.txt       # Optional: MIT/BSD/GPL
└── assets/
    └── screenshot.png  # Screenshot of UI in action
```

---

## 📄 License

MIT, Apache 2.0, or your license of choice — feel free to modify!

---

## 🙋 About

Developed as part of a U.S. Navy CRAM competition submission. This offline tool brings together scoring precision and AI-powered insights to help teams triage vulnerabilities without needing access to NIST’s hosted tools or internet access.

---
