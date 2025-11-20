# password-analyzer

A powerful and intelligent password analysis tool that detects weak patterns, dictionary words (with leet substitutions), repeated sequences, keyboard patterns, entropy, and estimated brute-force cracking time. It also provides detailed suggestions to improve password strength.

---

## 📦 Installation

You can install **password-analyzer** in 3 ways:

* **Method 1 (recommended)** – Install directly via pip from GitHub
* **Method 2** – Clone repository + install into virtual environment
* **Method 3** – Offline ZIP install

Works on **Linux, macOS, Windows, WSL, and Kali Linux**.

---

## ⭐ Method 1 — Install directly using pip (recommended)

### HTTPS:

```bash
pip install git+https://github.com/hacaksh/password-analyzer.git
```

### SSH:

```bash
pip install git+ssh://git@github.com/hacaksh/password-analyzer.git
```

Then run:

```bash
password-analyzer "MyP@ssw0rd123"
```

---

## ⭐ Method 2 — Clone the repo + install in virtual environment

```bash
git clone https://github.com/hacaksh/password-analyzer.git
cd password-analyzer

python3 -m venv .venv
source .venv/bin/activate        # Linux / macOS / WSL
# .\.venv\Scripts\Activate.ps1   # Windows PowerShell

pip install -e .
```

### Run the CLI:

```bash
password-analyzer "hello12345"
```

### Run the interactive analyzer:

```bash
python -m password_analyzer.analyzer
```

---

## ⭐ Kali Linux Users — IMPORTANT (PEP 668 Fix)

If you see this error:

```
error: externally-managed-environment
```

Kali prevents system-wide pip installs.

Fix:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## ⭐ Method 3 — Offline / No Internet

Download ZIP:

```
https://github.com/hacaksh/password-analyzer/archive/refs/heads/main.zip
```

Extract → open folder → run:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

## ▶️ Usage Examples

### Quick CLI scan:

```bash
password-analyzer "P@ssw0rd123"
```

### Interactive mode:

```bash
python -m password_analyzer.analyzer
```

---

## 🧪 Running Tests

```bash
pytest -q
```

---

## 🧩 File Structure

```
password-analyzer/
├── password_analyzer/
│   ├── analyzer.py
│   ├── cli.py
│   └── __init__.py
├── tests/
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## 🛠️ Troubleshooting

### ❌ CLI not found?

Activate virtual environment:

```bash
source .venv/bin/activate
```

### ❌ ModuleNotFoundError: password_analyzer

Reinstall editable mode:

```bash
pip install -e .
```

### ❌ Kali PEP668 error

Always use venv:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

---

For issues or improvements, feel free to open an issue or PR on GitHub!
