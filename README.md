# CanaryScanner - A Canary Token Scanner

A tool to detect canary token honeypots in Office documents (.docx, .xlsx,) and PDF files.

## Features
- Scans Microsoft Office documents and PDFs for embedded URLs
- Identifies potentially malicious links while ignoring common safe domains
- Color-coded output for easy threat identification
- Supports both single file or directory scanning

## Supported File Types
- Microsoft Office: `.docx`, and `.xlsx`
- Adobe: `.pdf`

## Installation
clone repo
```bash
git clone https://github.com/TangInasal/CanaryScanner.git
```

create venv (optional)
```bash
python -m venv <name your venv>
```
OR (for Linux only)
```bash
source ./canaryscan_venv/bin/activate  
```

Install dependencies:
```bash
pip install install -r requirements.txt
```

---
## Usage

```bash
python canaryscanner.py <FILE_TO_SCAN>
```