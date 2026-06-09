# PE Triage Tool 🔍

A Python-based malware analysis tool for static PE file analysis.

## What it does
- SHA256 hash extraction → VirusTotal lookup
- Compilation timestamp analysis (anti-forensics detection)
- Import table analysis (DLL & function enumeration)
- Shannon entropy calculation per section (packed/encrypted detection)
- Overlay data detection (hidden payload detection)

## Usage
```bash
pip install pefile
python Module_1_Project.py
```

## Sample Output
FILE: malware.exe
SHA256: a3f8c2d1...
VirusTotal: https://virustotal.com/gui/file/a3f8c2d1...
Compiled: 2039-07-16 (SUSPICIOUS - future timestamp)
Overlay: clean
--- IMPORTS ---
--- SECTIONS ---
.text: 6.24

## Skills Demonstrated
- Python 3 binary analysis
- PE format internals
- Shannon entropy calculation
- Malware triage workflow
