import hashlib
import pefile
import datetime
import math
import subprocess

def hash_file(filepath):
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(65536), b''):
            h.update(chunk)
    return h.hexdigest()

def entropy(data):
    if not data: return 0
    freq = [data.count(bytes([b]))/len(data) for b in set(data)]
    return -sum(p * math.log2(p) for p in freq if p > 0)
def analyze(filepath):
    print(f"\n{'='*50}")
    print(f"FILE: {filepath}")
    print(f"{'='*50}")
    sha256 = hash_file(filepath)
    print(f"\nSHA256: {sha256}")
    print(f"VirusTotal: https://virustotal.com/gui/file/{sha256}")
    pe = pefile.PE(filepath)
    ts = pe.FILE_HEADER.TimeDateStamp
    dt = datetime.datetime.fromtimestamp(ts)
    print(f"\nCompiled: {dt}")
    overlay = pe.get_overlay()
    if overlay:
        print(f"OVERLAY: {len(overlay)} bytes — SUSPICIOUS!")
    else:
        print("Overlay: clean")
    
    print("\n--- IMPORTS ---")
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode()
        print(f"  {dll}")
    
    print("\n--- SECTIONS ---")
    for section in pe.sections:
        name = section.Name.decode().rstrip('\x00')
        ent = entropy(section.get_data())
        flag = "<< SUSPICIOUS!" if ent > 7.0 else ""
        print(f"  {name}: {ent:.2f} {flag}")

analyze('C:\\Windows\\System32\\notepad.exe')