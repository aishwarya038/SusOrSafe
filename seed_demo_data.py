"""Pushes realistic sample files and hashes through the REAL SusOrSafe endpoints.
Nothing is faked: every result below comes from the same scan pipeline as a manual upload.
All files are built in memory and are inert (plain bytes, never executed).

Usage:  python app.py            (in one terminal)
        python seed_demo_data.py (in another)      optional: python seed_demo_data.py http://127.0.0.1:5000
"""
import io, os, sys, json, hashlib, requests

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000").rstrip("/")
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

FILES = {
    "eicar.com": EICAR,                                                        # harmless AV test file -> Malicious
    "notes.txt": b"Meeting notes: ship the report on Friday. Nothing risky here.\n" * 5,   # clean
    "dropper.ps1": b"powershell -enc SQBFAFgA; [Convert]::FromBase64String($x); $s=New-Object -ComObject WScript.Shell; cmd.exe /c whoami",  # 4 suspicious script strings -> Suspicious
    "injector_demo.exe": b"MZ" + b"\x00" * 60 + b"VirtualAllocEx WriteProcessMemory CreateRemoteThread IsDebuggerPresent" + os.urandom(2500),  # inert bytes with the injection API trio -> Suspicious (scored from the strings, not the file name)
    "packed_blob.bin": b"UPX!" + os.urandom(6000),                             # high entropy only (UPX check applies to PE/ELF files) -> low score
    "invoice.pdf": b"%PDF-1.4\n1 0 obj << /OpenAction 2 0 R /JavaScript (app.alert(1)) >> endobj\n%%EOF",  # PDF active content
    "photo.png": b"\x89PNG\r\n\x1a\n" + os.urandom(4000),                       # compressed data must NOT be flagged for entropy
}
HASHES = [("EICAR (sha256)", hashlib.sha256(EICAR).hexdigest()),
          ("EICAR (md5)", hashlib.md5(EICAR).hexdigest()),
          ("Random unknown hash", hashlib.sha256(b"susorsafe-demo-unknown").hexdigest())]
PACKAGES = {"package.json": json.dumps({"dependencies": {"lodash": "4.17.15", "minimist": "1.2.0", "express": "latest"}}),
            "requirements.txt": "flask==0.12\nrequests==2.19.0\nreportlab==4.0.0\n"}

def show(label, r):
    try: d = r.json()
    except Exception: d = {}
    if r.ok: print(f"  OK    {label:<22} {d.get('verdict'):<11} {d.get('score')}/100   (scan #{d.get('id')})")
    else: print(f"  FAIL  {label:<22} {d.get('error') or r.status_code}")

try: requests.get(BASE + "/api/stats", timeout=5).raise_for_status()
except Exception as e: sys.exit(f"Cannot reach {BASE}. Start the server first: python app.py   ({e})")

print("Deep file scans")
for n, b in FILES.items(): show(n, requests.post(BASE + "/api/scan", files={"file": (n, io.BytesIO(b))}, timeout=90))
print("Hash lookups")
for n, h in HASHES: show(n, requests.post(BASE + "/api/hash", json={"sha256": h, "name": n}, timeout=90))
print("Package checks")
for n, t in PACKAGES.items(): show(n, requests.post(BASE + "/api/package", files={"file": (n, io.BytesIO(t.encode()))}, timeout=90))
print("\nDone. Open", BASE + "/#dashboard")