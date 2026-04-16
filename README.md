Aegis Scan
===========

Aegis Scan is a small, safe network reconnaissance tool for authorized testing and learning.

Clone this repository:

  git clone https://github.com/Ark1414/Aegis-scan.git

Linux quick start (one-click runner)
----------------------------------
If you want a fast, clickable way to run AegisScan on a Linux machine, use the provided `run_aegis_scan.py` script which auto-discovers listening TCP ports and runs the scanner non-interactively.

1. Clone or download the repo (ZIP or TAR):

  # Clone (recommended if you plan to update)
  git clone https://github.com/Ark1414/Aegis-scan.git

  # Or download the ZIP of the main branch:
  https://github.com/Ark1414/Aegis-scan/archive/refs/heads/main.zip

  # Or download the tarball:
  https://github.com/Ark1414/Aegis-scan/archive/refs/heads/main.tar.gz

2. Create and activate a Python virtual environment (recommended):

  python3 -m venv .venv
  source .venv/bin/activate

3. Install dependencies (optional deps enable plotting and SMB checks):

  pip install -r requirements.txt

4. Make the runner executable and run it:

  chmod +x run_aegis_scan.py
  ./run_aegis_scan.py       # defaults to scanning localhost

  # or provide a target IP:
  ./run_aegis_scan.py 192.168.1.5

Notes:
- The runner uses `ss` (or `netstat` fallback) on Unix to detect listening ports. If neither is available the script defaults to scanning ports 1-1024 (which may take longer).
- The runner calls the CLI with `--yes` so it runs non-interactively; only use it on hosts you own or have explicit permission to test.

If you'd like, I can also add a small `.desktop` launcher file so double-clicking an icon will open a terminal and run the script on GNOME/KDE desktops. Let me know and I will add that next.

Usage
-----

  python -m aegis_scan.cli --target 192.0.2.1 --ports 22,80,443

Important safety
Only run scans against hosts or networks you own or have explicit permission to test. Misuse can be illegal.

Automated local port discovery and scan (Windows)
-----------------------------------------------
You can automatically discover listening TCP ports on this Windows machine and run AegisScan against them with the included PowerShell helper:

  .\\scripts\\auto_scan.ps1 -Target 127.0.0.1 -WinChecks

This will list listening ports using `Get-NetTCPConnection` and run the scanner non-interactively (it auto-confirms consent). Use only on hosts you own or have permission to test.



Files
-----
- `aegis_scan/` - package with CLI and scanner
- `tests/` - pytest tests
- `scripts/setup_git_remote.ps1` - helper to set Git remote from PowerShell

License
-------
Use at your own risk. No warranty.
