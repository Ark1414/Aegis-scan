Aegis Scan
===========

Aegis Scan is a small, safe network reconnaissance tool for authorized testing and learning.

Clone this repository:

  git clone https://github.com/Ark1414/Aegis-scan.git

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
