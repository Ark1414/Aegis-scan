Aegis Scan
===========

Aegis Scan is a small, safe network reconnaissance tool for authorized testing and learning.

Usage
-----
- Python 3.8+
- From the repository root run:

  python -m aegis_scan.cli --target 192.0.2.1 --ports 22,80,443

Important safety
----------------
Only run scans against hosts or networks you own or have explicit permission to test. Misuse can be illegal.



Files
-----
- `aegis_scan/` - package with CLI and scanner
- `tests/` - pytest tests
- `scripts/setup_git_remote.ps1` - helper to set Git remote from PowerShell

License
-------
Use at your own risk. No warranty.
