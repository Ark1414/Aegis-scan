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

Linking GitHub to VS Code
------------------------
- In VS Code: open the Command Palette (Ctrl+Shift+P) -> "Sign in to GitHub" and follow the prompts.
- Or push this repo to GitHub and open it in VS Code. Use the Git extension to see changes.

To quickly set a remote from PowerShell (replace <repo-url>):

  .\scripts\setup_git_remote.ps1 -RepoUrl "https://github.com/username/repo.git"

Files
-----
- `aegis_scan/` - package with CLI and scanner
- `tests/` - pytest tests
- `scripts/setup_git_remote.ps1` - helper to set Git remote from PowerShell

License
-------
Use at your own risk. No warranty.
