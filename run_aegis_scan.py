#!/usr/bin/env python3
"""One-click runner for AegisScan.

On Linux, this script auto-discovers listening TCP ports (using `ss` or `netstat`)
and runs the AegisScan CLI non-interactively. It writes the JSON report to
`docs/` by default (auto mode).

Usage: double-click or run from terminal. Optional: provide target as first arg.
"""
import sys
import subprocess
import platform
import re
import shutil
import os


def get_listening_ports_unix():
    # Prefer ss
    ports = set()
    ss = shutil.which("ss")
    netstat = shutil.which("netstat")
    if ss:
        try:
            out = subprocess.check_output([ss, "-ltn"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                # lines with LISTEN include something like "0.0.0.0:22" or "[::]:22"
                m = re.search(r":(\d+)", line)
                if m:
                    ports.add(int(m.group(1)))
        except Exception:
            pass
    elif netstat:
        try:
            out = subprocess.check_output([netstat, "-ltn"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                m = re.search(r":(\d+)", line)
                if m:
                    ports.add(int(m.group(1)))
        except Exception:
            pass
    return sorted(p for p in ports if p > 0)


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    system = platform.system().lower()
    if system in ("linux", "darwin"):
        ports = get_listening_ports_unix()
    else:
        # fallback: scan common ports
        ports = []

    if not ports:
        print("No listening ports detected; defaulting to common ports 1-1024 (may be slow).")
        ports_arg = "1-1024"
    else:
        ports_arg = ",".join(str(p) for p in ports)
        print(f"Detected listening ports: {ports_arg}")

    cmd = [sys.executable, "-m", "aegis_scan.cli", "--target", target, "--ports", ports_arg, "--yes"]
    # include win-checks only on Windows
    if system == "windows":
        cmd.append("--win-checks")

    print("Running:", " ".join(cmd))
    try:
        subprocess.run(cmd, check=False)
    except KeyboardInterrupt:
        print("Interrupted.")


if __name__ == "__main__":
    main()
