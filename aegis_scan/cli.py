import argparse
import sys
from aegis_scan import scanner, utils
from aegis_scan import windows_checks


def confirm_target(target: str) -> bool:
    print(f"Target: {target}")
    print("Ensure you have permission to scan this target. Proceed? [y/N]", end=" ")
    resp = input().strip().lower()
    return resp in ("y", "yes")


def main(argv=None):
    argv = argv or sys.argv[1:]
    p = argparse.ArgumentParser(prog="aegis-scan")
    p.add_argument("--target", required=True, help="IP or hostname to scan")
    p.add_argument("--ports", default="22,80,443", help="Comma-separated ports or ranges (e.g. 1-1024,8080)")
    p.add_argument("--timeout", type=float, default=0.8, help="Connect timeout in seconds")
    p.add_argument("--workers", type=int, default=100, help="Max concurrent connections")
    p.add_argument("--banner", action="store_true", help="Try to grab service banners on open ports")
    p.add_argument("--win-checks", action="store_true", help="Run Windows-specific best-effort checks (ports, SMB anonymous shares if enabled)")
    args = p.parse_args(argv)

    if not confirm_target(args.target):
        print("Aborted.")
        return 1

    ports = utils.parse_ports(args.ports)
    print(f"Scanning {args.target} ports: {ports[:10]}{('...' if len(ports)>10 else '')}")
    open_ports = scanner.scan_ports(args.target, ports, timeout=args.timeout, workers=args.workers)
    if not open_ports:
        print("No open ports found.")
        return 0

    # Optional Windows checks
    if args.win_checks:
        print("Running Windows checks (best-effort, non-destructive)...")
        port_map = windows_checks.check_common_windows_ports(args.target, timeout=args.timeout, workers=args.workers)
        for svc, present in port_map.items():
            print(f" - {svc}: {'open' if present else 'closed'}")
        # If SMB open, try anonymous share list (requires impacket installed)
        if port_map.get('smb'):
            shares = windows_checks.smb_anonymous_share_list(args.target)
            if shares:
                print("SMB anonymous shares:")
                for s in shares:
                    print(f"   - {s}")
            else:
                print("SMB anonymous share listing not available or not allowed (impacket not installed or anonymous access denied).")
        # WinRM probe
        wm = windows_checks.winrm_service_probe(args.target)
        if wm:
            print("WinRM probe results:")
            for k, v in wm.items():
                print(f" - {k}: {v}")

    print("Open ports:")
    for pnum in open_ports:
        if args.banner:
            b = scanner.grab_banner(args.target, pnum)
            print(f" - {pnum}: {b}")
        else:
            print(f" - {pnum}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
