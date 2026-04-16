import argparse
import sys
from aegis_scan import scanner, utils
from aegis_scan import windows_checks, vuln_db, report
import os
from datetime import datetime


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
    p.add_argument("--yes", action="store_true", help="Skip consent prompt (non-interactive)")
    p.add_argument("--json", nargs="?", const="auto", help="Write JSON report. Optionally provide a path; if omitted 'auto' will write to docs/scan_<target>_<ts>.json")
    p.add_argument("--win-checks", action="store_true", help="Run Windows-specific best-effort checks (ports, SMB anonymous shares if enabled)")
    args = p.parse_args(argv)

    if not args.yes:
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
        # try to grab a small banner if requested
        b = ""
        if args.banner:
            b = scanner.grab_banner(args.target, pnum)

        # assess severity for the open port
        finding = vuln_db.assess_port(pnum, banner=b)
        score = finding.get("score")
        label = finding.get("label")
        note = finding.get("note")
        if b:
            print(f" - {pnum}: {score}/10 ({label}) - {note}")
        else:
            print(f" - {pnum}: {score}/10 ({label})")

    # Build findings dict (include banner when present)
    findings = {}
    for p in open_ports:
        # if b was captured earlier per-port, reuse; else call assess_port with banner if available
        findings[p] = vuln_db.assess_port(p, banner=scanner.grab_banner(args.target, p) if args.banner else "")
    counts = vuln_db.summarize_findings(findings)
    print("\nSeverity distribution (1..10):")
    # ASCII histogram
    for s in range(1, 11):
        bar = "#" * counts.get(s, 0)
        print(f" {s:2d}: {bar} ({counts.get(s,0)})")

    # Try to generate a PNG chart if matplotlib present
    try:
        import matplotlib.pyplot as plt

        scores = list(range(1, 11))
        values = [counts.get(s, 0) for s in scores]
        plt.figure(figsize=(6, 3))
        plt.bar(scores, values, color="#d9534f")
        plt.xlabel("Severity (1-10)")
        plt.ylabel("Count")
        plt.title("AegisScan Severity Distribution")
        plt.xticks(scores)
        chart_path = "docs/severity_chart.png"
        plt.tight_layout()
        plt.savefig(chart_path)
        plt.close()
        print(f"Severity chart saved to: {chart_path}")
    except Exception:
        # matplotlib not available or failure — skip quietly
        pass

    # JSON report output
    if args.json:
        out = args.json
        if out == "auto":
            ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
            safe_target = args.target.replace(':', '_').replace('/', '_')
            out = os.path.join("docs", f"scan_{safe_target}_{ts}.json")
            os.makedirs(os.path.dirname(out), exist_ok=True)
        rep = report.build_report(args.target, open_ports, {p: {**findings.get(p, {}), "banner": (scanner.grab_banner(args.target, p) if args.banner else "") } for p in open_ports}, metadata={"timeout": args.timeout, "workers": args.workers})
        try:
            report.write_json_report(rep, out)
            print(f"JSON report written to: {out}")
        except Exception as e:
            print(f"Failed to write JSON report: {e}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
