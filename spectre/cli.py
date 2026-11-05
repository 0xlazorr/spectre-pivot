import argparse
import asyncio
from spectre.scanner import SpectreScanner
from spectre.fingerprint import ServiceFingerprinter
from spectre.audit import SecurityAuditor
from spectre.reporter import SecurityReporter

async def run_scan(target: str, ports: list, concurrency: int):
    print(f"🛰️ Scanning target {target} across {len(ports)} ports (concurrency={concurrency})...")
    scanner = SpectreScanner(concurrency=concurrency)

    if "/" in target:
        open_ports = await scanner.scan_cidr(target, ports)
    else:
        open_ports = await scanner.scan_host(target, ports)

    print(f"🔍 Discovered {len(open_ports)} open endpoints. Fingerprinting services...")
    services = []
    for p in open_ports:
        info = await ServiceFingerprinter.probe(p.host, p.port)
        services.append(info)

    findings = SecurityAuditor.audit(services)
    SecurityReporter.render(open_ports, services, findings)

def main():
    parser = argparse.ArgumentParser(description="Spectre Pivot Network Auditor")
    subparsers = parser.add_subparsers(dest="command")

    scan_p = subparsers.add_parser("scan", help="Scan host or CIDR subnet")
    scan_p.add_argument("--target", default="127.0.0.1", help="Target IP or CIDR")
    scan_p.add_argument("--ports", default="21,22,23,80,443,3000,6379,8000,8080", help="Comma-separated ports")
    scan_p.add_argument("--concurrency", type=int, default=100, help="Concurrency limit")

    args = parser.parse_args()
    if args.command == "scan":
        port_list = [int(p.strip()) for p in args.ports.split(",") if p.strip()]
        asyncio.run(run_scan(args.target, port_list, args.concurrency))
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
