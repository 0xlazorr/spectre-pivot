import asyncio
from spectre.scanner import SpectreScanner
from spectre.fingerprint import ServiceFingerprinter
from spectre.audit import SecurityAuditor
from spectre.reporter import SecurityReporter

async def main():
    print("🛰️ Running local Spectre Pivot assessment...")
    scanner = SpectreScanner(concurrency=50)
    ports = [22, 80, 443, 6379, 8000, 8080]

    open_ports = await scanner.scan_host("127.0.0.1", ports)
    services = [await ServiceFingerprinter.probe("127.0.0.1", p.port) for p in open_ports]
    findings = SecurityAuditor.audit(services)

    SecurityReporter.render(open_ports, services, findings)

if __name__ == "__main__":
    asyncio.run(main())
