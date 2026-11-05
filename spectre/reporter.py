from rich.console import Console
from rich.table import Table
from typing import List
from spectre.scanner import PortResult
from spectre.fingerprint import ServiceInfo
from spectre.audit import VulnerabilityFinding

console = Console()

class SecurityReporter:
    @staticmethod
    def render(open_ports: List[PortResult], services: List[ServiceInfo], findings: List[VulnerabilityFinding]):
        # Table 1: Open Ports & Services
        table = Table(title="🛰️ Spectre Pivot — Discovered Services")
        table.add_column("Host", style="cyan")
        table.add_column("Port", style="green")
        table.add_column("Service", style="yellow")
        table.add_column("Banner / Info", style="white")

        for s in services:
            table.add_row(s.host, str(s.port), s.service_name, s.banner)

        console.print(table)

        # Table 2: Vulnerability Findings
        if findings:
            vuln_table = Table(title="🚨 Identified Security Weaknesses & Misconfigurations")
            vuln_table.add_column("Severity", style="bold red")
            vuln_table.add_column("Target", style="cyan")
            vuln_table.add_column("Title", style="bold white")
            vuln_table.add_column("Description", style="dim")

            for f in findings:
                vuln_table.add_row(f.severity, f"{f.host}:{f.port}", f.title, f.description)

            console.print(vuln_table)
        else:
            console.print("[green]✅ No immediate critical misconfigurations detected on scanned targets.[/green]")
