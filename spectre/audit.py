from dataclasses import dataclass
from typing import List
from spectre.fingerprint import ServiceInfo

@dataclass
class VulnerabilityFinding:
    severity: str  # Critical, High, Medium, Low
    title: str
    host: str
    port: int
    description: str

class SecurityAuditor:
    @staticmethod
    def audit(services: List[ServiceInfo]) -> List[VulnerabilityFinding]:
        findings = []
        for s in services:
            # Rule 1: Unauthenticated Redis
            if s.service_name == "redis" and s.details.get("unauthenticated"):
                findings.append(VulnerabilityFinding(
                    severity="Critical",
                    title="Exposed Unauthenticated Redis Instance",
                    host=s.host,
                    port=s.port,
                    description="Redis accepted PING without requiring AUTH. Attacker can read/write memory and execute RCE via module loading or cron jobs."
                ))

            # Rule 2: Insecure HTTP cleartext on public ports
            if s.service_name == "http" and s.port in [80, 8080]:
                findings.append(VulnerabilityFinding(
                    severity="Low",
                    title="Cleartext HTTP Service Exposed",
                    host=s.host,
                    port=s.port,
                    description=f"HTTP service detected with banner: {s.banner[:60]}. Data in transit lacks TLS/SSL encryption."
                ))

            # Rule 3: Telnet service detected
            if s.port == 23:
                findings.append(VulnerabilityFinding(
                    severity="High",
                    title="Insecure Legacy Telnet Service",
                    host=s.host,
                    port=s.port,
                    description="Cleartext remote administrative protocol active on port 23."
                ))

        return findings
