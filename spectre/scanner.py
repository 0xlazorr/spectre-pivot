import asyncio
import ipaddress
import socket
from typing import List, Tuple
from dataclasses import dataclass

@dataclass
class PortResult:
    host: str
    port: int
    is_open: bool
    latency_ms: float = 0.0

class SpectreScanner:
    def __init__(self, concurrency: int = 150, timeout: float = 1.5):
        self.concurrency = concurrency
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(concurrency)

    async def scan_port(self, host: str, port: int) -> PortResult:
        async with self.semaphore:
            loop = asyncio.get_running_loop()
            start = loop.time()
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                await writer.wait_closed()
                elapsed = (loop.time() - start) * 1000.0
                return PortResult(host=host, port=port, is_open=True, latency_ms=elapsed)
            except Exception:
                return PortResult(host=host, port=port, is_open=False)

    async def scan_host(self, host: str, ports: List[int]) -> List[PortResult]:
        tasks = [self.scan_port(host, p) for p in ports]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r.is_open]

    async def scan_cidr(self, cidr: str, ports: List[int]) -> List[PortResult]:
        net = ipaddress.ip_network(cidr, strict=False)
        tasks = []
        for host in net.hosts():
            for p in ports:
                tasks.append(self.scan_port(str(host), p))
        results = await asyncio.gather(*tasks)
        return [r for r in results if r.is_open]
