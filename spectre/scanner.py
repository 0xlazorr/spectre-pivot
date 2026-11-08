import asyncio
from enum import Enum
import ipaddress
import socket
from typing import List, Tuple
from dataclasses import dataclass

class ProbeState(str, Enum):
    """Explicit state machine for port probing."""
    NOT_STARTED = "not_started"
    CONNECTING = "connecting"
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    TIMEOUT = "timeout"

@dataclass
class PortResult:
    host: str
    port: int
    is_open: bool
    state: ProbeState = ProbeState.CLOSED
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
            writer = None
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                elapsed = (loop.time() - start) * 1000.0
                return PortResult(host=host, port=port, is_open=True, state=ProbeState.OPEN, latency_ms=elapsed)
            except asyncio.TimeoutError:
                return PortResult(host=host, port=port, is_open=False, state=ProbeState.TIMEOUT)
            except Exception:
                return PortResult(host=host, port=port, is_open=False, state=ProbeState.CLOSED)
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

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
