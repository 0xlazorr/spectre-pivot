import asyncio
from dataclasses import dataclass
from typing import Optional

@dataclass
class ServiceInfo:
    host: str
    port: int
    service_name: str
    banner: str
    details: dict

class ServiceFingerprinter:
    @staticmethod
    async def probe(host: str, port: int, timeout: float = 2.0) -> ServiceInfo:
        banner = ""
        service = "unknown"
        details = {}

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )

            # Common probes by port
            if port in [80, 8080, 8000, 3000]:
                writer.write(b"HEAD / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
                banner = data.decode(errors="ignore").strip()
                service = "http"
            elif port == 6379:
                writer.write(b"PING\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                banner = data.decode(errors="ignore").strip()
                if "+PONG" in banner:
                    service = "redis"
                    details["unauthenticated"] = True
            elif port == 22:
                data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                banner = data.decode(errors="ignore").strip()
                service = "ssh"
            else:
                writer.write(b"\r\n")
                await writer.drain()
                data = await asyncio.wait_for(reader.read(256), timeout=1.0)
                banner = data.decode(errors="ignore").strip()

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            banner = f"Probe error: {e}"

        return ServiceInfo(
            host=host,
            port=port,
            service_name=service,
            banner=banner[:150],
            details=details,
        )
