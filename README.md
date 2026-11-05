# Spectre Pivot 🛰️🐍

An ultra-fast, asynchronous **Network Pivoting, Service Fingerprinting & Security Audit Engine** written in **Python (Asyncio)**.

Designed for internal lateral movement assessments, subnet asset discovery, low-overhead TCP probing, and automated misconfiguration detection without external dependency overhead.

---

## 🏛️ Architecture & Modules

```text
Target CIDR Subnet / Host Range (e.g. 192.168.1.0/24)
          │
          ├──► [ Async Subnet Scanner ] ── (Asyncio semaphore, TCP socket connect)
          │
          ├──► [ Service Fingerprinter ] ── (Banner grabbing: HTTP, SSH, Redis, DBs)
          │
          ├──► [ Security Auditor ] ──► Unauthenticated DBs, Exposed APIs, Insecure TLS
          │
          ▼
   [ Structured Security Report ] (Terminal Rich Tables / JSON Output)
```

---

## 🌟 Key Capabilities

- **Zero-Dependency Async Scanning**: Highly optimized non-blocking socket probing capable of sweeping subnets concurrently using standard `asyncio`.
- **Active Service Fingerprinting**: Identifies banners across SSH, HTTP/HTTPS, Redis, Postgres, MySQL, and Telnet.
- **Misconfiguration & Weakness Detection**:
  - Flags exposed unauthenticated Redis instances (`PING / INFO`).
  - Flags anonymous access endpoints and administrative consoles.
  - Inspects HTTP headers for missing security controls (`HSTS`, `Content-Security-Policy`).
- **Lateral Movement Ready**: Designed to drop into compromised pivot hosts with zero external C-dependencies.
- **Rich Terminal UI & JSON Export**: Live progress tracking and exportable JSON vulnerability reports.

---

## 📂 Project Structure

```text
spectre-pivot/
├── pyproject.toml         # Package definition
├── requirements.txt       # Minimal dependencies
├── spectre/
│   ├── __init__.py        # Public API exports
│   ├── scanner.py         # Async TCP subnet & port scanner
│   ├── fingerprint.py     # Protocol banner grabbers & handshakes
│   ├── audit.py           # Vulnerability & security rule evaluation
│   ├── reporter.py        # Report generators (Terminal & JSON)
│   └── cli.py             # CLI application
├── examples/
│   └── audit_local.py     # Local assessment demo
└── README.md
```

---

## 🚀 Quickstart

### Scan a Host or Subnet:
```bash
python3 -m spectre.cli scan --target 127.0.0.1 --ports 22,80,443,6379,8000,8080
```

### Scan a Local Subnet:
```bash
python3 -m spectre.cli scan --target 192.168.1.0/24 --concurrency 250
```

---

## 📜 License
MIT License • Engineered by [Lazarus Ebi](https://github.com/0xlazorr)
