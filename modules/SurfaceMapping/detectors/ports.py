"""
ports.py — Port scanner com socket.
Substitui o binário Go port_scanner.
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict

TOP_100_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 9200, 6379, 27017, 5432, 1521,
    1433, 11211, 2181, 9092, 4848, 7001, 9000, 4000, 5000, 8000, 8001, 8888,
    9999, 10000, 49152, 554, 1080, 2049, 2375, 2376, 4243, 5601, 5672, 15672,
]

SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    27017: "MongoDB", 1433: "MSSQL", 1521: "Oracle", 11211: "Memcached",
    2375: "Docker (unauth!)", 2376: "Docker TLS", 5601: "Kibana",
    5672: "RabbitMQ", 15672: "RabbitMQ Mgmt",
}

HIGH_RISK_PORTS = {3306, 5432, 27017, 6379, 9200, 1433, 1521, 11211, 2375, 2376}


def _scan_port(host: str, port: int, timeout: float) -> tuple[int, bool]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            return port, True
    except Exception:
        return port, False


def scan(hosts: list[str], ports: list[int] | None = None,
         threads: int = 50, timeout: float = 1.5) -> dict:
    """
    Escaneia lista de hosts.
    Retorna dict host → {open_ports, services, high_risk}.
    """
    if ports is None:
        ports = TOP_100_PORTS

    results = {}

    for host in hosts[:20]:   # limita hosts por segurança
        open_ports = []

        with ThreadPoolExecutor(max_workers=min(threads, len(ports))) as ex:
            futures = {ex.submit(_scan_port, host, p, timeout): p for p in ports}
            for fut in as_completed(futures):
                port, is_open = fut.result()
                if is_open:
                    open_ports.append(port)

        open_ports.sort()
        services  = {p: SERVICE_NAMES.get(p, "unknown") for p in open_ports}
        high_risk = [p for p in open_ports if p in HIGH_RISK_PORTS]

        results[host] = {
            "open_ports": open_ports,
            "services":   services,
            "high_risk":  high_risk,
        }

        if high_risk:
            names = [f"{p}/{SERVICE_NAMES.get(p,'?')}" for p in high_risk]
            print(f"  \033[91m[!] HIGH RISK ports on {host}: {', '.join(names)}\033[0m")

    return results
