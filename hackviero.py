#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HACKVIERO - Toolkit de ciberseguridad para la terminal.

Una colección de herramientas de reconocimiento, análisis y utilidades
criptográficas con una interfaz bonita hecha con `rich`.

Úsalo únicamente en sistemas que sean tuyos o sobre los que tengas
autorización expresa. El autor no se hace responsable del mal uso.
"""
from __future__ import annotations

import argparse
import base64
import codecs
import concurrent.futures
import getpass
import hashlib
import hmac
import ipaddress
import itertools
import json
import math
import os
import platform
import re
import secrets
import socket
import ssl
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone

try:
    from rich import box
    from rich.align import Align
    from rich.console import Console
    from rich.markup import escape
    from rich.panel import Panel
    from rich.progress import (
        BarColumn,
        Progress,
        SpinnerColumn,
        TaskProgressColumn,
        TextColumn,
        TimeElapsedColumn,
    )
    from rich.prompt import Confirm, IntPrompt, Prompt
    from rich.syntax import Syntax
    from rich.table import Table
    from rich.text import Text
except ImportError:  # pragma: no cover
    print("[!] Falta la librería 'rich'. Instálala con:  pip install rich")
    sys.exit(1)


VERSION = "1.1.0"
__version__ = VERSION

BANNER = [
    "██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗   ██╗██╗███████╗██████╗  ██████╗ ",
    "██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║   ██║██║██╔════╝██╔══██╗██╔═══██╗",
    "███████║███████║██║     █████╔╝ ██║   ██║██║█████╗  ██████╔╝██║   ██║",
    "██╔══██║██╔══██║██║     ██╔═██╗ ╚██╗ ██╔╝██║██╔══╝  ██╔══██╗██║   ██║",
    "██║  ██║██║  ██║╚██████╗██║  ██╗ ╚████╔╝ ██║███████╗██║  ██║╚██████╔╝",
    "╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝  ╚═══╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ",
]
GRADIENT = ["#00ff9c", "#00f0b8", "#00dcd4", "#00c2ea", "#1fa2ff", "#4f7dff"]

console = Console()


# ════════════════════════════════════════════════════════════════════════════
#  PROMPTS EN ESPAÑOL
# ════════════════════════════════════════════════════════════════════════════
class PromptES(Prompt):
    validate_error_message = "[prompt.invalid]Escribe una respuesta válida"
    illegal_choice_message = "[prompt.invalid.choice]Elige una de las opciones disponibles"


class PromptMenu(PromptES):
    """Prompt del menú principal: sin los dos puntos finales."""

    prompt_suffix = " "


class IntPromptES(IntPrompt):
    validate_error_message = "[prompt.invalid]Escribe un número entero válido"
    illegal_choice_message = "[prompt.invalid.choice]Elige una de las opciones disponibles"


class ConfirmES(Confirm):
    choices = ["s", "n"]
    validate_error_message = "[prompt.invalid]Escribe 's' (sí) o 'n' (no)"


def ask(label: str, default: str | None = None, password: bool = False) -> str:
    kwargs: dict = {"password": password}
    if default is not None:
        kwargs["default"] = default
    return PromptES.ask(f"[bold cyan]{label}[/]", **kwargs).strip()


def ask_yes(label: str, default: bool = True) -> bool:
    return ConfirmES.ask(f"[bold cyan]{label}[/]", default=default)


def submenu(options: list[str]) -> str:
    console.print()
    for index, option in enumerate(options, 1):
        console.print(f"  [bold bright_green]{index}[/]  {option}")
    console.print("  [bold red]0[/]  Volver")
    return PromptES.ask(
        "[bold cyan]Opción[/]",
        choices=[str(i) for i in range(len(options) + 1)],
        show_choices=False,
    )


# ════════════════════════════════════════════════════════════════════════════
#  HELPERS DE INTERFAZ
# ════════════════════════════════════════════════════════════════════════════
def ok(message: str) -> None:
    console.print(f"[bold green][+][/] {message}")


def info(message: str) -> None:
    console.print(f"[bold cyan][*][/] {message}")


def warn(message: str) -> None:
    console.print(f"[bold yellow][!][/] {message}")


def err(message: str) -> None:
    console.print(f"[bold red][-][/] {escape(message)}")


def header(title: str, subtitle: str = "") -> None:
    console.print()
    console.print(
        Panel(
            Text(subtitle, style="grey70"),
            title=f"[bold bright_green] {title} [/]",
            title_align="left",
            border_style="green",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )


def show_banner() -> None:
    console.clear()
    art = Text(justify="center")
    for line, color in zip(BANNER, GRADIENT):
        art.append(line.rstrip() + "\n", style=f"bold {color}")
    console.print()
    console.print(Align.center(art))
    console.print(
        Align.center(Text("T O O L K I T   D E   C I B E R S E G U R I D A D", style="bold bright_cyan"))
    )
    console.print(
        Align.center(Text(f"v{VERSION}  ·  hecho con Python + rich", style="italic grey50"))
    )
    console.print()
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = "usuario"
    grid = Table.grid(padding=(0, 3))
    grid.add_row(
        f"[green]usuario[/] {escape(user)}",
        f"[green]host[/] {escape(socket.gethostname())}",
        f"[green]so[/] {escape(platform.system())} {escape(platform.release())}",
        f"[green]python[/] {platform.python_version()}",
    )
    console.print(
        Align.center(Panel(grid, border_style="grey37", box=box.ROUNDED, expand=False, padding=(0, 2)))
    )
    console.print()


def pause() -> None:
    try:
        console.print()
        console.input("[grey50]Presiona Enter para volver al menú...[/]")
    except (EOFError, KeyboardInterrupt):
        pass


def key_value_table(rows: list[tuple[str, str]], title: str | None = None) -> Table:
    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        title=title,
        title_style="bold bright_white",
        show_header=False,
        padding=(0, 1),
    )
    table.add_column(style="bold bright_green", no_wrap=True)
    table.add_column(overflow="fold")
    for key, value in rows:
        table.add_row(escape(key), escape(value))
    return table


def clean_target(raw: str) -> str:
    """Quita esquema y rutas si el usuario pegó una URL completa."""
    raw = raw.strip()
    raw = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", raw)
    return raw.split("/")[0].strip()


def is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def confirm_authorization(target: str) -> bool:
    """Pide confirmación de autorización salvo para localhost."""
    if is_loopback_host(target):
        return True
    console.print(
        Panel(
            "Solo debes analizar sistemas [bold]propios[/] o para los que tengas "
            "[bold]autorización expresa[/].\nEl acceso no autorizado es ilegal en la "
            "mayoría de países.",
            title="[bold yellow]Aviso legal[/]",
            border_style="yellow",
            box=box.ROUNDED,
        )
    )
    return ask_yes("¿Tienes autorización para analizar este objetivo?", default=False)


# ════════════════════════════════════════════════════════════════════════════
#  1. ESCÁNER DE PUERTOS
# ════════════════════════════════════════════════════════════════════════════
TOP_PORTS = sorted(
    {
        20, 21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 139, 143, 389, 443, 445,
        465, 514, 515, 587, 631, 636, 993, 995, 1080, 1194, 1433, 1434, 1521,
        1723, 2049, 2375, 3000, 3128, 3306, 3389, 4444, 5000, 5060, 5432, 5601,
        5900, 5985, 5986, 6379, 6667, 8000, 8008, 8080, 8081, 8443, 8888, 9000,
        9090, 9200, 9300, 11211, 27017,
    }
)

HTTP_PLAIN_PORTS = {80, 3000, 5000, 8000, 8008, 8080, 8081, 8888, 9000, 9090}

FALLBACK_SERVICES = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 465: "smtps",
    587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
    5900: "vnc", 6379: "redis", 8080: "http-proxy", 8443: "https-alt",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
}

RISK_NOTES = {
    21: "FTP envía credenciales sin cifrar. Prefiere SFTP/FTPS.",
    23: "Telnet no cifra nada. Sustitúyelo por SSH.",
    135: "RPC de Windows: no debería estar expuesto a internet.",
    139: "NetBIOS: no debería estar expuesto a internet.",
    445: "SMB expuesto: objetivo frecuente de ataques. Filtra por firewall.",
    1433: "Base de datos expuesta (MSSQL). Restringe por IP/VPN.",
    2375: "API de Docker sin TLS: equivale a acceso total al host.",
    3306: "Base de datos expuesta (MySQL). Restringe por IP/VPN.",
    3389: "RDP expuesto: usa VPN y autenticación multifactor.",
    4444: "Puerto típico de shells inversas. Investiga qué escucha ahí.",
    5432: "Base de datos expuesta (PostgreSQL). Restringe por IP/VPN.",
    5900: "VNC suele tener autenticación débil. Túnel por SSH/VPN.",
    6379: "Redis expuesto sin auth permite ejecución de comandos.",
    9200: "Elasticsearch expuesto puede filtrar todos tus datos.",
    11211: "Memcached expuesto: fuga de datos y amplificación DDoS.",
    27017: "MongoDB expuesto: asegúrate de tener autenticación activa.",
}


@dataclass
class PortResult:
    port: int
    service: str
    banner: str = ""


def parse_ports(spec: str) -> list[int]:
    """Convierte '22,80,1000-1010' en una lista ordenada de puertos."""
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                a, b = part.split("-", 1)
                start, end = int(a), int(b)
                if start > end:
                    start, end = end, start
            else:
                start = end = int(part)
        except ValueError:
            raise ValueError(f"Puerto inválido: {part!r}") from None
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise ValueError("Los puertos deben estar entre 1 y 65535")
        ports.update(range(start, end + 1))
    if not ports:
        raise ValueError("No indicaste ningún puerto")
    return sorted(ports)


def service_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return FALLBACK_SERVICES.get(port, "desconocido")


def resolve_host(host: str) -> str:
    try:
        return socket.gethostbyname(host)
    except (socket.gaierror, UnicodeError):
        raise ValueError(f"No se pudo resolver '{host}'") from None


def probe_port(ip: str, port: int, timeout: float, grab_banner: bool) -> tuple[int, bool, str]:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            banner = ""
            if grab_banner:
                try:
                    sock.settimeout(timeout)
                    if port in HTTP_PLAIN_PORTS:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = sock.recv(256)
                    lines = data.decode(errors="ignore").strip().splitlines()
                    banner = lines[0][:70] if lines else ""
                except OSError:
                    pass
            return port, True, banner
    except OSError:
        return port, False, ""


def scan_ports(
    ip: str,
    ports: list[int],
    timeout: float = 0.7,
    workers: int = 150,
    grab_banner: bool = True,
    on_progress=None,
) -> list[PortResult]:
    results: list[PortResult] = []
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, 500)))
    try:
        futures = [pool.submit(probe_port, ip, p, timeout, grab_banner) for p in ports]
        for future in concurrent.futures.as_completed(futures):
            port, is_open, banner = future.result()
            if is_open:
                results.append(PortResult(port, service_name(port), banner))
            if on_progress:
                on_progress()
    except KeyboardInterrupt:
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    pool.shutdown(wait=True)
    return sorted(results, key=lambda r: r.port)


def tool_portscan() -> None:
    header("ESCÁNER DE PUERTOS", "Detecta puertos TCP abiertos y servicios (connect scan).")
    target = clean_target(ask("Objetivo (IP o dominio)"))
    if not target:
        warn("No indicaste ningún objetivo.")
        return
    try:
        ip = resolve_host(target)
    except ValueError as exc:
        err(str(exc))
        return
    if target != ip:
        info(f"Objetivo resuelto: [bold]{escape(target)}[/] → [bold]{ip}[/]")
    if not confirm_authorization(ip if not is_loopback_host(target) else target):
        warn("Operación cancelada.")
        return

    choice = submenu(
        [
            f"Rápido      · puertos comunes ({len(TOP_PORTS)})",
            "Estándar    · puertos 1-1024",
            "Completo    · puertos 1-65535 (lento)",
            "Personalizado",
        ]
    )
    if choice == "0":
        return
    if choice == "1":
        ports = TOP_PORTS
    elif choice == "2":
        ports = list(range(1, 1025))
    elif choice == "3":
        ports = list(range(1, 65536))
    else:
        try:
            ports = parse_ports(ask("Puertos (ej: 22,80,443 o 1-1000)"))
        except ValueError as exc:
            err(str(exc))
            return

    grab = ask_yes("¿Intentar leer banners de servicio?", default=True)
    console.print()
    results, elapsed = run_scan(ip, ports, target, grab)
    render_scan(results, target, ip, ports, elapsed)


def resolve_port_spec(spec: str) -> list[int]:
    """Acepta 'top', 'all' o una lista/rango de puertos ('22,80,1-1024')."""
    key = spec.strip().lower()
    if key in ("top", "rapido", "rápido"):
        return list(TOP_PORTS)
    if key in ("all", "todos", "completo"):
        return list(range(1, 65536))
    return parse_ports(spec)


def run_scan(
    ip: str,
    ports: list[int],
    label: str,
    grab_banner: bool = True,
    timeout: float = 0.7,
    workers: int = 150,
) -> tuple[list[PortResult], float]:
    """Ejecuta el escaneo mostrando una barra de progreso."""
    started = time.perf_counter()
    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[bold]Escaneando[/] [cyan]{task.fields[host]}[/]"),
        BarColumn(bar_width=None, complete_style="green", finished_style="bright_green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("scan", total=len(ports), host=label)
        results = scan_ports(
            ip,
            ports,
            timeout=timeout,
            workers=workers,
            grab_banner=grab_banner,
            on_progress=lambda: progress.advance(task),
        )
    return results, time.perf_counter() - started


def render_scan(results: list[PortResult], target: str, ip: str, ports: list[int], elapsed: float) -> None:
    if not results:
        warn(f"Ningún puerto abierto de {len(ports)} escaneados ({elapsed:.2f}s).")
        return

    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_green",
        title=f"Puertos abiertos en {escape(target)} ({ip})",
        title_style="bold bright_white",
    )
    table.add_column("Puerto", justify="right", style="bold bright_white")
    table.add_column("Estado", style="green")
    table.add_column("Servicio", style="cyan")
    table.add_column("Banner", style="grey70", overflow="fold")
    for result in results:
        table.add_row(f"{result.port}/tcp", "abierto", escape(result.service), escape(result.banner))
    console.print(table)
    ok(f"{len(results)} abiertos de {len(ports)} escaneados en {elapsed:.2f}s")

    risky = [(r.port, RISK_NOTES[r.port]) for r in results if r.port in RISK_NOTES]
    if risky:
        console.print()
        for port, note in risky:
            warn(f"[bold]{port}[/]: {escape(note)}")


# ════════════════════════════════════════════════════════════════════════════
#  2. DNS / RESOLUCIÓN
# ════════════════════════════════════════════════════════════════════════════
def dns_lookup(target: str) -> dict:
    """Resuelve un dominio (A/AAAA, alias) y hace resolución inversa."""
    result: dict = {
        "target": target,
        "canonical": "",
        "aliases": [],
        "ipv4": [],
        "ipv6": [],
        "reverse": {},
    }
    try:
        ipaddress.ip_address(target)
        is_ip = True
    except ValueError:
        is_ip = False

    ips: list[str] = []
    if is_ip:
        ips = [target]
    else:
        try:
            canonical, aliases, _ = socket.gethostbyname_ex(target)
            result["canonical"] = canonical
            result["aliases"] = aliases
        except (socket.gaierror, UnicodeError):
            pass
        try:
            infos = socket.getaddrinfo(target, None, proto=socket.IPPROTO_TCP)
        except (socket.gaierror, UnicodeError):
            raise ValueError(f"No se pudo resolver '{target}'") from None
        for _family, _type, _proto, _canon, sockaddr in infos:
            ips.append(sockaddr[0])

    for ip in dict.fromkeys(ips):
        version = ipaddress.ip_address(ip.split("%")[0]).version
        result["ipv4" if version == 4 else "ipv6"].append(ip)
        try:
            result["reverse"][ip] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            result["reverse"][ip] = None
    return result


def tool_dns() -> None:
    header("DNS / RESOLUCIÓN", "Resuelve dominios a IPs (IPv4/IPv6) y consulta DNS inverso.")
    target = clean_target(ask("Dominio o IP"))
    if not target:
        warn("No indicaste ningún objetivo.")
        return
    try:
        with console.status("[green]Consultando DNS...[/]", spinner="dots"):
            data = dns_lookup(target)
    except ValueError as exc:
        err(str(exc))
        return

    render_dns(data)


def render_dns(data: dict) -> None:
    rows: list[tuple[str, str]] = [("Objetivo", data["target"])]
    if data["canonical"] and data["canonical"] != data["target"]:
        rows.append(("Nombre canónico", data["canonical"]))
    if data["aliases"]:
        rows.append(("Alias", ", ".join(data["aliases"])))
    for ip in data["ipv4"]:
        rows.append(("IPv4", ip))
    for ip in data["ipv6"]:
        rows.append(("IPv6", ip))
    for ip, name in data["reverse"].items():
        rows.append((f"Inverso {ip}", name or "(sin registro PTR)"))
    console.print(key_value_table(rows, title="Resultado DNS"))


# ════════════════════════════════════════════════════════════════════════════
#  3. SUBDOMINIOS
# ════════════════════════════════════════════════════════════════════════════
SUBDOMAIN_WORDS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "mx", "ns1", "ns2", "ns3", "ftp", "sftp",
    "dev", "development", "test", "testing", "qa", "stage", "staging", "preprod", "beta", "demo",
    "api", "api2", "rest", "graphql", "app", "apps", "m", "mobile", "web", "portal", "admin",
    "administrator", "panel", "cpanel", "dashboard", "login", "sso", "auth", "accounts", "id",
    "vpn", "remote", "gateway", "proxy", "intranet", "internal", "corp", "extranet",
    "blog", "shop", "store", "tienda", "docs", "help", "support", "ayuda", "status", "wiki",
    "cdn", "static", "assets", "img", "images", "media", "files", "download", "uploads",
    "git", "gitlab", "github", "svn", "jenkins", "ci", "build", "grafana", "kibana", "prometheus",
    "monitor", "logs", "db", "sql", "mysql", "postgres", "redis", "mongo", "backup", "old", "new",
    "secure", "cloud", "autodiscover", "owa", "exchange", "calendar", "chat", "meet", "forum",
]


def resolve_quiet(name: str) -> list[str]:
    try:
        return sorted(set(socket.gethostbyname_ex(name)[2]))
    except (socket.gaierror, UnicodeError, OSError):
        return []


def load_wordlist(path: str) -> list[str]:
    words: list[str] = []
    with open(os.path.expanduser(path), encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            word = line.strip().lower()
            if word and not word.startswith("#"):
                words.append(word)
    return list(dict.fromkeys(words))


def enumerate_subdomains(
    domain: str,
    words: list[str],
    workers: int = 50,
    on_progress=None,
) -> tuple[list[tuple[str, list[str]]], set[str]]:
    """Resuelve <palabra>.<dominio>. Detecta wildcard DNS para evitar falsos positivos."""
    wildcard_ips = set(resolve_quiet(f"{secrets.token_hex(8)}.{domain}"))
    found: list[tuple[str, list[str]]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, min(workers, 200))) as pool:
        futures = {pool.submit(resolve_quiet, f"{w}.{domain}"): w for w in words}
        try:
            for future in concurrent.futures.as_completed(futures):
                ips = future.result()
                if ips and not (wildcard_ips and set(ips) <= wildcard_ips):
                    found.append((f"{futures[future]}.{domain}", ips))
                if on_progress:
                    on_progress()
        except KeyboardInterrupt:
            pool.shutdown(wait=False, cancel_futures=True)
            raise
    return sorted(found), wildcard_ips


def run_subdomains(
    domain: str, words: list[str], workers: int = 50
) -> tuple[list[tuple[str, list[str]]], set[str], float]:
    started = time.perf_counter()
    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[bold]Buscando subdominios de[/] [cyan]{task.fields[host]}[/]"),
        BarColumn(bar_width=None, complete_style="green", finished_style="bright_green"),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("subs", total=len(words), host=domain)
        found, wildcard = enumerate_subdomains(
            domain, words, workers=workers, on_progress=lambda: progress.advance(task)
        )
    return found, wildcard, time.perf_counter() - started


def render_subdomains(
    found: list[tuple[str, list[str]]], wildcard: set[str], domain: str, total: int, elapsed: float
) -> None:
    if wildcard:
        warn(
            f"[bold]{escape(domain)}[/] usa DNS wildcard ({', '.join(sorted(wildcard))}): "
            "se descartan las respuestas idénticas al comodín."
        )
    if not found:
        warn(f"No se encontró ningún subdominio con {total} palabras ({elapsed:.2f}s).")
        return
    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_green",
        title=f"Subdominios de {escape(domain)}",
        title_style="bold bright_white",
    )
    table.add_column("Subdominio", style="bold bright_white")
    table.add_column("IPs", style="bright_cyan", overflow="fold")
    for name, ips in found:
        table.add_row(escape(name), escape(", ".join(ips)))
    console.print(table)
    ok(f"{len(found)} encontrados de {total} probados en {elapsed:.2f}s")


def tool_subdomains() -> None:
    header("SUBDOMINIOS", "Descubre subdominios probando nombres comunes por DNS.")
    domain = clean_target(ask("Dominio (ej: ejemplo.com)")).lower()
    if not domain or "." not in domain:
        warn("Indica un dominio válido, por ejemplo ejemplo.com")
        return
    if not confirm_authorization(domain):
        warn("Operación cancelada.")
        return
    words = SUBDOMAIN_WORDS
    custom = ask("Lista de palabras propia (Enter = lista integrada)", default="").strip("\"'")
    if custom:
        try:
            words = load_wordlist(custom)
        except OSError as exc:
            err(f"No se pudo leer la lista: {exc}")
            return
        if not words:
            err("La lista está vacía.")
            return
    console.print()
    found, wildcard, elapsed = run_subdomains(domain, words)
    render_subdomains(found, wildcard, domain, len(words), elapsed)


# ════════════════════════════════════════════════════════════════════════════
#  4. WHOIS
# ════════════════════════════════════════════════════════════════════════════
WHOIS_FIELDS = [
    ("Domain Name", "Dominio"),
    ("Registrar", "Registrador"),
    ("Creation Date", "Creación"),
    ("Updated Date", "Última actualización"),
    ("Registry Expiry Date", "Expira"),
    ("Registrar Registration Expiration Date", "Expira"),
    ("Domain Status", "Estado"),
    ("Name Server", "Servidores DNS"),
    ("DNSSEC", "DNSSEC"),
    ("Registrant Organization", "Organización"),
    ("Registrant Country", "País"),
    ("NetRange", "Rango de red"),
    ("inetnum", "Rango de red"),
    ("CIDR", "CIDR"),
    ("NetName", "Nombre de red"),
    ("netname", "Nombre de red"),
    ("OrgName", "Organización"),
    ("org-name", "Organización"),
    ("descr", "Descripción"),
    ("Country", "País"),
    ("country", "País"),
    ("OriginAS", "AS de origen"),
    ("abuse-mailbox", "Contacto de abuso"),
    ("OrgAbuseEmail", "Contacto de abuso"),
]


def whois_query(server: str, query: str, timeout: float = 8.0) -> str:
    chunks: list[bytes] = []
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(f"{query}\r\n".encode())
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
            if sum(map(len, chunks)) > 300_000:
                break
    return b"".join(chunks).decode("utf-8", errors="replace")


def whois_lookup(target: str) -> tuple[str, str]:
    """Consulta WHOIS siguiendo la referencia de IANA hasta el servidor autoritativo."""
    query = target
    try:
        ipaddress.ip_address(target)
    except ValueError:
        try:
            query = target.encode("idna").decode()
        except UnicodeError:
            pass
    server = "whois.iana.org"
    text = whois_query(server, query)
    match = re.search(r"^\s*(?:refer|whois):\s*(\S+)", text, re.I | re.M)
    if match and match.group(1).strip().lower() != server:
        server = match.group(1).strip().lower()
        text = whois_query(server, query)
        # Registros "thin" (.com/.net): se sigue al WHOIS del registrador si responde
        thin = re.search(r"Registrar WHOIS Server:\s*(\S+)", text, re.I)
        if thin:
            nxt = thin.group(1).strip().lower().removeprefix("whois://").rstrip("/")
            if nxt and nxt != server:
                try:
                    extra = whois_query(nxt, query)
                except OSError:
                    extra = ""
                if extra.strip():
                    server, text = nxt, extra
    return server, text


def parse_whois(text: str) -> list[tuple[str, str]]:
    pairs: dict[str, list[str]] = {}
    for line in text.splitlines():
        if line.lstrip().startswith(("%", "#", ">>>")):
            continue
        key, sep, value = line.partition(":")
        key, value = key.strip(), value.strip()
        if sep and key and value:
            pairs.setdefault(key.lower(), []).append(value)
    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for key, label in WHOIS_FIELDS:
        values = pairs.get(key.lower())
        if values and label not in seen:
            seen.add(label)
            unique = list(dict.fromkeys(values))
            rows.append((label, ", ".join(unique[:8])))
    return rows


def render_whois(target: str, server: str, text: str, raw: bool = False) -> None:
    rows = parse_whois(text)
    if rows:
        console.print(key_value_table(rows, title=f"WHOIS · {target} (vía {server})"))
    if raw or not rows:
        if not rows:
            warn("No se pudieron extraer campos conocidos; se muestra la respuesta completa.")
        console.print(
            Panel(
                escape(text.strip()[:6000]) or "(respuesta vacía)",
                title="[bold bright_green]Respuesta completa[/]",
                border_style="grey37",
                box=box.ROUNDED,
            )
        )


def tool_whois() -> None:
    header("WHOIS", "Consulta pública de registro de un dominio o una IP.")
    target = clean_target(ask("Dominio o IP"))
    if not target:
        warn("No indicaste ningún objetivo.")
        return
    try:
        with console.status("[green]Consultando WHOIS...[/]", spinner="dots"):
            server, text = whois_lookup(target)
    except OSError as exc:
        err(f"No se pudo consultar WHOIS: {exc}")
        return
    render_whois(target, server, text, raw=ask_yes("¿Mostrar también la respuesta completa?", False))


# ════════════════════════════════════════════════════════════════════════════
#  5. CERTIFICADO TLS
# ════════════════════════════════════════════════════════════════════════════
def split_host_port(raw: str, default_port: int = 443) -> tuple[str, int]:
    host = clean_target(raw)
    if host.count(":") == 1:  # host:puerto (las IPv6 llevan varios ':')
        name, _, port = host.partition(":")
        try:
            return name, int(port)
        except ValueError:
            raise ValueError(f"Puerto inválido: {port!r}") from None
    return host, default_port


def _cert_name(rdns) -> dict[str, str]:
    return {key: value for rdn in rdns for key, value in rdn}


def tls_inspect(host: str, port: int = 443, timeout: float = 8.0) -> dict:
    """Conecta por TLS y devuelve datos del certificado y del protocolo negociado."""
    result: dict = {
        "host": host,
        "port": port,
        "verified": False,
        "error": None,
        "protocol": None,
        "cipher": None,
        "subject": {},
        "issuer": {},
        "not_before": None,
        "not_after": None,
        "days_left": None,
        "san": [],
        "serial": None,
    }
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                result["protocol"] = tls.version()
                cipher = tls.cipher()
                result["cipher"] = cipher[0] if cipher else None
        result["verified"] = True
    except ssl.SSLCertVerificationError as exc:
        result["error"] = exc.verify_message or str(exc)
        # Reintento sin validar solo para informar del protocolo y el cifrado
        loose = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        loose.check_hostname = False
        loose.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with loose.wrap_socket(sock, server_hostname=host) as tls:
                    result["protocol"] = tls.version()
                    cipher = tls.cipher()
                    result["cipher"] = cipher[0] if cipher else None
        except OSError:
            pass
        return result

    result["subject"] = _cert_name(cert.get("subject", ()))
    result["issuer"] = _cert_name(cert.get("issuer", ()))
    result["serial"] = cert.get("serialNumber")
    result["san"] = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    try:
        start = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), tz=timezone.utc)
        end = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        result["not_before"], result["not_after"] = start, end
        result["days_left"] = (end - datetime.now(timezone.utc)).days
    except (KeyError, ValueError):
        pass
    return result


def render_tls(data: dict) -> None:
    subject, issuer = data["subject"], data["issuer"]
    rows: list[tuple[str, str]] = [("Objetivo", f"{data['host']}:{data['port']}")]
    if data["verified"]:
        rows.append(("Cadena de confianza", "✔ válida y el nombre coincide"))
    else:
        rows.append(("Cadena de confianza", f"✘ {data['error']}"))
    if subject:
        rows.append(("Titular (CN)", subject.get("commonName", "—")))
        if subject.get("organizationName"):
            rows.append(("Organización", subject["organizationName"]))
    if issuer:
        rows.append(("Emisor", issuer.get("organizationName") or issuer.get("commonName", "—")))
    if data["not_before"] and data["not_after"]:
        rows.append(("Válido desde", f"{data['not_before']:%Y-%m-%d}"))
        rows.append(("Válido hasta", f"{data['not_after']:%Y-%m-%d}  ({data['days_left']} días)"))
    if data["san"]:
        shown = ", ".join(data["san"][:8]) + (f" … (+{len(data['san']) - 8})" if len(data["san"]) > 8 else "")
        rows.append(("Nombres alternativos", shown))
    if data["protocol"]:
        rows.append(("Protocolo", data["protocol"]))
    if data["cipher"]:
        rows.append(("Cifrado", data["cipher"]))
    console.print(key_value_table(rows, title="Certificado TLS"))

    if not data["verified"]:
        warn("El certificado no es de confianza: los navegadores mostrarán una advertencia.")
    days = data["days_left"]
    if days is not None:
        if days < 0:
            warn("[bold]El certificado está CADUCADO.[/]")
        elif days < 30:
            warn(f"El certificado caduca en {days} días: renuévalo pronto.")
    if data["protocol"] in ("TLSv1", "TLSv1.1", "SSLv3"):
        warn(f"Protocolo obsoleto ({data['protocol']}). Usa TLS 1.2 o 1.3.")
    elif data["protocol"] == "TLSv1.3":
        ok("Protocolo moderno: TLS 1.3")


def tool_tls() -> None:
    header("CERTIFICADO TLS", "Inspecciona el certificado y el cifrado de un servidor HTTPS.")
    raw = ask("Host o host:puerto (ej: ejemplo.com)")
    try:
        host, port = split_host_port(raw)
    except ValueError as exc:
        err(str(exc))
        return
    if not host:
        warn("No indicaste ningún objetivo.")
        return
    if not confirm_authorization(host):
        warn("Operación cancelada.")
        return
    try:
        with console.status("[green]Negociando TLS...[/]", spinner="dots"):
            data = tls_inspect(host, port)
    except (OSError, ssl.SSLError, UnicodeError) as exc:
        err(f"No se pudo establecer la conexión TLS: {exc}")
        return
    render_tls(data)


# ════════════════════════════════════════════════════════════════════════════
#  6. CABECERAS HTTP DE SEGURIDAD
# ════════════════════════════════════════════════════════════════════════════
SECURITY_HEADERS = [
    ("strict-transport-security", "Strict-Transport-Security", "Fuerza HTTPS en el navegador"),
    ("content-security-policy", "Content-Security-Policy", "Mitiga XSS e inyección de contenido"),
    ("x-frame-options", "X-Frame-Options", "Protege contra clickjacking"),
    ("x-content-type-options", "X-Content-Type-Options", "Evita el MIME sniffing"),
    ("referrer-policy", "Referrer-Policy", "Controla qué datos viajan en el Referer"),
    ("permissions-policy", "Permissions-Policy", "Restringe APIs del navegador"),
]
LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]


@dataclass
class HeaderReport:
    final_url: str
    status: int
    headers: dict
    cookies: list = field(default_factory=list)


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        raise ValueError("No indicaste ninguna URL")
    if "://" not in raw:
        raw = "https://" + raw
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError("URL inválida (usa http:// o https://)")
    return raw


def fetch_headers(url: str, timeout: float = 8.0) -> HeaderReport:
    def _request(method: str):
        req = urllib.request.Request(
            url, method=method, headers={"User-Agent": f"Hackviero/{VERSION}"}
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.geturl(), resp.status, resp.headers
        except urllib.error.HTTPError as exc:
            return exc.geturl() or url, exc.code, exc.headers

    final_url, status, headers = _request("HEAD")
    if status in (405, 501):
        final_url, status, headers = _request("GET")
    return HeaderReport(
        final_url=final_url,
        status=status,
        headers={k.lower(): v for k, v in headers.items()},
        cookies=headers.get_all("Set-Cookie") or [],
    )


def analyze_headers(report: HeaderReport) -> dict:
    headers = report.headers
    present: list[str] = []
    missing: list[str] = []
    for key, _name, _desc in SECURITY_HEADERS:
        has = key in headers
        if key == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", ""):
            has = True
        (present if has else missing).append(key)

    leaks = [(k, headers[k]) for k in LEAKY_HEADERS if k in headers]

    cookie_issues: list[str] = []
    for cookie in report.cookies:
        name = cookie.split("=", 1)[0].strip()
        low = cookie.lower()
        problems = []
        if "secure" not in low:
            problems.append("Secure")
        if "httponly" not in low:
            problems.append("HttpOnly")
        if "samesite" not in low:
            problems.append("SameSite")
        if problems:
            cookie_issues.append(f"{name}: falta {', '.join(problems)}")

    score = round(100 * len(present) / len(SECURITY_HEADERS))
    if score == 100:
        grade = "A+"
    elif score >= 83:
        grade = "A"
    elif score >= 66:
        grade = "B"
    elif score >= 50:
        grade = "C"
    elif score >= 33:
        grade = "D"
    else:
        grade = "F"
    return {
        "present": present,
        "missing": missing,
        "leaks": leaks,
        "cookie_issues": cookie_issues,
        "score": score,
        "grade": grade,
        "uses_https": report.final_url.lower().startswith("https://"),
    }


def tool_headers() -> None:
    header("CABECERAS HTTP", "Audita las cabeceras de seguridad de un sitio web.")
    raw = ask("URL o dominio (ej: ejemplo.com)")
    try:
        url = normalize_url(raw)
    except ValueError as exc:
        err(str(exc))
        return
    host = urllib.parse.urlparse(url).hostname or ""
    if not confirm_authorization(host):
        warn("Operación cancelada.")
        return

    try:
        with console.status("[green]Consultando servidor...[/]", spinner="dots"):
            report = fetch_headers(url)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        err(f"No se pudo conectar: {exc}")
        return

    render_headers(report, analyze_headers(report))


def render_headers(report: HeaderReport, analysis: dict) -> None:
    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_green",
        title=f"Cabeceras de seguridad · HTTP {report.status}",
        title_style="bold bright_white",
    )
    table.add_column("Cabecera", style="bold white", no_wrap=True)
    table.add_column("Estado", justify="center")
    table.add_column("Detalle", overflow="fold", style="grey70")
    for key, name, description in SECURITY_HEADERS:
        if key in analysis["present"]:
            value = report.headers.get(key, "(cubierto por CSP frame-ancestors)")
            table.add_row(name, "[bold green]✔ presente[/]", escape(value[:90]))
        else:
            table.add_row(name, "[bold red]✘ falta[/]", escape(description))
    console.print(table)

    color = {"A+": "bright_green", "A": "green", "B": "yellow", "C": "yellow"}.get(analysis["grade"], "red")
    console.print(
        Panel(
            f"Nota: [bold {color}]{analysis['grade']}[/]   ·   "
            f"{len(analysis['present'])}/{len(SECURITY_HEADERS)} cabeceras",
            border_style=color,
            box=box.ROUNDED,
            expand=False,
        )
    )
    if not analysis["uses_https"]:
        warn("El sitio responde por HTTP sin cifrar. Activa HTTPS y HSTS.")
    for key, value in analysis["leaks"]:
        warn(f"Revela tecnología con [bold]{escape(key)}[/]: {escape(value)} (considera ocultarla)")
    for issue in analysis["cookie_issues"]:
        warn(f"Cookie · {escape(issue)}")


# ════════════════════════════════════════════════════════════════════════════
#  7. HASHES
# ════════════════════════════════════════════════════════════════════════════
HASH_ALGOS = ["md5", "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_256", "sha3_512", "blake2b"]
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def hash_bytes(data: bytes) -> dict:
    return {algo: hashlib.new(algo, data).hexdigest() for algo in HASH_ALGOS}


def hash_file(path: str) -> dict:
    hashers = {algo: hashlib.new(algo) for algo in HASH_ALGOS}
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}


def identify_hash(value: str) -> list[str]:
    """Sugiere posibles tipos de hash según su formato y longitud."""
    value = value.strip()
    if not value:
        return []
    prefixed = [
        (r"^\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}$", ["bcrypt"]),
        (r"^\$argon2(id|i|d)\$", ["Argon2"]),
        (r"^\$1\$", ["MD5-crypt"]),
        (r"^\$5\$", ["SHA-256-crypt"]),
        (r"^\$6\$", ["SHA-512-crypt"]),
        (r"^\$[PH]\$[./0-9A-Za-z]{31}$", ["phpass (WordPress / phpBB)"]),
        (r"^\*[0-9A-Fa-f]{40}$", ["MySQL 4.1+"]),
        (r"^pbkdf2_sha256\$", ["Django PBKDF2-SHA256"]),
    ]
    for pattern, names in prefixed:
        if re.match(pattern, value):
            return names
    if HEX_RE.match(value):
        by_length = {
            8: ["CRC-32"],
            16: ["MySQL323", "CRC-64"],
            32: ["MD5", "NTLM", "MD4"],
            40: ["SHA-1", "RIPEMD-160"],
            56: ["SHA-224", "SHA3-224"],
            64: ["SHA-256", "SHA3-256", "BLAKE2s-256"],
            96: ["SHA-384", "SHA3-384"],
            128: ["SHA-512", "SHA3-512", "BLAKE2b-512", "Whirlpool"],
        }
        return by_length.get(len(value), [])
    return []


def verify_file_hash(path: str, expected: str) -> str | None:
    """Devuelve el nombre del algoritmo que coincide con el hash esperado, o None."""
    expected = expected.strip().lower().encode()
    for algo, digest in hash_file(path).items():
        if hmac.compare_digest(digest.encode(), expected):
            return algo
    return None


def render_hashes(digests: dict, title: str) -> None:
    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_green",
        title=title,
        title_style="bold bright_white",
    )
    table.add_column("Algoritmo", style="bold white", no_wrap=True)
    table.add_column("Hash", style="bright_cyan", overflow="fold")
    for algo, digest in digests.items():
        table.add_row(algo.upper().replace("_", "-"), digest)
    console.print(table)


def ask_file_path() -> str | None:
    path = ask("Ruta del archivo").strip("\"'")
    if not path:
        warn("No indicaste ninguna ruta.")
        return None
    path = os.path.expanduser(path)
    if not os.path.isfile(path):
        err(f"No existe el archivo: {path}")
        return None
    return path


def tool_hash() -> None:
    header("HASHES", "Genera, identifica y verifica hashes e integridad de archivos.")
    while True:
        choice = submenu(
            [
                "Hashear un texto",
                "Hashear un archivo",
                "Identificar un hash",
                "Verificar integridad de un archivo",
            ]
        )
        if choice == "0":
            return
        if choice == "1":
            text = ask("Texto")
            render_hashes(hash_bytes(text.encode()), "Hashes del texto")
        elif choice == "2":
            path = ask_file_path()
            if path:
                try:
                    render_hashes(hash_file(path), f"Hashes de {escape(os.path.basename(path))}")
                except OSError as exc:
                    err(f"No se pudo leer el archivo: {exc}")
        elif choice == "3":
            value = ask("Hash a identificar")
            guesses = identify_hash(value)
            if guesses:
                ok("Posibles tipos: " + ", ".join(f"[bold]{escape(g)}[/]" for g in guesses))
            else:
                warn("No se reconoce el formato de ese hash.")
        elif choice == "4":
            path = ask_file_path()
            if not path:
                continue
            expected = ask("Hash esperado (el que publica el autor)")
            try:
                algo = verify_file_hash(path, expected)
            except OSError as exc:
                err(f"No se pudo leer el archivo: {exc}")
                continue
            if algo:
                ok(f"[bold green]INTEGRIDAD VERIFICADA[/] · coincide con {algo.upper().replace('_', '-')}")
            else:
                err("El hash NO coincide. El archivo está corrupto o fue modificado.")


# ════════════════════════════════════════════════════════════════════════════
#  8. CONTRASEÑAS (analizar, generar y filtraciones)
# ════════════════════════════════════════════════════════════════════════════
COMMON_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "abc123",
    "football", "monkey", "letmein", "111111", "iloveyou", "admin", "welcome",
    "123123", "dragon", "sunshine", "master", "login", "passw0rd", "password1",
    "qwerty123", "1q2w3e4r", "contraseña", "contrasena", "hola1234", "admin123",
    "root", "toor", "changeme", "princess", "starwars", "654321", "superman",
    "1234567", "zaq12wsx", "trustno1", "kali", "hackviero",
}
KEYBOARD_SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop", "asdfghjkl", "zxcvbnm",
]
AMBIGUOUS_CHARS = "O0oIl1|"
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"


def charset_size(password: str) -> int:
    size = 0
    if any(c.islower() for c in password):
        size += 26
    if any(c.isupper() for c in password):
        size += 26
    if any(c.isdigit() for c in password):
        size += 10
    if any(c in string.punctuation for c in password):
        size += 32
    if any(not c.isalnum() and c not in string.punctuation for c in password):
        size += 20
    return size


def has_sequence(password: str, length: int = 4) -> bool:
    low = password.lower()
    for seq in KEYBOARD_SEQUENCES + [s[::-1] for s in KEYBOARD_SEQUENCES]:
        for i in range(len(low) - length + 1):
            if low[i : i + length] in seq:
                return True
    return False


def humanize_seconds(seconds: float) -> str:
    if seconds < 1:
        return "instantáneo"
    for name, size in (("segundos", 60), ("minutos", 60), ("horas", 24), ("días", 365), ("años", 100)):
        if seconds < size:
            return f"{seconds:.0f} {name}"
        seconds /= size
    if seconds > 1.38e8:
        return "más que la edad del universo"
    if seconds < 1e6:
        return f"{seconds:,.0f} siglos"
    return f"{seconds:.1e} siglos"


def analyze_password(password: str) -> dict:
    issues: list[str] = []
    tips: list[str] = []
    size = charset_size(password)
    entropy = len(password) * math.log2(size) if size else 0.0

    if password.lower() in COMMON_PASSWORDS:
        entropy = min(entropy, 8.0)
        issues.append("Está entre las contraseñas más comunes y se prueba primero")
    if re.search(r"(.)\1{2,}", password):
        entropy *= 0.85
        issues.append("Contiene caracteres repetidos (aaa, 111...)")
    if has_sequence(password):
        entropy *= 0.85
        issues.append("Contiene secuencias previsibles (abcd, 1234, qwerty...)")

    if len(password) < 12:
        tips.append("Usa al menos 12 caracteres (idealmente 16 o más)")
    if not any(c.isupper() for c in password):
        tips.append("Añade mayúsculas")
    if not any(c.isdigit() for c in password):
        tips.append("Añade números")
    if not any(c in string.punctuation for c in password):
        tips.append("Añade símbolos")
    tips.append("Mejor aún: una frase larga y única, y un gestor de contraseñas")

    entropy = max(entropy, 0.0)
    score = min(100, int(entropy / 80 * 100))
    if entropy < 28:
        label, color = "Muy débil", "red"
    elif entropy < 36:
        label, color = "Débil", "dark_orange"
    elif entropy < 60:
        label, color = "Aceptable", "yellow"
    elif entropy < 80:
        label, color = "Fuerte", "green"
    else:
        label, color = "Excelente", "bright_green"

    # Ataque offline contra un hash rápido: ~10 mil millones de intentos/s
    crack_seconds = (2 ** entropy) / 2 / 1e10
    return {
        "length": len(password),
        "entropy": entropy,
        "score": score,
        "label": label,
        "color": color,
        "crack_time": humanize_seconds(crack_seconds),
        "issues": issues,
        "tips": tips,
    }


def generate_password(
    length: int = 20,
    lower: bool = True,
    upper: bool = True,
    digits: bool = True,
    symbols: bool = True,
    avoid_ambiguous: bool = False,
) -> str:
    pools: list[str] = []
    if lower:
        pools.append(string.ascii_lowercase)
    if upper:
        pools.append(string.ascii_uppercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append(SYMBOLS)
    if avoid_ambiguous:
        pools = ["".join(c for c in pool if c not in AMBIGUOUS_CHARS) for pool in pools]
    if not pools:
        raise ValueError("Selecciona al menos un tipo de carácter")
    if length < len(pools):
        raise ValueError("La longitud es demasiado corta para los tipos elegidos")
    chars = [secrets.choice(pool) for pool in pools]
    everything = "".join(pools)
    chars += [secrets.choice(everything) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def render_password_analysis(result: dict) -> None:
    filled = round(result["score"] / 5)
    bar = "█" * filled + "░" * (20 - filled)
    console.print(
        Panel(
            f"[{result['color']}]{bar}[/]  [bold {result['color']}]{result['label']}[/]",
            title="[bold bright_white]Fortaleza[/]",
            border_style=result["color"],
            box=box.ROUNDED,
            expand=False,
        )
    )
    console.print(
        key_value_table(
            [
                ("Longitud", f"{result['length']} caracteres"),
                ("Entropía estimada", f"{result['entropy']:.1f} bits"),
                ("Tiempo de ataque offline", result["crack_time"]),
            ]
        )
    )
    for issue in result["issues"]:
        warn(escape(issue))
    for tip in result["tips"]:
        info(escape(tip))
    console.print("[grey50]Todo se analiza localmente; nada sale de tu equipo.[/]")


def render_generated(passwords: list[str]) -> None:
    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_green",
        title="Contraseñas generadas",
        title_style="bold bright_white",
    )
    table.add_column("#", justify="right", style="grey50")
    table.add_column("Contraseña", style="bold bright_cyan", overflow="fold")
    table.add_column("Entropía", justify="right", style="green")
    for index, pw in enumerate(passwords, 1):
        table.add_row(str(index), escape(pw), f"{analyze_password(pw)['entropy']:.0f} bits")
    console.print(table)
    console.print("[grey50]Generadas con el módulo criptográfico `secrets` de Python.[/]")


def pwned_count(password: str, timeout: float = 8.0) -> int:
    """Veces que la contraseña aparece en filtraciones (API Pwned Passwords, k-anonimato).

    Solo se envían los 5 primeros caracteres del SHA-1; la contraseña nunca sale del equipo.
    """
    digest = hashlib.sha1(password.encode()).hexdigest().upper()  # noqa: S324 (lo exige la API)
    prefix, suffix = digest[:5], digest[5:]
    request = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": f"Hackviero/{VERSION}", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = response.read().decode()
    for line in body.splitlines():
        candidate, _, count = line.partition(":")
        if candidate.strip() == suffix:
            return int(count.strip() or 0)
    return 0


def report_pwned(password: str) -> int:
    """Muestra el resultado. Código de salida: 0 = no filtrada, 1 = filtrada, 2 = error de red."""
    try:
        with console.status("[green]Consultando Have I Been Pwned...[/]", spinner="dots"):
            count = pwned_count(password)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        err(f"No se pudo consultar el servicio: {exc}")
        return 2
    if count:
        err(f"Esta contraseña aparece en filtraciones {count:,} veces. NO la uses.")
    else:
        ok("No aparece en las filtraciones conocidas (eso no la hace automáticamente segura).")
    console.print("[grey50]Privacidad: solo se envían 5 caracteres del hash SHA-1 (k-anonimato).[/]")
    return 1 if count else 0


def tool_password() -> None:
    header("CONTRASEÑAS", "Analiza, genera y comprueba si una contraseña fue filtrada.")
    while True:
        choice = submenu(
            [
                "Analizar una contraseña",
                "Generar contraseñas seguras",
                "Comprobar si apareció en filtraciones (HIBP)",
            ]
        )
        if choice == "0":
            return
        if choice == "1":
            password = ask("Contraseña (no se muestra al escribir)", password=True)
            if not password:
                warn("No escribiste nada.")
                continue
            render_password_analysis(analyze_password(password))
        elif choice == "3":
            password = ask("Contraseña a comprobar (no se muestra al escribir)", password=True)
            if not password:
                warn("No escribiste nada.")
                continue
            report_pwned(password)
        else:
            length = IntPromptES.ask("[bold cyan]Longitud[/]", default=20)
            if not 4 <= length <= 128:
                err("La longitud debe estar entre 4 y 128.")
                continue
            count = IntPromptES.ask("[bold cyan]Cantidad[/]", default=5)
            count = max(1, min(count, 50))
            lower = ask_yes("¿Minúsculas?", True)
            upper = ask_yes("¿Mayúsculas?", True)
            digits = ask_yes("¿Números?", True)
            symbols = ask_yes("¿Símbolos?", True)
            ambiguous = ask_yes("¿Evitar caracteres ambiguos (O, 0, l, 1, I)?", False)
            try:
                passwords = [
                    generate_password(length, lower, upper, digits, symbols, ambiguous)
                    for _ in range(count)
                ]
            except ValueError as exc:
                err(str(exc))
                continue
            render_generated(passwords)


# ════════════════════════════════════════════════════════════════════════════
#  9. CODIFICADORES / DECODIFICADORES
# ════════════════════════════════════════════════════════════════════════════
def _b64_decode(text: str) -> str:
    text = text.strip()
    return base64.b64decode(text + "=" * (-len(text) % 4), validate=True).decode()


def _b32_decode(text: str) -> str:
    text = text.strip().upper()
    return base64.b32decode(text + "=" * (-len(text) % 8)).decode()


def _bin_encode(text: str) -> str:
    return " ".join(f"{byte:08b}" for byte in text.encode())


def _bin_decode(text: str) -> str:
    bits = re.sub(r"\s+", "", text)
    if not bits or len(bits) % 8 or set(bits) - {"0", "1"}:
        raise ValueError("El binario debe ser una cadena de 0 y 1 en bloques de 8 bits")
    return bytes(int(bits[i : i + 8], 2) for i in range(0, len(bits), 8)).decode()


CODECS = [
    ("Base64", lambda s: base64.b64encode(s.encode()).decode(), _b64_decode),
    ("Base32", lambda s: base64.b32encode(s.encode()).decode(), _b32_decode),
    ("Hexadecimal", lambda s: s.encode().hex(), lambda s: bytes.fromhex(s.strip()).decode()),
    ("URL (percent-encoding)", lambda s: urllib.parse.quote(s, safe=""), urllib.parse.unquote),
    ("ROT13", lambda s: codecs.encode(s, "rot_13"), lambda s: codecs.encode(s, "rot_13")),
    ("Binario", _bin_encode, _bin_decode),
]


def decode_jwt(token: str) -> tuple[dict, dict]:
    """Decodifica (sin verificar firma) cabecera y payload de un JWT."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise ValueError("Un JWT tiene 3 partes separadas por puntos")

    def segment(part: str) -> dict:
        raw = base64.urlsafe_b64decode(part + "=" * (-len(part) % 4))
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("Segmento JWT inválido")
        return value

    return segment(parts[0]), segment(parts[1])


CODEC_KEYS = {
    "b64": 0, "base64": 0,
    "b32": 1, "base32": 1,
    "hex": 2,
    "url": 3,
    "rot13": 4,
    "bin": 5, "binario": 5,
}


def show_jwt(token: str) -> bool:
    """Muestra cabecera y payload de un JWT. Devuelve False si no se pudo decodificar."""
    try:
        head, payload = decode_jwt(token)
    except ValueError as exc:
        err(f"No se pudo decodificar el JWT: {exc}")
        return False
    for title, content in (("Cabecera", head), ("Payload", payload)):
        console.print(
            Panel(
                Syntax(json.dumps(content, indent=2, ensure_ascii=False), "json", background_color="default"),
                title=f"[bold bright_green]{title}[/]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
    if str(head.get("alg", "")).lower() == "none":
        warn("El algoritmo es 'none': el token no está firmado. Nunca debería aceptarse.")
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and not isinstance(exp, bool):
        try:
            when = datetime.fromtimestamp(exp, tz=timezone.utc)
            state = "[red]EXPIRADO[/]" if when < datetime.now(timezone.utc) else "[green]vigente[/]"
            info(f"Expira: {when:%Y-%m-%d %H:%M:%S} UTC ({state})")
        except (OverflowError, OSError, ValueError):
            pass
    console.print("[grey50]Solo se decodifica: la firma no se verifica.[/]")
    return True


def tool_encode() -> None:
    header("CODIFICADORES", "Codifica y decodifica texto en formatos comunes.")
    while True:
        names = [c[0] for c in CODECS] + ["JWT (solo decodificar)"]
        choice = submenu(names)
        if choice == "0":
            return
        index = int(choice) - 1

        if index == len(CODECS):  # JWT
            show_jwt(ask("Token JWT"))
            continue

        name, encode, decode = CODECS[index]
        action = PromptES.ask(
            f"[bold cyan]{name}[/] · ¿Codificar o decodificar? [c/d]",
            choices=["c", "d"],
            show_choices=False,
        )
        text = ask("Texto")
        try:
            output = encode(text) if action == "c" else decode(text)
        except ValueError as exc:  # incluye binascii.Error y UnicodeDecodeError
            err(f"No se pudo decodificar como {name}: {exc}")
            continue
        console.print(
            Panel(
                Text(output, style="bold bright_cyan"),
                title=f"[bold bright_green]{name} · {'codificado' if action == 'c' else 'decodificado'}[/]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )


# ════════════════════════════════════════════════════════════════════════════
# 10. CALCULADORA DE SUBREDES
# ════════════════════════════════════════════════════════════════════════════
def subnet_info(cidr: str) -> dict:
    net = ipaddress.ip_network(cidr.strip(), strict=False)
    rows: list[tuple[str, str]] = [
        ("Versión", f"IPv{net.version}"),
        ("Red", str(net.network_address)),
        ("Prefijo", f"/{net.prefixlen}"),
        ("Máscara", str(net.netmask)),
    ]
    if net.version == 4:
        rows.append(("Wildcard", str(net.hostmask)))
        rows.append(("Broadcast", str(net.broadcast_address)))
        if net.prefixlen <= 30:
            first, last = net.network_address + 1, net.broadcast_address - 1
            usable = net.num_addresses - 2
        elif net.prefixlen == 31:
            first, last = net.network_address, net.broadcast_address
            usable = 2
        else:
            first = last = net.network_address
            usable = 1
        rows.append(("Primer host", str(first)))
        rows.append(("Último host", str(last)))
        rows.append(("Hosts utilizables", f"{usable:,}"))
    else:
        rows.append(("Primera dirección", str(net.network_address)))
        rows.append(("Última dirección", str(net.broadcast_address)))
    rows.append(("Direcciones totales", f"{net.num_addresses:,}"))

    kind = []
    base = net.network_address
    if base.is_loopback:
        kind.append("loopback")
    if base.is_private:
        kind.append("privada")
    if base.is_link_local:
        kind.append("link-local")
    if base.is_multicast:
        kind.append("multicast")
    if base.is_global:
        kind.append("pública / global")
    rows.append(("Tipo", ", ".join(kind) or "otro"))
    return {"network": net, "rows": rows}


def render_subnet_split(net: ipaddress.IPv4Network | ipaddress.IPv6Network, new_prefix: int) -> None:
    total = 2 ** (new_prefix - net.prefixlen)
    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_green",
        title=f"{total:,} subredes /{new_prefix}",
        title_style="bold bright_white",
    )
    table.add_column("#", justify="right", style="grey50")
    table.add_column("Subred", style="bold bright_cyan")
    for index, sub in enumerate(itertools.islice(net.subnets(new_prefix=new_prefix), 16), 1):
        table.add_row(str(index), str(sub))
    console.print(table)
    if total > 16:
        console.print(f"[grey50]... y {total - 16:,} más.[/]")


def tool_subnet() -> None:
    header("CALCULADORA DE SUBREDES", "Analiza una red en notación CIDR (IPv4 e IPv6).")
    raw = ask("Red CIDR (ej: 192.168.1.10/24)")
    try:
        data = subnet_info(raw)
    except ValueError as exc:
        err(f"CIDR inválido: {exc}")
        return
    console.print(key_value_table(data["rows"], title=f"Red {data['network']}"))

    net = data["network"]
    if net.prefixlen < net.max_prefixlen and ask_yes("¿Dividir en subredes más pequeñas?", False):
        new_prefix = IntPromptES.ask(
            f"[bold cyan]Nuevo prefijo[/] ({net.prefixlen + 1}-{net.max_prefixlen})",
            default=min(net.prefixlen + 2, net.max_prefixlen),
        )
        if not net.prefixlen < new_prefix <= net.max_prefixlen:
            err("Prefijo fuera de rango.")
            return
        render_subnet_split(net, new_prefix)


# ════════════════════════════════════════════════════════════════════════════
# 11. INFORMACIÓN DEL SISTEMA Y RED LOCAL
# ════════════════════════════════════════════════════════════════════════════
def local_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))  # UDP: no envía ningún paquete
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


def is_admin() -> bool:
    try:
        if hasattr(os, "geteuid"):
            return os.geteuid() == 0
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001
        return False


def system_info() -> list[tuple[str, str]]:
    try:
        user = getpass.getuser()
    except Exception:  # noqa: BLE001
        user = "desconocido"
    try:
        interfaces = ", ".join(name for _idx, name in socket.if_nameindex())
    except (AttributeError, OSError):
        interfaces = "no disponible"
    return [
        ("Usuario", user),
        ("Privilegios", "administrador / root" if is_admin() else "usuario estándar"),
        ("Host", socket.gethostname()),
        ("Sistema", platform.platform()),
        ("Arquitectura", platform.machine() or "desconocida"),
        ("Python", f"{platform.python_version()} ({platform.python_implementation()})"),
        ("IP local", local_ip()),
        ("Interfaces", interfaces or "no disponible"),
        ("Directorio actual", os.getcwd()),
    ]


def tool_sysinfo() -> None:
    header("INFO DEL SISTEMA", "Datos de tu equipo y de tu red local.")
    console.print(key_value_table(system_info(), title="Tu equipo"))


# ════════════════════════════════════════════════════════════════════════════
#  MENÚ PRINCIPAL
# ════════════════════════════════════════════════════════════════════════════
TOOLS = [
    ("1", "Escáner de puertos", "Descubre puertos TCP abiertos y servicios", tool_portscan),
    ("2", "DNS / Resolución", "IPs de un dominio y DNS inverso", tool_dns),
    ("3", "Subdominios", "Descubre subdominios con un diccionario DNS", tool_subdomains),
    ("4", "WHOIS", "Registro público de un dominio o una IP", tool_whois),
    ("5", "Certificado TLS", "Inspecciona el certificado y el cifrado HTTPS", tool_tls),
    ("6", "Cabeceras HTTP", "Audita las cabeceras de seguridad de un sitio", tool_headers),
    ("7", "Hashes", "Generar, identificar y verificar integridad", tool_hash),
    ("8", "Contraseñas", "Analizar, generar y comprobar filtraciones", tool_password),
    ("9", "Codificadores", "Base64, hex, URL, ROT13, binario y JWT", tool_encode),
    ("10", "Subredes CIDR", "Calculadora de redes IPv4 / IPv6", tool_subnet),
    ("11", "Info del sistema", "Datos de tu equipo y red local", tool_sysinfo),
]


def show_menu() -> None:
    table = Table(
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold bright_green",
        title="[bold bright_white]MENÚ PRINCIPAL[/]",
        padding=(0, 2),
    )
    table.add_column("#", justify="center", style="bold bright_green", no_wrap=True)
    table.add_column("Herramienta", style="bold white", no_wrap=True)
    table.add_column("Descripción", style="grey70")
    for key, name, description, _func in TOOLS:
        table.add_row(key, name, description)
    table.add_section()
    table.add_row("[bold red]0[/]", "[bold red]Salir[/]", "Cerrar Hackviero")
    console.print(Align.center(table))
    console.print(
        Align.center(Text("Úsalo solo en sistemas propios o con autorización expresa.", style="italic grey50"))
    )
    console.print()


def goodbye() -> None:
    console.print()
    console.print(
        Align.center(
            Panel(
                "[bold bright_green]Hasta pronto.[/] Hackea con ética.",
                border_style="green",
                box=box.ROUNDED,
                expand=False,
                padding=(0, 4),
            )
        )
    )
    console.print()


def configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass


# ════════════════════════════════════════════════════════════════════════════
#  MODO COMANDO (sin menú):  hackviero scan ejemplo.com -p top
# ════════════════════════════════════════════════════════════════════════════
def mini_banner() -> None:
    """Marca de una línea para el modo comando (solo en terminales interactivas)."""
    if not console.is_terminal:
        return
    brand = Text()
    for char, color in zip("HACKVIERO", ["#00ff9c", "#00f0b8", "#00dcd4", "#00c2ea", "#1fa2ff", "#4f7dff", "#6a6dff", "#8a5cff", "#a64dff"]):
        brand.append(char, style=f"bold {color}")
    brand.append(f"  v{VERSION}", style="grey50")
    console.print(brand)


def _authorized(target: str, args: argparse.Namespace) -> bool:
    """Autorización para pruebas activas: --yes, loopback o confirmación interactiva."""
    if getattr(args, "yes", False) or is_loopback_host(target):
        return True
    if not sys.stdin.isatty():
        err("Sesión no interactiva: añade --yes para confirmar que tienes autorización sobre el objetivo.")
        return False
    if confirm_authorization(target):
        return True
    warn("Operación cancelada.")
    return False


def cmd_scan(args: argparse.Namespace) -> int:
    target = clean_target(args.target)
    try:
        ip = resolve_host(target)
        ports = resolve_port_spec(args.ports)
    except ValueError as exc:
        err(str(exc))
        return 2
    if target != ip:
        info(f"Objetivo resuelto: [bold]{escape(target)}[/] → [bold]{ip}[/]")
    if not _authorized(ip, args):
        return 1
    results, elapsed = run_scan(
        ip, ports, target, grab_banner=not args.no_banner, timeout=args.timeout, workers=args.workers
    )
    render_scan(results, target, ip, ports, elapsed)
    if args.output:
        report = {
            "target": target,
            "ip": ip,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "scanned_ports": len(ports),
            "elapsed_seconds": round(elapsed, 2),
            "open": [
                {"port": r.port, "service": r.service, "banner": r.banner, "note": RISK_NOTES.get(r.port)}
                for r in results
            ],
        }
        try:
            with open(args.output, "w", encoding="utf-8") as handle:
                json.dump(report, handle, indent=2, ensure_ascii=False)
        except OSError as exc:
            err(f"No se pudo guardar el informe: {exc}")
            return 1
        ok(f"Informe guardado en [bold]{escape(args.output)}[/]")
    return 0


def cmd_dns(args: argparse.Namespace) -> int:
    target = clean_target(args.target)
    try:
        with console.status("[green]Consultando DNS...[/]", spinner="dots"):
            data = dns_lookup(target)
    except ValueError as exc:
        err(str(exc))
        return 1
    render_dns(data)
    return 0


def cmd_subs(args: argparse.Namespace) -> int:
    domain = clean_target(args.domain).lower()
    if "." not in domain:
        err("Indica un dominio válido, por ejemplo ejemplo.com")
        return 2
    words = SUBDOMAIN_WORDS
    if args.wordlist:
        try:
            words = load_wordlist(args.wordlist)
        except OSError as exc:
            err(f"No se pudo leer la lista: {exc}")
            return 2
        if not words:
            err("La lista está vacía.")
            return 2
    if not _authorized(domain, args):
        return 1
    found, wildcard, elapsed = run_subdomains(domain, words, workers=args.workers)
    render_subdomains(found, wildcard, domain, len(words), elapsed)
    return 0


def cmd_whois(args: argparse.Namespace) -> int:
    target = clean_target(args.target)
    try:
        with console.status("[green]Consultando WHOIS...[/]", spinner="dots"):
            server, text = whois_lookup(target)
    except OSError as exc:
        err(f"No se pudo consultar WHOIS: {exc}")
        return 1
    render_whois(target, server, text, raw=args.raw)
    return 0


def cmd_tls(args: argparse.Namespace) -> int:
    try:
        host, port = split_host_port(args.target)
    except ValueError as exc:
        err(str(exc))
        return 2
    if args.port:
        port = args.port
    if not host or not _authorized(host, args):
        return 1
    try:
        with console.status("[green]Negociando TLS...[/]", spinner="dots"):
            data = tls_inspect(host, port)
    except (OSError, ssl.SSLError, UnicodeError) as exc:
        err(f"No se pudo establecer la conexión TLS: {exc}")
        return 1
    render_tls(data)
    return 0


def cmd_headers(args: argparse.Namespace) -> int:
    try:
        url = normalize_url(args.url)
    except ValueError as exc:
        err(str(exc))
        return 2
    if not _authorized(urllib.parse.urlparse(url).hostname or "", args):
        return 1
    try:
        with console.status("[green]Consultando servidor...[/]", spinner="dots"):
            report = fetch_headers(url)
    except (urllib.error.URLError, OSError, ValueError) as exc:
        err(f"No se pudo conectar: {exc}")
        return 1
    render_headers(report, analyze_headers(report))
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    if args.what == "text":
        render_hashes(hash_bytes(args.value.encode()), "Hashes del texto")
        return 0
    if args.what == "id":
        guesses = identify_hash(args.value)
        if not guesses:
            warn("No se reconoce el formato de ese hash.")
            return 1
        ok("Posibles tipos: " + ", ".join(f"[bold]{escape(g)}[/]" for g in guesses))
        return 0
    path = os.path.expanduser(args.value)
    if not os.path.isfile(path):
        err(f"No existe el archivo: {path}")
        return 2
    try:
        if args.what == "file":
            render_hashes(hash_file(path), f"Hashes de {escape(os.path.basename(path))}")
            return 0
        algo = verify_file_hash(path, args.hash)  # what == "verify"
    except OSError as exc:
        err(f"No se pudo leer el archivo: {exc}")
        return 1
    if algo:
        ok(f"[bold green]INTEGRIDAD VERIFICADA[/] · coincide con {algo.upper().replace('_', '-')}")
        return 0
    err("El hash NO coincide. El archivo está corrupto o fue modificado.")
    return 1


def cmd_pass(args: argparse.Namespace) -> int:
    if args.what == "gen":
        if not 4 <= args.length <= 128:
            err("La longitud debe estar entre 4 y 128.")
            return 2
        count = max(1, min(args.count, 50))
        try:
            passwords = [
                generate_password(
                    args.length,
                    lower=not args.no_lower,
                    upper=not args.no_upper,
                    digits=not args.no_digits,
                    symbols=not args.no_symbols,
                    avoid_ambiguous=args.avoid_ambiguous,
                )
                for _ in range(count)
            ]
        except ValueError as exc:
            err(str(exc))
            return 2
        if console.is_terminal:
            render_generated(passwords)
        else:
            print("\n".join(passwords))
        return 0
    # check / pwned: la contraseña se pide oculta para que no quede en el historial de la shell
    password = getpass.getpass("Contraseña (no se muestra): ")
    if not password:
        warn("No escribiste nada.")
        return 2
    if args.what == "check":
        render_password_analysis(analyze_password(password))
        return 0
    return report_pwned(password)


def cmd_enc(args: argparse.Namespace) -> int:
    name, encode, decode = CODECS[CODEC_KEYS[args.format]]
    try:
        output = decode(args.text) if args.decode else encode(args.text)
    except ValueError as exc:  # incluye binascii.Error y UnicodeDecodeError
        err(f"No se pudo {'decodificar' if args.decode else 'codificar'} como {name}: {exc}")
        return 1
    if console.is_terminal:
        console.print(
            Panel(
                Text(output, style="bold bright_cyan"),
                title=f"[bold bright_green]{name} · {'decodificado' if args.decode else 'codificado'}[/]",
                border_style="cyan",
                box=box.ROUNDED,
            )
        )
    else:
        print(output)
    return 0


def cmd_jwt(args: argparse.Namespace) -> int:
    return 0 if show_jwt(args.token) else 1


def cmd_subnet(args: argparse.Namespace) -> int:
    try:
        data = subnet_info(args.cidr)
    except ValueError as exc:
        err(f"CIDR inválido: {exc}")
        return 2
    net = data["network"]
    console.print(key_value_table(data["rows"], title=f"Red {net}"))
    if args.split is not None:
        if not net.prefixlen < args.split <= net.max_prefixlen:
            err(f"El prefijo debe estar entre {net.prefixlen + 1} y {net.max_prefixlen}.")
            return 2
        render_subnet_split(net, args.split)
    return 0


def cmd_sys(_args: argparse.Namespace) -> int:
    console.print(key_value_table(system_info(), title="Tu equipo"))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hackviero",
        description="Hackviero · toolkit de ciberseguridad para la terminal. "
        "Sin argumentos abre el menú interactivo.",
        epilog="Úsalo solo en sistemas propios o con autorización expresa.",
        add_help=False,
    )
    parser.add_argument("-h", "--help", action="help", help="muestra esta ayuda y sale")
    parser.add_argument("-v", "--version", action="version", version=f"Hackviero {VERSION}", help="muestra la versión")
    sub = parser.add_subparsers(dest="command", metavar="comando", title="comandos")

    def add(name: str, help_text: str, func) -> argparse.ArgumentParser:
        p = sub.add_parser(name, help=help_text, description=help_text, add_help=False)
        p.add_argument("-h", "--help", action="help", help="muestra esta ayuda y sale")
        p.set_defaults(func=func)
        return p

    yes_help = "confirma que tienes autorización sobre el objetivo (omite la pregunta)"

    p = add("scan", "escáner de puertos TCP", cmd_scan)
    p.add_argument("target", help="IP o dominio")
    p.add_argument("-p", "--ports", default="top", help="'top', 'all' o lista/rango: 22,80,1-1024 (def: top)")
    p.add_argument("-t", "--timeout", type=float, default=0.7, help="segundos por puerto (def: 0.7)")
    p.add_argument("-w", "--workers", type=int, default=150, help="hilos simultáneos (def: 150)")
    p.add_argument("--no-banner", action="store_true", help="no leer banners de servicio")
    p.add_argument("-o", "--output", metavar="ARCHIVO", help="guarda el informe en JSON")
    p.add_argument("-y", "--yes", action="store_true", help=yes_help)

    p = add("dns", "resolución DNS e inversa", cmd_dns)
    p.add_argument("target", help="dominio o IP")

    p = add("subs", "descubre subdominios por diccionario", cmd_subs)
    p.add_argument("domain", help="dominio base, ej: ejemplo.com")
    p.add_argument("-l", "--wordlist", metavar="ARCHIVO", help="lista de palabras propia")
    p.add_argument("-w", "--workers", type=int, default=50, help="hilos simultáneos (def: 50)")
    p.add_argument("-y", "--yes", action="store_true", help=yes_help)

    p = add("whois", "registro WHOIS de un dominio o IP", cmd_whois)
    p.add_argument("target", help="dominio o IP")
    p.add_argument("--raw", action="store_true", help="muestra también la respuesta completa")

    p = add("tls", "inspecciona el certificado TLS", cmd_tls)
    p.add_argument("target", help="host o host:puerto")
    p.add_argument("-p", "--port", type=int, help="puerto (def: 443)")
    p.add_argument("-y", "--yes", action="store_true", help=yes_help)

    p = add("headers", "audita cabeceras HTTP de seguridad", cmd_headers)
    p.add_argument("url", help="URL o dominio")
    p.add_argument("-y", "--yes", action="store_true", help=yes_help)

    p = add("hash", "hashes: generar, identificar y verificar", cmd_hash)
    hsub = p.add_subparsers(dest="what", metavar="acción", required=True)
    hsub.add_parser("text", help="hashea un texto", add_help=False).add_argument("value", metavar="TEXTO")
    hsub.add_parser("file", help="hashea un archivo", add_help=False).add_argument("value", metavar="RUTA")
    hsub.add_parser("id", help="identifica el tipo de un hash", add_help=False).add_argument("value", metavar="HASH")
    verify = hsub.add_parser("verify", help="verifica un archivo contra un hash", add_help=False)
    verify.add_argument("value", metavar="RUTA")
    verify.add_argument("hash", metavar="HASH")

    p = add("pass", "contraseñas: analizar, generar, filtraciones", cmd_pass)
    psub = p.add_subparsers(dest="what", metavar="acción", required=True)
    psub.add_parser("check", help="analiza la fortaleza (se pide oculta)", add_help=False)
    psub.add_parser("pwned", help="comprueba filtraciones con HIBP (se pide oculta)", add_help=False)
    gen = psub.add_parser("gen", help="genera contraseñas seguras", add_help=False)
    gen.add_argument("-l", "--length", type=int, default=20, help="longitud (def: 20)")
    gen.add_argument("-n", "--count", type=int, default=5, help="cantidad (def: 5)")
    gen.add_argument("--no-lower", action="store_true", help="sin minúsculas")
    gen.add_argument("--no-upper", action="store_true", help="sin mayúsculas")
    gen.add_argument("--no-digits", action="store_true", help="sin números")
    gen.add_argument("--no-symbols", action="store_true", help="sin símbolos")
    gen.add_argument("--avoid-ambiguous", action="store_true", help="evita O, 0, l, 1, I")

    p = add("enc", "codifica / decodifica texto", cmd_enc)
    p.add_argument("format", choices=sorted(CODEC_KEYS), help="formato")
    p.add_argument("text", help="texto de entrada")
    p.add_argument("-d", "--decode", action="store_true", help="decodificar en vez de codificar")

    p = add("jwt", "decodifica un JWT (sin verificar firma)", cmd_jwt)
    p.add_argument("token")

    p = add("subnet", "calculadora de subredes CIDR", cmd_subnet)
    p.add_argument("cidr", help="ej: 192.168.1.10/24")
    p.add_argument("-s", "--split", type=int, metavar="PREFIJO", help="divide en subredes de este prefijo")

    add("sys", "información del equipo y la red local", cmd_sys)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_stdio()
    if getattr(args, "command", None):
        mini_banner()
        try:
            return args.func(args)
        except KeyboardInterrupt:
            console.print()
            warn("Operación cancelada por el usuario.")
            return 130
        except (OSError, ssl.SSLError) as exc:
            err(str(exc))
            return 1
    return interactive()


def interactive() -> int:
    handlers = {key: func for key, _name, _desc, func in TOOLS}
    valid = list(handlers) + ["0"]

    while True:
        show_banner()
        show_menu()
        try:
            choice = PromptMenu.ask(
                "[bold green]hackviero[/][grey50]@[/][cyan]toolkit[/] [bold bright_white]›[/]",
                choices=valid,
                show_choices=False,
            )
        except (KeyboardInterrupt, EOFError):
            goodbye()
            return 0
        if choice == "0":
            goodbye()
            return 0
        try:
            handlers[choice]()
        except KeyboardInterrupt:
            console.print()
            warn("Operación cancelada por el usuario.")
        except EOFError:
            goodbye()
            return 0
        pause()


if __name__ == "__main__":
    sys.exit(main())
