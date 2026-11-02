#!/usr/bin/env python3
"""
brute-force-detector — detecta força bruta e password spraying em logs de autenticação.

Fontes suportadas:
  * Linux  : /var/log/auth.log ou /var/log/secure (OpenSSH)
  * Windows: CSV exportado do Security Log (Event IDs 4625 = falha, 4624 = sucesso)

MITRE ATT&CK:
  * T1110.001 — Brute Force: Password Guessing
  * T1110.003 — Brute Force: Password Spraying
  * T1078     — Valid Accounts (login bem-sucedido após série de falhas)

Uso rápido:
  python detector.py samples/auth.log
  python detector.py samples/windows_security.csv --threshold 10 --window 120
  python detector.py samples/auth.log --format json --output alertas.json
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #


@dataclass
class AuthEvent:
    timestamp: datetime
    source_ip: str
    username: str
    success: bool
    source: str  # "ssh" ou "windows"


@dataclass
class Alert:
    source_ip: str
    severity: str
    technique: str
    description: str
    failures: int
    max_in_window: int
    distinct_users: int
    first_seen: str
    last_seen: str
    users_sample: list[str] = field(default_factory=list)
    compromised_users: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Parsers
# --------------------------------------------------------------------------- #

# Formato syslog clássico:  "Nov  2 14:03:11 host sshd[1234]: ..."
SYSLOG_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s")
# Formato RFC 3339 (rsyslog moderno / journald): "2026-11-02T14:03:11.123456-03:00 host ..."
ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")

SSH_FAILED = re.compile(
    r"sshd\[\d+\]: Failed (?:password|publickey) for (?:invalid user )?"
    r"(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port \d+"
)
SSH_ACCEPTED = re.compile(
    r"sshd\[\d+\]: Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+) port \d+"
)


def _parse_syslog_time(line: str, year: int) -> datetime | None:
    if m := ISO_TS.match(line):
        return datetime.strptime(m["ts"], "%Y-%m-%dT%H:%M:%S")
    if m := SYSLOG_TS.match(line):
        # O syslog clássico não grava o ano; assumimos o ano informado.
        ts = re.sub(r"\s+", " ", m["ts"])
        return datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
    return None


def parse_auth_log(path: Path, year: int) -> list[AuthEvent]:
    """Lê um auth.log/secure do OpenSSH e devolve eventos de autenticação."""
    events: list[AuthEvent] = []
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if "sshd[" not in line:
                continue
            for regex, success in ((SSH_FAILED, False), (SSH_ACCEPTED, True)):
                m = regex.search(line)
                if not m:
                    continue
                ts = _parse_syslog_time(line, year)
                if ts is None:
                    break
                events.append(AuthEvent(ts, m["ip"], m["user"], success, "ssh"))
                break
    return events


# Nomes de coluna aceitos (Export-Csv do PowerShell, Event Viewer, SIEMs...)
WIN_COLUMNS = {
    "time": ("TimeCreated", "TimeGenerated", "Date and Time", "timestamp"),
    "event": ("Id", "EventID", "Event ID", "event_id"),
    "user": ("TargetUserName", "Account Name", "user"),
    "ip": ("IpAddress", "Source Network Address", "source_ip"),
}
WIN_TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
)


def _pick(row: dict, key: str) -> str:
    for name in WIN_COLUMNS[key]:
        if row.get(name):
            return row[name].strip()
    return ""


def _parse_win_time(value: str) -> datetime | None:
    value = value.split(".")[0].replace("Z", "")
    for fmt in WIN_TIME_FORMATS:
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return None


def parse_windows_csv(path: Path) -> list[AuthEvent]:
    """Lê um CSV de eventos 4624/4625 do Windows Security Log."""
    events: list[AuthEvent] = []
    with path.open(encoding="utf-8-sig", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            event_id = _pick(row, "event")
            if event_id not in ("4624", "4625"):
                continue
            ip = _pick(row, "ip")
            ts = _parse_win_time(_pick(row, "time"))
            if not ip or ip in ("-", "::1", "127.0.0.1") or ts is None:
                continue
            events.append(
                AuthEvent(ts, ip, _pick(row, "user") or "-", event_id == "4624", "windows")
            )
    return events


def load_events(path: Path, year: int) -> list[AuthEvent]:
    if path.suffix.lower() == ".csv":
        return parse_windows_csv(path)
    return parse_auth_log(path, year)


# --------------------------------------------------------------------------- #
# Detecção
# --------------------------------------------------------------------------- #


def max_events_in_window(timestamps: list[datetime], window: int) -> int:
    """Maior quantidade de eventos dentro de qualquer janela deslizante de `window` segundos."""
    timestamps = sorted(timestamps)
    best = start = 0
    for end, ts in enumerate(timestamps):
        while (ts - timestamps[start]).total_seconds() > window:
            start += 1
        best = max(best, end - start + 1)
    return best


def detect(
    events: list[AuthEvent],
    threshold: int = 5,
    window: int = 60,
    spray_users: int = 5,
) -> list[Alert]:
    by_ip: dict[str, list[AuthEvent]] = defaultdict(list)
    for ev in events:
        by_ip[ev.source_ip].append(ev)

    alerts: list[Alert] = []
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e.timestamp)
        failures = [e for e in evs if not e.success]
        if not failures:
            continue

        burst = max_events_in_window([e.timestamp for e in failures], window)
        users = sorted({e.username for e in failures})
        is_spray = len(users) >= spray_users
        is_brute = burst >= threshold
        if not (is_brute or is_spray):
            continue

        # Login com sucesso depois da primeira falha = possível conta comprometida
        first_fail = failures[0].timestamp
        compromised = sorted({e.username for e in evs if e.success and e.timestamp >= first_fail})

        if compromised:
            severity, technique = "CRITICAL", "T1110 -> T1078"
            desc = "Login bem-sucedido após série de falhas — possível conta comprometida"
        elif is_spray:
            severity, technique = "HIGH", "T1110.003"
            desc = f"Password spraying: {len(users)} usuários distintos testados"
        else:
            severity, technique = "MEDIUM", "T1110.001"
            desc = f"Força bruta: {burst} falhas em {window}s"

        alerts.append(
            Alert(
                source_ip=ip,
                severity=severity,
                technique=technique,
                description=desc,
                failures=len(failures),
                max_in_window=burst,
                distinct_users=len(users),
                first_seen=failures[0].timestamp.isoformat(sep=" "),
                last_seen=evs[-1].timestamp.isoformat(sep=" "),
                users_sample=users[:5],
                compromised_users=compromised,
            )
        )

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    alerts.sort(key=lambda a: (order[a.severity], -a.failures))
    return alerts


# --------------------------------------------------------------------------- #
# Saída
# --------------------------------------------------------------------------- #

COLORS = {"CRITICAL": "\033[1;31m", "HIGH": "\033[31m", "MEDIUM": "\033[33m"}
RESET = "\033[0m"


def render_table(alerts: list[Alert], total_events: int, color: bool) -> str:
    lines = [f"[*] {total_events} eventos de autenticação analisados", ""]
    if not alerts:
        lines.append("[+] Nenhuma atividade suspeita encontrada.")
        return "\n".join(lines)

    lines.append(f"[!] {len(alerts)} alerta(s) gerado(s)\n")
    header = f"{'SEVERIDADE':<10}  {'IP ORIGEM':<16}  {'FALHAS':>6}  {'PICO':>4}  "
    header += f"{'USERS':>5}  {'MITRE':<15}  DESCRIÇÃO"
    lines += [header, "-" * len(header) + "-" * 30]
    for a in alerts:
        sev = f"{a.severity:<10}"
        if color:
            sev = f"{COLORS[a.severity]}{sev}{RESET}"
        lines.append(
            f"{sev}  {a.source_ip:<16}  {a.failures:>6}  {a.max_in_window:>4}  "
            f"{a.distinct_users:>5}  {a.technique:<15}  {a.description}"
        )
        if a.compromised_users:
            lines.append(f"{'':12}└─ contas com login após falhas: {', '.join(a.compromised_users)}")
    return "\n".join(lines)


def write_csv(alerts: list[Alert], fh) -> None:
    writer = csv.DictWriter(fh, fieldnames=list(asdict(alerts[0]).keys()) if alerts else ["-"])
    writer.writeheader()
    for a in alerts:
        row = asdict(a)
        row["users_sample"] = ";".join(row["users_sample"])
        row["compromised_users"] = ";".join(row["compromised_users"])
        writer.writerow(row)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Detecta força bruta / password spraying em auth.log (SSH) ou CSV do Windows.",
    )
    p.add_argument("logfile", type=Path, help="auth.log, secure ou CSV de eventos 4624/4625")
    p.add_argument("-t", "--threshold", type=int, default=5,
                   help="falhas dentro da janela para gerar alerta (padrão: 5)")
    p.add_argument("-w", "--window", type=int, default=60,
                   help="tamanho da janela deslizante em segundos (padrão: 60)")
    p.add_argument("-s", "--spray-users", type=int, default=5,
                   help="usuários distintos por IP para caracterizar spraying (padrão: 5)")
    p.add_argument("-y", "--year", type=int, default=datetime.now().year,
                   help="ano dos logs syslog sem ano no timestamp (padrão: ano atual)")
    p.add_argument("-f", "--format", choices=("table", "json", "csv"), default="table")
    p.add_argument("-o", "--output", type=Path, help="salva o resultado em arquivo")
    p.add_argument("--no-color", action="store_true", help="desativa cores no terminal")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not args.logfile.is_file():
        print(f"[x] Arquivo não encontrado: {args.logfile}", file=sys.stderr)
        return 2

    events = load_events(args.logfile, args.year)
    alerts = detect(events, args.threshold, args.window, args.spray_users)

    out = args.output.open("w", encoding="utf-8", newline="") if args.output else sys.stdout
    try:
        if args.format == "json":
            json.dump([asdict(a) for a in alerts], out, indent=2, ensure_ascii=False)
            out.write("\n")
        elif args.format == "csv":
            write_csv(alerts, out)
        else:
            color = not args.no_color and not args.output and sys.stdout.isatty()
            out.write(render_table(alerts, len(events), color) + "\n")
    finally:
        if args.output:
            out.close()
            print(f"[+] Resultado salvo em {args.output}", file=sys.stderr)

    # Código de saída 1 quando há alertas — útil em pipelines/cron.
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
