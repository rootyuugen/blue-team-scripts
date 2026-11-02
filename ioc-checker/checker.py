#!/usr/bin/env python3
"""
ioc-checker — consulta a reputação de IOCs em fontes de threat intelligence.

Fontes:
  * VirusTotal  (IP, domínio, URL, hash)   — VT_API_KEY
  * AbuseIPDB   (IP)                        — ABUSEIPDB_API_KEY
  * AlienVault OTX (IP, domínio, URL, hash) — OTX_API_KEY

As chaves são lidas do arquivo .env na raiz do repositório (veja .env.example).
Fontes sem chave configurada são simplesmente puladas.

Uso rápido:
  python checker.py 185.220.101.47 evil.com 44d88612fea8a8f36de82e1278abb02f
  python checker.py -f samples/iocs.txt --format csv --output resultado.csv
  python ../ioc-extractor/extractor.py relatorio.txt --format plain | python checker.py -
"""

from __future__ import annotations

import argparse
import base64
import csv
import ipaddress
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

import requests
from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parent.parent
load_dotenv(REPO_ROOT / ".env")
load_dotenv()  # também aceita um .env no diretório atual

TIMEOUT = 15
USER_AGENT = "blue-team-scripts/ioc-checker"

# --------------------------------------------------------------------------- #
# Classificação do IOC
# --------------------------------------------------------------------------- #

RE_DOMAIN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$", re.I)
RE_HASH = {32: "md5", 40: "sha1", 64: "sha256"}


def refang(value: str) -> str:
    value = value.strip()
    value = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\[dot\]", ".", value, flags=re.I)
    value = re.sub(r"^hxxp", "http", value, flags=re.I)
    return value.replace("[:]", ":")


def classify(ioc: str) -> str | None:
    """Devolve o tipo do IOC: ip, domain, url, md5, sha1, sha256 — ou None se inválido."""
    if re.match(r"^(?:https?|ftp)://", ioc, re.I):
        return "url"
    try:
        ipaddress.ip_address(ioc)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[A-Fa-f0-9]+", ioc) and len(ioc) in RE_HASH:
        return RE_HASH[len(ioc)]
    if RE_DOMAIN.match(ioc):
        return "domain"
    return None


def is_private_ip(ioc: str) -> bool:
    try:
        return not ipaddress.ip_address(ioc).is_global
    except ValueError:
        return False


# --------------------------------------------------------------------------- #
# Resultado
# --------------------------------------------------------------------------- #


@dataclass
class Result:
    ioc: str
    type: str
    verdict: str = "UNKNOWN"
    vt_malicious: int | None = None
    vt_suspicious: int | None = None
    vt_total: int | None = None
    abuse_score: int | None = None
    abuse_reports: int | None = None
    otx_pulses: int | None = None
    country: str | None = None
    owner: str | None = None
    errors: list[str] = field(default_factory=list)


def compute_verdict(r: Result) -> str:
    """Regras simples e explicáveis — ajuste os limiares à realidade do seu SOC."""
    if all(v is None for v in (r.vt_malicious, r.abuse_score, r.otx_pulses)):
        return "UNKNOWN"
    vt_mal = r.vt_malicious or 0
    vt_sus = r.vt_suspicious or 0
    abuse = r.abuse_score or 0
    pulses = r.otx_pulses or 0
    if vt_mal >= 5 or abuse >= 75:
        return "MALICIOUS"
    if vt_mal >= 1 or vt_sus >= 2 or abuse >= 25 or pulses >= 1:
        return "SUSPICIOUS"
    return "CLEAN"


# --------------------------------------------------------------------------- #
# Fontes de threat intel
# --------------------------------------------------------------------------- #


class Source:
    name = "base"
    env_key = ""
    supports: tuple[str, ...] = ()

    def __init__(self, session: requests.Session):
        self.session = session
        self.api_key = os.getenv(self.env_key, "").strip()

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _get(self, url: str, **kwargs) -> dict | None:
        resp = self.session.get(url, timeout=TIMEOUT, **kwargs)
        if resp.status_code == 404:
            return None  # IOC desconhecido pela fonte
        if resp.status_code == 401:
            raise RuntimeError(f"{self.name}: chave de API inválida")
        if resp.status_code == 429:
            raise RuntimeError(f"{self.name}: limite de requisições atingido (429)")
        resp.raise_for_status()
        return resp.json()

    def lookup(self, ioc: str, kind: str, result: Result) -> None:
        raise NotImplementedError


class VirusTotal(Source):
    name = "VirusTotal"
    env_key = "VT_API_KEY"
    supports = ("ip", "domain", "url", "md5", "sha1", "sha256")
    base = "https://www.virustotal.com/api/v3"

    def lookup(self, ioc: str, kind: str, result: Result) -> None:
        if kind == "ip":
            endpoint = f"ip_addresses/{ioc}"
        elif kind == "domain":
            endpoint = f"domains/{ioc}"
        elif kind == "url":
            url_id = base64.urlsafe_b64encode(ioc.encode()).decode().rstrip("=")
            endpoint = f"urls/{url_id}"
        else:
            endpoint = f"files/{ioc}"

        data = self._get(f"{self.base}/{endpoint}", headers={"x-apikey": self.api_key})
        if data is None:
            result.vt_malicious, result.vt_suspicious, result.vt_total = 0, 0, 0
            return
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        result.vt_malicious = stats.get("malicious", 0)
        result.vt_suspicious = stats.get("suspicious", 0)
        result.vt_total = sum(stats.values()) if stats else 0
        result.country = result.country or attrs.get("country")
        result.owner = result.owner or attrs.get("as_owner") or attrs.get("registrar")


class AbuseIPDB(Source):
    name = "AbuseIPDB"
    env_key = "ABUSEIPDB_API_KEY"
    supports = ("ip",)
    url = "https://api.abuseipdb.com/api/v2/check"

    def lookup(self, ioc: str, kind: str, result: Result) -> None:
        data = self._get(
            self.url,
            headers={"Key": self.api_key, "Accept": "application/json"},
            params={"ipAddress": ioc, "maxAgeInDays": 90},
        )
        d = (data or {}).get("data", {})
        result.abuse_score = d.get("abuseConfidenceScore", 0)
        result.abuse_reports = d.get("totalReports", 0)
        result.country = d.get("countryCode") or result.country
        result.owner = d.get("isp") or result.owner


class OTX(Source):
    name = "AlienVault OTX"
    env_key = "OTX_API_KEY"
    supports = ("ip", "domain", "url", "md5", "sha1", "sha256")
    base = "https://otx.alienvault.com/api/v1/indicators"

    def lookup(self, ioc: str, kind: str, result: Result) -> None:
        section = {
            "ip": "IPv6" if ":" in ioc else "IPv4",
            "domain": "domain",
            "url": "url",
        }.get(kind, "file")
        data = self._get(
            f"{self.base}/{section}/{ioc}/general", headers={"X-OTX-API-KEY": self.api_key}
        )
        result.otx_pulses = (data or {}).get("pulse_info", {}).get("count", 0)


SOURCES = (VirusTotal, AbuseIPDB, OTX)


# --------------------------------------------------------------------------- #
# Orquestração
# --------------------------------------------------------------------------- #


def check_iocs(
    iocs: list[str], delay: float, include_private: bool, verbose: bool = True
) -> list[Result] | None:
    session = requests.Session()
    session.headers["User-Agent"] = USER_AGENT
    sources = [cls(session) for cls in SOURCES]
    active = [s for s in sources if s.enabled]

    if not active:
        print("[x] Nenhuma chave de API configurada. Copie .env.example para .env "
              "e preencha ao menos uma chave.", file=sys.stderr)
        return None
    if verbose:
        names = ", ".join(s.name for s in active)
        print(f"[*] Fontes ativas: {names}", file=sys.stderr)

    results: list[Result] = []
    for i, raw in enumerate(iocs):
        ioc = refang(raw)
        kind = classify(ioc)
        if kind is None:
            if verbose:
                print(f"[-] Ignorado (formato não reconhecido): {raw}", file=sys.stderr)
            continue
        if kind == "ip" and is_private_ip(ioc) and not include_private:
            if verbose:
                print(f"[-] Ignorado (IP privado/reservado): {ioc}", file=sys.stderr)
            continue

        if verbose:
            print(f"[{i + 1}/{len(iocs)}] {ioc} ({kind})", file=sys.stderr)
        result = Result(ioc=ioc, type=kind)
        for src in active:
            if kind not in src.supports:
                continue
            try:
                src.lookup(ioc, kind, result)
            except (requests.RequestException, RuntimeError, ValueError) as exc:
                result.errors.append(f"{src.name}: {exc}")
        result.verdict = compute_verdict(result)
        results.append(result)

        if delay and i < len(iocs) - 1:
            time.sleep(delay)
    return results


# --------------------------------------------------------------------------- #
# Saída
# --------------------------------------------------------------------------- #

COLORS = {
    "MALICIOUS": "\033[1;31m",
    "SUSPICIOUS": "\033[33m",
    "CLEAN": "\033[32m",
    "UNKNOWN": "\033[90m",
}
RESET = "\033[0m"


def _fmt(value) -> str:
    return "-" if value is None else str(value)


def render_table(results: list[Result], color: bool) -> str:
    if not results:
        return "[*] Nenhum resultado."
    header = (f"{'VEREDITO':<11} {'TIPO':<7} {'IOC':<45} {'VT':>7} "
              f"{'ABUSE':>5} {'OTX':>4}  {'PAÍS':<4} DONO/ASN")
    lines = [header, "-" * (len(header) + 10)]
    for r in results:
        vt = f"{r.vt_malicious}/{r.vt_total}" if r.vt_malicious is not None else "-"
        verdict = f"{r.verdict:<11}"
        if color:
            verdict = f"{COLORS[r.verdict]}{verdict}{RESET}"
        ioc = r.ioc if len(r.ioc) <= 45 else r.ioc[:42] + "..."
        owner = (r.owner or "-")[:30]
        lines.append(
            f"{verdict} {r.type:<7} {ioc:<45} {vt:>7} {_fmt(r.abuse_score):>5} "
            f"{_fmt(r.otx_pulses):>4}  {_fmt(r.country):<4} {owner}"
        )
        for err in r.errors:
            lines.append(f"{'':20}└─ ⚠ {err}")

    counts = {v: sum(r.verdict == v for r in results) for v in COLORS}
    summary = " | ".join(f"{k}: {v}" for k, v in counts.items() if v)
    lines += ["", f"[*] Resumo — {summary}"]
    return "\n".join(lines)


def write_csv(results: list[Result], fh) -> None:
    fields = list(Result.__dataclass_fields__)
    writer = csv.DictWriter(fh, fieldnames=fields)
    writer.writeheader()
    for r in results:
        row = asdict(r)
        row["errors"] = "; ".join(row["errors"])
        writer.writerow(row)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def collect_iocs(args) -> list[str]:
    items: list[str] = []
    for value in args.iocs:
        if value == "-":
            items += sys.stdin.read().split()
        else:
            items.append(value)
    if args.file:
        for line in args.file.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                items.append(line)
    # remove duplicados preservando a ordem
    return list(dict.fromkeys(items))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Consulta reputação de IPs, domínios, URLs e hashes "
                    "(VirusTotal, AbuseIPDB, AlienVault OTX)."
    )
    p.add_argument("iocs", nargs="*", help="IOCs a consultar, ou '-' para ler do stdin")
    p.add_argument("-f", "--file", type=Path, help="arquivo com um IOC por linha (# = comentário)")
    p.add_argument("-d", "--delay", type=float, default=15.0,
                   help="segundos entre IOCs; o plano free do VirusTotal permite 4 req/min "
                        "(padrão: 15)")
    p.add_argument("--format", choices=("table", "json", "csv"), default="table")
    p.add_argument("-o", "--output", type=Path, help="salva o resultado em arquivo")
    p.add_argument("--include-private", action="store_true", help="consulta IPs privados também")
    p.add_argument("--no-color", action="store_true", help="desativa cores no terminal")
    p.add_argument("-q", "--quiet", action="store_true", help="não mostra o progresso no stderr")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    iocs = collect_iocs(args)
    if not iocs:
        parser.error("informe ao menos um IOC (argumento, --file ou '-' para stdin)")

    results = check_iocs(iocs, args.delay, args.include_private, verbose=not args.quiet)
    if results is None:
        return 2

    out = args.output.open("w", encoding="utf-8", newline="") if args.output else sys.stdout
    try:
        if args.format == "json":
            json.dump([asdict(r) for r in results], out, indent=2, ensure_ascii=False)
            out.write("\n")
        elif args.format == "csv":
            write_csv(results, out)
        else:
            color = not args.no_color and not args.output and sys.stdout.isatty()
            out.write(render_table(results, color) + "\n")
    finally:
        if args.output:
            out.close()
            print(f"[+] Resultado salvo em {args.output}", file=sys.stderr)

    # 1 = algum IOC malicioso/suspeito (útil para automação)
    return 1 if any(r.verdict in ("MALICIOUS", "SUSPICIOUS") for r in results) else 0


if __name__ == "__main__":
    sys.exit(main())
