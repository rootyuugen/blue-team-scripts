#!/usr/bin/env python3
"""
email-header-analyzer — analisa cabeçalhos de e-mail em busca de phishing e spoofing.

Verifica:
  * Autenticação: SPF, DKIM e DMARC (Authentication-Results / Received-SPF)
  * Alinhamento: From x Return-Path x Reply-To x DKIM d= x Message-ID
  * Display name enganoso ("PayPal <x@dominio-qualquer.com>")
  * Rota (Received): saltos, IPs de origem e atrasos entre servidores

MITRE ATT&CK:
  * T1566     — Phishing (.001 anexo / .002 link)
  * T1672     — Email Spoofing

Uso rápido:
  python analyzer.py samples/phishing_sample.eml
  python analyzer.py samples/phishing_sample.eml --format json
  python analyzer.py cabecalho.txt            # também aceita só os headers colados em .txt
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime
from email import policy
from email.message import Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from pathlib import Path

# --------------------------------------------------------------------------- #
# Modelos
# --------------------------------------------------------------------------- #


@dataclass
class Hop:
    index: int
    from_host: str
    by_host: str
    ips: list[str]
    timestamp: str | None
    delay_seconds: int | None = None


@dataclass
class Finding:
    severity: str  # INFO, LOW, MEDIUM, HIGH
    title: str
    detail: str
    points: int


@dataclass
class Report:
    subject: str
    date: str
    from_address: str
    from_display: str
    return_path: str
    reply_to: str
    message_id: str
    x_mailer: str
    spf: str
    dkim: str
    dmarc: str
    dkim_domain: str
    origin_ip: str | None
    public_ips: list[str]
    hops: list[Hop] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    score: int = 0
    risk: str = "LOW"


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

RE_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
RE_AUTH = {
    k: re.compile(rf"\b{k}\s*=\s*(\w+)", re.I) for k in ("spf", "dkim", "dmarc")
}
RE_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@([\w-]+\.)+[a-z]{2,}", re.I)
# Marcas frequentemente usadas em display name de phishing -> domínios legítimos.
# Adicione a sua própria empresa aqui para detectar personificação interna.
BRANDS: dict[str, tuple[str, ...]] = {
    "microsoft": ("microsoft.com", "office.com", "outlook.com", "microsoftonline.com"),
    "office 365": ("microsoft.com", "office.com", "office365.com"),
    "outlook": ("microsoft.com", "outlook.com"),
    "paypal": ("paypal.com", "paypal.com.br"),
    "apple": ("apple.com", "icloud.com"),
    "google": ("google.com", "gmail.com"),
    "amazon": ("amazon.com", "amazon.com.br"),
    "netflix": ("netflix.com",),
    "docusign": ("docusign.com", "docusign.net"),
    "itau": ("itau.com.br",),
    "itaú": ("itau.com.br",),
    "bradesco": ("bradesco.com.br",),
    "santander": ("santander.com.br",),
    "caixa": ("caixa.gov.br",),
    "banco do brasil": ("bb.com.br",),
    "nubank": ("nubank.com.br",),
    "correios": ("correios.com.br",),
    "receita federal": ("receita.fazenda.gov.br", "gov.br"),
    "mercado livre": ("mercadolivre.com.br", "mercadolivre.com"),
}


def domain_of(address: str) -> str:
    address = parseaddr(address)[1] or address
    return address.rsplit("@", 1)[-1].strip(" <>").lower() if "@" in address else ""


def org_domain(domain: str) -> str:
    """Aproximação do domínio organizacional (sem Public Suffix List): últimos 2 rótulos,
    ou 3 para sufixos como .com.br / .co.uk."""
    parts = domain.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"com", "net", "org", "gov", "edu", "co"} \
            and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def aligned(d1: str, d2: str) -> bool:
    return bool(d1 and d2) and org_domain(d1) == org_domain(d2)


def is_public(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def header(msg: Message, name: str) -> str:
    value = msg.get(name)
    return str(value).strip() if value is not None else ""


# --------------------------------------------------------------------------- #
# Análise
# --------------------------------------------------------------------------- #


def parse_received(values: list[str]) -> list[Hop]:
    """Converte os headers Received (do mais novo p/ o mais antigo) em saltos cronológicos."""
    hops: list[Hop] = []
    for i, raw in enumerate(reversed(values), start=1):
        raw = " ".join(raw.split())
        from_host = re.search(r"\bfrom\s+(\S+)", raw, re.I)
        by_host = re.search(r"\bby\s+(\S+)", raw, re.I)
        # Só os IPs da cláusula "from" (antes do "by") identificam quem entregou
        from_part = re.split(r"\bby\s", raw, maxsplit=1, flags=re.I)[0]
        ips = list(dict.fromkeys(RE_IP.findall(from_part)))

        ts = None
        if ";" in raw:
            try:
                ts = parsedate_to_datetime(raw.rsplit(";", 1)[1].strip())
            except (TypeError, ValueError):
                ts = None
        hops.append(Hop(
            index=i,
            from_host=from_host[1] if from_host else "-",
            by_host=by_host[1] if by_host else "-",
            ips=ips,
            timestamp=ts.isoformat() if ts else None,
        ))

    prev: datetime | None = None
    for hop in hops:
        cur = datetime.fromisoformat(hop.timestamp) if hop.timestamp else None
        if prev and cur and prev.tzinfo and cur.tzinfo:
            hop.delay_seconds = int((cur - prev).total_seconds())
        prev = cur or prev
    return hops


def auth_results(msg: Message) -> dict[str, str]:
    results = {"spf": "none", "dkim": "none", "dmarc": "none"}
    # Usamos o Authentication-Results mais recente (o do nosso próprio servidor, no topo)
    auth_headers = msg.get_all("Authentication-Results") or []
    if auth_headers:
        text = str(auth_headers[0])
        for key, regex in RE_AUTH.items():
            if m := regex.search(text):
                results[key] = m[1].lower()
    if results["spf"] == "none" and (rspf := header(msg, "Received-SPF")):
        results["spf"] = rspf.split()[0].lower()
    return results


def dkim_signing_domain(msg: Message) -> str:
    sig = header(msg, "DKIM-Signature")
    m = re.search(r"\bd=([^;\s]+)", sig)
    return m[1].lower() if m else ""


def analyze(msg: Message) -> Report:
    from_display, from_addr = parseaddr(header(msg, "From"))
    return_path = parseaddr(header(msg, "Return-Path"))[1]
    reply_to = ", ".join(a for _, a in getaddresses([header(msg, "Reply-To")]) if a)
    message_id = header(msg, "Message-ID")
    auth = auth_results(msg)
    dkim_d = dkim_signing_domain(msg)
    hops = parse_received(msg.get_all("Received") or [])

    public_ips = list(dict.fromkeys(ip for h in hops for ip in h.ips if is_public(ip)))
    x_orig = RE_IP.findall(header(msg, "X-Originating-IP"))
    origin_ip = x_orig[0] if x_orig else (public_ips[0] if public_ips else None)

    report = Report(
        subject=header(msg, "Subject"),
        date=header(msg, "Date"),
        from_address=from_addr,
        from_display=from_display,
        return_path=return_path,
        reply_to=reply_to,
        message_id=message_id,
        x_mailer=header(msg, "X-Mailer") or header(msg, "User-Agent"),
        spf=auth["spf"],
        dkim=auth["dkim"],
        dmarc=auth["dmarc"],
        dkim_domain=dkim_d,
        origin_ip=origin_ip,
        public_ips=public_ips,
        hops=hops,
    )
    report.findings = run_checks(report)
    report.score = sum(f.points for f in report.findings)
    report.risk = "HIGH" if report.score >= 60 else "MEDIUM" if report.score >= 30 else "LOW"
    return report


def run_checks(r: Report) -> list[Finding]:
    f: list[Finding] = []
    from_dom = domain_of(r.from_address)

    # --- Autenticação ---------------------------------------------------------
    if r.spf in ("fail", "softfail"):
        f.append(Finding("HIGH" if r.spf == "fail" else "MEDIUM", f"SPF {r.spf}",
                         "O servidor de origem não está autorizado a enviar pelo domínio do "
                         "envelope.", 25 if r.spf == "fail" else 15))
    elif r.spf in ("none", "neutral", "temperror", "permerror"):
        f.append(Finding("LOW", f"SPF {r.spf}", "Sem validação SPF conclusiva.", 5))

    if r.dkim in ("fail", "permerror"):
        f.append(Finding("HIGH", "DKIM fail",
                         "Assinatura DKIM inválida — conteúdo alterado ou forjado.", 20))
    elif r.dkim == "none":
        f.append(Finding("LOW", "Sem DKIM", "Mensagem não assinada.", 5))

    if r.dmarc == "fail":
        f.append(Finding("HIGH", "DMARC fail",
                         "From não está alinhado com SPF nem DKIM — típico de spoofing.", 25))

    # --- Alinhamento de domínios ---------------------------------------------
    rp_dom = domain_of(r.return_path)
    if rp_dom and from_dom and not aligned(rp_dom, from_dom):
        f.append(Finding("MEDIUM", "Return-Path diferente do From",
                         f"From: {from_dom}  |  Return-Path: {rp_dom}", 15))

    for addr in filter(None, (a.strip() for a in r.reply_to.split(","))):
        rt_dom = domain_of(addr)
        if rt_dom and from_dom and not aligned(rt_dom, from_dom):
            f.append(Finding("HIGH", "Reply-To aponta para outro domínio",
                             f"As respostas irão para {addr} (From: {from_dom}).", 20))
            break

    if r.dkim_domain and from_dom and not aligned(r.dkim_domain, from_dom):
        f.append(Finding("LOW", "DKIM assinado por outro domínio",
                         f"d={r.dkim_domain} (comum em ESPs; suspeito se não reconhecido).", 5))

    mid_dom = r.message_id.strip("<>").rsplit("@", 1)[-1].lower() if "@" in r.message_id else ""
    if mid_dom and from_dom and not aligned(mid_dom, from_dom):
        f.append(Finding("INFO", "Message-ID de outro domínio",
                         f"Message-ID gerado por {mid_dom}.", 3))

    # --- Display name ----------------------------------------------------------
    display = r.from_display.lower()
    if m := RE_EMAIL_IN_TEXT.search(display):
        shown = domain_of(m[0])
        if shown and not aligned(shown, from_dom):
            f.append(Finding("HIGH", "Display name contém outro e-mail",
                             f"Exibe '{m[0]}' mas o remetente real é {r.from_address}.", 25))
    for brand, legit in BRANDS.items():
        if brand in display and not any(
            from_dom == d or from_dom.endswith("." + d) for d in legit
        ):
            f.append(Finding("MEDIUM", "Possível personificação de marca",
                             f"Display name cita '{brand}', mas o domínio é {from_dom}.", 15))
            break

    # --- Rota -------------------------------------------------------------------
    for hop in r.hops:
        if hop.delay_seconds is not None and hop.delay_seconds < -60:
            f.append(Finding("LOW", "Timestamp fora de ordem",
                             f"Salto {hop.index} tem horário anterior ao salto anterior "
                             f"({hop.delay_seconds}s) — relógio errado ou header forjado.", 5))
            break
    if not r.hops:
        f.append(Finding("INFO", "Sem headers Received",
                         "Não é possível reconstruir a rota da mensagem.", 0))

    return f


# --------------------------------------------------------------------------- #
# Saída
# --------------------------------------------------------------------------- #

SEV_COLORS = {"HIGH": "\033[31m", "MEDIUM": "\033[33m", "LOW": "\033[36m", "INFO": "\033[90m"}
RESET = "\033[0m"


def _status(value: str) -> str:
    return {"pass": "✅ pass", "fail": "❌ fail", "softfail": "⚠️  softfail"}.get(value, f"➖ {value}")


def render_text(r: Report, color: bool) -> str:
    def c(sev: str, text: str) -> str:
        return f"{SEV_COLORS.get(sev, '')}{text}{RESET}" if color else text

    lines = [
        "═" * 70,
        "  ANÁLISE DE CABEÇALHO DE E-MAIL",
        "═" * 70,
        f"  Assunto     : {r.subject}",
        f"  Data        : {r.date}",
        f"  From        : {r.from_display + ' ' if r.from_display else ''}<{r.from_address}>",
        f"  Return-Path : {r.return_path or '-'}",
        f"  Reply-To    : {r.reply_to or '-'}",
        f"  Message-ID  : {r.message_id or '-'}",
        f"  X-Mailer    : {r.x_mailer or '-'}",
        "",
        "── AUTENTICAÇÃO " + "─" * 54,
        f"  SPF   : {_status(r.spf)}",
        f"  DKIM  : {_status(r.dkim)}" + (f"  (d={r.dkim_domain})" if r.dkim_domain else ""),
        f"  DMARC : {_status(r.dmarc)}",
        "",
        "── ROTA (origem → destino) " + "─" * 43,
    ]
    for h in r.hops:
        delay = f"+{h.delay_seconds}s" if h.delay_seconds is not None else ""
        ips = ", ".join(h.ips) or "-"
        lines.append(f"  [{h.index}] {h.from_host}  ({ips})")
        lines.append(f"       └─ por {h.by_host}  {delay}".rstrip())
    lines += [
        "",
        f"  IP de origem provável : {r.origin_ip or '-'}",
        f"  IPs públicos na rota  : {', '.join(r.public_ips) or '-'}",
        "",
        "── ACHADOS " + "─" * 59,
    ]
    if not r.findings:
        lines.append("  Nenhum indicador suspeito.")
    for fd in sorted(r.findings, key=lambda x: -x.points):
        lines.append(f"  {c(fd.severity, f'[{fd.severity:<6}]')} {fd.title}")
        lines.append(f"            {fd.detail}")

    risk_sev = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}[r.risk]
    lines += [
        "",
        "═" * 70,
        f"  RISCO: {c(risk_sev, r.risk)}  (score {r.score})",
        "═" * 70,
    ]
    if r.public_ips:
        lines.append(f"\n  Próximo passo: python ../ioc-checker/checker.py {' '.join(r.public_ips)}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def load_message(path: str) -> Message:
    data = sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()
    # Normaliza quebras de linha (headers colados de webmail vêm com \r\n ou \n)
    data = data.replace(b"\r\n", b"\n")
    return BytesParser(policy=policy.default).parsebytes(data, headersonly=True)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Analisa cabeçalhos de e-mail (.eml/.txt) "
                                            "em busca de phishing e spoofing.")
    p.add_argument("file", help="arquivo .eml / .txt com os headers, ou '-' para stdin")
    p.add_argument("-f", "--format", choices=("text", "json"), default="text")
    p.add_argument("-o", "--output", type=Path, help="salva o resultado em arquivo")
    p.add_argument("--no-color", action="store_true", help="desativa cores no terminal")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        msg = load_message(args.file)
    except FileNotFoundError:
        print(f"[x] Arquivo não encontrado: {args.file}", file=sys.stderr)
        return 2

    report = analyze(msg)
    if args.format == "json":
        result = json.dumps(asdict(report), indent=2, ensure_ascii=False)
    else:
        color = not args.no_color and not args.output and sys.stdout.isatty()
        result = render_text(report, color)

    if args.output:
        args.output.write_text(result + "\n", encoding="utf-8")
        print(f"[+] Resultado salvo em {args.output}", file=sys.stderr)
    else:
        print(result)
    return 1 if report.risk == "HIGH" else 0


if __name__ == "__main__":
    sys.exit(main())
