#!/usr/bin/env python3
"""
ioc-extractor — extrai Indicadores de Comprometimento (IOCs) de texto livre.

Funciona com relatórios de threat intel, e-mails (.eml), logs, HTML, saída de
sandbox... Reconhece IOCs "defanged" (hxxp://, 1.2.3[.]4, evil[dot]com) e
pode devolvê-los defanged para colar com segurança em tickets e chats.

Tipos extraídos: ipv4, domain, url, email, md5, sha1, sha256, cve

Uso rápido:
  python extractor.py samples/threat_report.txt
  python extractor.py relatorio.txt --format json --output iocs.json
  cat phishing.eml | python extractor.py - --types ipv4,domain --format plain
  python extractor.py relatorio.txt --format plain | python ../ioc-checker/checker.py -
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
import sys
from pathlib import Path

IOC_TYPES = ("ipv4", "domain", "url", "email", "md5", "sha1", "sha256", "cve")

# --------------------------------------------------------------------------- #
# Refang / defang
# --------------------------------------------------------------------------- #

REFANG_RULES = [
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}"), "."),
    (re.compile(r"\[\s*dot\s*\]|\(\s*dot\s*\)", re.I), "."),
    (re.compile(r"\[\s*@\s*\]|\[\s*at\s*\]|\(\s*at\s*\)", re.I), "@"),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*/\s*\]"), "/"),
    (re.compile(r"\bhxxp(s?)", re.I), r"http\1"),
    (re.compile(r"\bfxp\b", re.I), "ftp"),
]


def refang(text: str) -> str:
    """Converte IOCs neutralizados de volta ao formato real (1.2.3[.]4 -> 1.2.3.4)."""
    for pattern, repl in REFANG_RULES:
        text = pattern.sub(repl, text)
    return text


def defang(ioc: str) -> str:
    """Neutraliza um IOC para que não vire link clicável (http -> hxxp, . -> [.])."""
    ioc = re.sub(r"^http", "hxxp", ioc, flags=re.I)
    ioc = ioc.replace("@", "[@]")
    # Só o último ponto do host vira [.] — padrão comum em relatórios de CTI
    if "://" in ioc:
        scheme, rest = ioc.split("://", 1)
        host, sep, path = rest.partition("/")
        return f"{scheme}://{_defang_host(host)}{sep}{path}"
    return _defang_host(ioc)


def _defang_host(host: str) -> str:
    head, dot, tail = host.rpartition(".")
    return f"{head}[.]{tail}" if dot else host


# --------------------------------------------------------------------------- #
# Expressões regulares
# --------------------------------------------------------------------------- #

RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'`\]\)]+", re.I)
RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,24}\b")
RE_DOMAIN = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}\b"
)
RE_SHA256 = re.compile(r"\b[A-Fa-f0-9]{64}\b")
RE_SHA1 = re.compile(r"\b[A-Fa-f0-9]{40}\b")
RE_MD5 = re.compile(r"\b[A-Fa-f0-9]{32}\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# Extensões de arquivo que casam com a regex de domínio (malware.exe, report.pdf...).
# Alguns são TLDs reais (.zip, .mov), mas no contexto de SOC quase sempre são arquivos.
FILE_EXTENSIONS = {
    "exe", "dll", "sys", "bat", "cmd", "ps1", "vbs", "js", "jse", "hta", "lnk", "scr",
    "msi", "jar", "py", "sh", "txt", "log", "csv", "json", "xml", "yml", "yaml", "ini",
    "cfg", "conf", "tmp", "dat", "bin", "doc", "docx", "docm", "xls", "xlsx", "xlsm",
    "ppt", "pptx", "pdf", "rtf", "zip", "rar", "7z", "gz", "tar", "iso", "img", "png",
    "jpg", "jpeg", "gif", "svg", "html", "htm", "php", "asp", "aspx", "eml", "msg",
    "md", "db", "sql", "pcap", "evtx", "mov", "mp4",
}

# gTLDs aceitos (ccTLDs de 2 letras são sempre aceitos). Evita falsos positivos como
# "header.from" ou "smtp.mailfrom" em cabeçalhos. Inclui os TLDs mais abusados em phishing.
KNOWN_GTLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "name", "pro", "mobi",
    "app", "dev", "io", "ai", "xyz", "top", "online", "site", "website", "club", "shop",
    "store", "tech", "cloud", "live", "life", "world", "today", "space", "fun", "icu",
    "buzz", "click", "link", "work", "email", "support", "services", "digital", "network",
    "host", "press", "news", "blog", "page", "win", "bid", "loan", "vip", "cyou", "rest",
    "monster", "lol", "sbs", "cfd", "bond", "quest", "beauty", "hair", "skin", "makeup",
    "asia", "help", "center", "company", "group", "solutions", "systems", "software",
    "security", "download", "zone", "one", "global", "ltd", "inc", "llc", "media",
    "agency", "studio", "design", "finance", "bank", "money", "pay", "cash", "credit",
    "exchange", "market", "trade", "capital", "fund", "pw", "tk", "ml", "ga", "cf", "gq",
}

# Domínios benignos que poluem a extração (schemas XML, assinaturas de e-mail...).
DEFAULT_ALLOWLIST = {
    "w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org", "purl.org",
    "attack.mitre.org", "mitre.org", "example.com", "example.org", "example.net",
}


def _is_allowlisted(domain: str, allowlist: set[str]) -> bool:
    domain = domain.lower()
    return any(domain == d or domain.endswith("." + d) for d in allowlist)


def _valid_ipv4(value: str, include_private: bool) -> bool:
    try:
        ip = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    if include_private:
        return True
    return ip.is_global


# --------------------------------------------------------------------------- #
# Extração
# --------------------------------------------------------------------------- #


def extract(
    text: str,
    include_private: bool = False,
    allowlist: set[str] | None = None,
) -> dict[str, list[str]]:
    """Extrai IOCs do texto e devolve um dicionário {tipo: [valores únicos]}."""
    allowlist = DEFAULT_ALLOWLIST if allowlist is None else allowlist
    text = refang(text)
    found: dict[str, dict[str, None]] = {t: {} for t in IOC_TYPES}  # dict = set ordenado

    def add(kind: str, value: str) -> None:
        found[kind].setdefault(value, None)

    # URLs primeiro; o host de cada URL também entra como domínio/IP.
    for url in RE_URL.findall(text):
        url = url.rstrip(".,;:!?")
        host = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/")[0].split(":")[0]
        if _is_allowlisted(host, allowlist):
            continue
        add("url", url)

    for email in RE_EMAIL.findall(text):
        if not _is_allowlisted(email.split("@")[1], allowlist):
            add("email", email.lower())

    for ip in RE_IPV4.findall(text):
        if _valid_ipv4(ip, include_private):
            add("ipv4", ip)

    # Remove a parte local dos e-mails para que "joao.silva@x.com" não gere "joao.silva"
    text_for_domains = RE_EMAIL.sub(lambda m: m.group(0).split("@")[1], text)
    for domain in RE_DOMAIN.findall(text_for_domains):
        domain = domain.lower()
        tld = domain.rsplit(".", 1)[-1]
        if len(tld) != 2 and tld not in KNOWN_GTLDS:
            continue
        if tld in FILE_EXTENSIONS or _is_allowlisted(domain, allowlist):
            continue
        add("domain", domain)

    # Hashes: SHA256 antes de SHA1 antes de MD5 (\b impede sobreposição entre tamanhos)
    for kind, regex in (("sha256", RE_SHA256), ("sha1", RE_SHA1), ("md5", RE_MD5)):
        for h in regex.findall(text):
            add(kind, h.lower())

    for cve in RE_CVE.findall(text):
        add("cve", cve.upper())

    return {k: list(v) for k, v in found.items()}


# --------------------------------------------------------------------------- #
# Saída
# --------------------------------------------------------------------------- #


def _maybe_defang(kind: str, value: str, do_defang: bool) -> str:
    if do_defang and kind in ("ipv4", "domain", "url", "email"):
        return defang(value)
    return value


def render(iocs: dict[str, list[str]], fmt: str, do_defang: bool) -> str:
    if fmt == "json":
        data = {k: [_maybe_defang(k, v, do_defang) for v in vals] for k, vals in iocs.items()}
        return json.dumps(data, indent=2, ensure_ascii=False)

    if fmt == "plain":  # um IOC por linha — ideal para pipe no ioc-checker
        return "\n".join(
            _maybe_defang(k, v, do_defang) for k, vals in iocs.items() for v in vals
        )

    if fmt == "csv":
        from io import StringIO

        buf = StringIO()
        writer = csv.writer(buf, lineterminator="\n")
        writer.writerow(["type", "value"])
        for k, vals in iocs.items():
            for v in vals:
                writer.writerow([k, _maybe_defang(k, v, do_defang)])
        return buf.getvalue().rstrip("\n")

    # tabela/texto agrupado
    total = sum(len(v) for v in iocs.values())
    lines = [f"[*] {total} IOC(s) únicos extraídos\n"]
    for k, vals in iocs.items():
        if not vals:
            continue
        lines.append(f"── {k.upper()} ({len(vals)})")
        lines += [f"   {_maybe_defang(k, v, do_defang)}" for v in vals]
        lines.append("")
    return "\n".join(lines).rstrip()


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def read_inputs(paths: list[str]) -> str:
    chunks = []
    for p in paths:
        if p == "-":
            chunks.append(sys.stdin.read())
        else:
            chunks.append(Path(p).read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Extrai IOCs (IPs, domínios, URLs, hashes...) de texto.")
    p.add_argument("inputs", nargs="+", help="arquivo(s) de entrada ou '-' para stdin")
    p.add_argument("-t", "--types", default=",".join(IOC_TYPES),
                   help=f"tipos a extrair, separados por vírgula (padrão: todos — {','.join(IOC_TYPES)})")
    p.add_argument("-f", "--format", choices=("table", "json", "csv", "plain"), default="table")
    p.add_argument("-o", "--output", type=Path, help="salva o resultado em arquivo")
    p.add_argument("--defang", action="store_true", help="devolve IOCs neutralizados (hxxp, [.])")
    p.add_argument("--include-private", action="store_true",
                   help="inclui IPs privados/reservados (RFC 1918, loopback...)")
    p.add_argument("--allowlist", type=Path,
                   help="arquivo com domínios a ignorar (um por linha), somado à lista padrão")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    wanted = [t.strip().lower() for t in args.types.split(",") if t.strip()]
    invalid = set(wanted) - set(IOC_TYPES)
    if invalid:
        print(f"[x] Tipo(s) inválido(s): {', '.join(sorted(invalid))}", file=sys.stderr)
        return 2

    allowlist = set(DEFAULT_ALLOWLIST)
    if args.allowlist:
        allowlist |= {
            line.strip().lower()
            for line in args.allowlist.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }

    try:
        text = read_inputs(args.inputs)
    except FileNotFoundError as exc:
        print(f"[x] Arquivo não encontrado: {exc.filename}", file=sys.stderr)
        return 2

    iocs = extract(text, args.include_private, allowlist)
    iocs = {k: v for k, v in iocs.items() if k in wanted}
    result = render(iocs, args.format, args.defang)

    if args.output:
        args.output.write_text(result + "\n", encoding="utf-8")
        print(f"[+] Resultado salvo em {args.output}", file=sys.stderr)
    else:
        print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
