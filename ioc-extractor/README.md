# 🧲 IOC Extractor

Extrai **Indicadores de Comprometimento** de qualquer texto — relatórios de threat intel, e-mails, logs, HTML, saída de sandbox — e entrega uma lista limpa, deduplicada e pronta para bloquear ou enriquecer.

Acabou o "Ctrl+C / Ctrl+V" de IP por IP de um PDF de 20 páginas.

---

## ✨ Funcionalidades

- **Tipos extraídos:** `ipv4`, `domain`, `url`, `email`, `md5`, `sha1`, `sha256`, `cve`
- **Refang automático:** entende `hxxp://`, `1.2.3[.]4`, `evil[dot]com`, `user[at]domain.com`
- **Defang na saída** (`--defang`): cola IOCs em ticket/Slack/Teams sem virar link clicável
- **Redução de falso positivo:**
  - ignora IPs privados/reservados (RFC 1918, loopback, link-local) — use `--include-private` para manter
  - ignora "domínios" que são nomes de arquivo (`invoice.pdf`, `payload.exe`, `script.ps1`)
  - allowlist de domínios benignos (`w3.org`, `attack.mitre.org`, `example.com`...) + sua própria lista
- **Saídas:** tabela, JSON, CSV ou `plain` (um por linha — feito para *pipe*)

**Contexto MITRE ATT&CK:** apoio à análise de [T1566 — Phishing](https://attack.mitre.org/techniques/T1566/) e de infraestrutura de [C2 (TA0011)](https://attack.mitre.org/tactics/TA0011/) descrita em relatórios.

---

## 🚀 Como usar

```bash
# Saída agrupada por tipo
python extractor.py samples/threat_report.txt

# Só rede, defanged, pronto para colar no ticket
python extractor.py samples/threat_report.txt --types ipv4,domain,url --defang

# JSON para integrar com SOAR / outro script
python extractor.py samples/threat_report.txt --format json --output iocs.json

# Vários arquivos de uma vez, ou stdin
python extractor.py relatorio1.txt relatorio2.html phishing.eml
cat alerta_sandbox.txt | python extractor.py -
```

### 🔗 Integração com o `ioc-checker`

```bash
python extractor.py samples/threat_report.txt --types ipv4,domain,sha256 --format plain \
  | python ../ioc-checker/checker.py -
```

### Parâmetros

| Opção | Padrão | Descrição |
|---|---|---|
| `inputs` | — | Um ou mais arquivos, ou `-` para ler do stdin |
| `-t`, `--types` | todos | Tipos a extrair, separados por vírgula |
| `-f`, `--format` | `table` | `table`, `json`, `csv` ou `plain` |
| `-o`, `--output` | — | Salva o resultado em arquivo |
| `--defang` | — | Neutraliza IPs, domínios, URLs e e-mails na saída |
| `--include-private` | — | Mantém IPs privados/reservados |
| `--allowlist` | — | Arquivo com domínios extras a ignorar (um por linha, `#` = comentário) |

---

## 📸 Exemplo de saída

```text
$ python extractor.py samples/threat_report.txt
[*] 14 IOC(s) únicos extraídos

── IPV4 (2)
   185.220.101.47
   45.142.212.61

── DOMAIN (3)
   notafiscal-sefaz.com
   cdn-update.xyz
   update-checker.top

── URL (2)
   https://cdn-update.xyz/static/payload.bin
   http://45.142.212.61/gate.php

── EMAIL (2)
   financeiro@notafiscal-sefaz.com
   cobranca@notafiscal-sefaz.com

── MD5 (1)
   5d41402abc4b2a76b9719d911017c592

── SHA1 (1)
   aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d

── SHA256 (1)
   e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

── CVE (2)
   CVE-2024-3400
   CVE-2021-26855
```

Note o que ficou **de fora**: `10.20.30.42` (IP interno), `explorer.exe` / `NF-e_88213.pdf.lnk` (arquivos) e `attack.mitre.org` (allowlist).

```text
$ python extractor.py samples/threat_report.txt -t ipv4,domain --format plain --defang
185.220.101[.]47
45.142.212[.]61
notafiscal-sefaz[.]com
cdn-update[.]xyz
update-checker[.]top
```

---

## 🧪 Amostras (`samples/`)

| Arquivo | Conteúdo |
|---|---|
| `threat_report.txt` | Relatório de incidente fictício de phishing com IOCs defanged, misturados com ruído interno para validar os filtros |

## ⚠️ Limitações

- IPv6 ainda não é extraído.
- TLDs que também são extensões de arquivo (`.zip`, `.mov`) são descartados de propósito — revise manualmente se a campanha usar esses TLDs.
- Hashes de 32/40/64 caracteres hexadecimais podem casar com GUIDs ou tokens sem hífen; sempre valide no contexto.
