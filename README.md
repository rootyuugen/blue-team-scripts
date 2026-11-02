# 🛡️ Blue Team Scripts

[![CI](https://github.com/rootyuugen/blue-team-scripts/actions/workflows/ci.yml/badge.svg)](https://github.com/rootyuugen/blue-team-scripts/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)

Coleção de ferramentas em Python para **automatizar tarefas do dia a dia de um analista SOC**: triagem de phishing, enriquecimento de IOCs e detecção de ataques em logs de autenticação.

Cada ferramenta é **independente** (um único arquivo `.py`, sem framework), mas elas foram pensadas para **trabalhar em conjunto** via *pipe* — do e-mail suspeito até o veredito de reputação.

---

## 🧰 Ferramentas

| Ferramenta | O que faz | Entrada | MITRE ATT&CK |
|---|---|---|---|
| 🔐 [**brute-force-detector**](brute-force-detector/) | Detecta força bruta, password spraying e **login bem-sucedido após falhas** | `auth.log` (SSH) · CSV de eventos 4624/4625 do Windows | T1110.001 · T1110.003 · T1078 |
| 🔎 [**ioc-checker**](ioc-checker/) | Consulta reputação de IPs, domínios, URLs e hashes e gera um veredito consolidado | IOCs via argumento, arquivo ou stdin | TA0011 · T1583 |
| 🧲 [**ioc-extractor**](ioc-extractor/) | Extrai IOCs de relatórios, e-mails e logs, com refang/defang e filtro de falso positivo | `.txt` · `.eml` · `.html` · `.log` · stdin | T1566 · TA0011 |
| 📧 [**email-header-analyzer**](email-header-analyzer/) | Analisa SPF/DKIM/DMARC, spoofing de remetente, Reply-To e rota do e-mail | `.eml` ou headers em `.txt` | T1566 · T1672 |

---

## 🔗 Como as ferramentas se conectam

```text
                ┌──────────────────────────┐
  suspeito.eml ─►  email-header-analyzer   ├──► SPF/DKIM/DMARC, spoofing, IP de origem
       │        └──────────────────────────┘                    │
       │        ┌──────────────────────────┐                    ▼
       └───────►      ioc-extractor        ├──► URLs, domínios, hashes ──► ┌─────────────┐
                └──────────────────────────┘                               │ ioc-checker │──► MALICIOUS / CLEAN
                ┌──────────────────────────┐                               └─────────────┘
  auth.log ────►   brute-force-detector    ├──► IPs atacantes ──────────────────▲
                └──────────────────────────┘
```

Exemplo real de triagem de phishing em três comandos:

```bash
python email-header-analyzer/analyzer.py suspeito.eml
python ioc-extractor/extractor.py suspeito.eml --types url,domain,ipv4 --format plain > iocs.txt
python ioc-checker/checker.py -f iocs.txt --format csv -o enriquecido.csv
```

---

## ⚡ Início rápido

### 1. Clonar e instalar

```bash
git clone https://github.com/rootyuugen/blue-team-scripts.git
cd blue-team-scripts

python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configurar as chaves de API (só o `ioc-checker` precisa)

```bash
cp .env.example .env               # Windows: copy .env.example .env
```

Edite o `.env` e cole as chaves gratuitas de [VirusTotal](https://www.virustotal.com/gui/my-apikey), [AbuseIPDB](https://www.abuseipdb.com/account/api) e/ou [AlienVault OTX](https://otx.alienvault.com/api).

> 🔒 O `.env` está no `.gitignore` — chaves **nunca** vão para o repositório.

### 3. Testar com as amostras incluídas

```bash
python brute-force-detector/detector.py brute-force-detector/samples/auth.log
python ioc-extractor/extractor.py ioc-extractor/samples/threat_report.txt
python email-header-analyzer/analyzer.py email-header-analyzer/samples/phishing_sample.eml
python ioc-checker/checker.py -f ioc-checker/samples/iocs.txt
```

---

## 📐 Padrões seguidos em todas as ferramentas

| Padrão | Por quê |
|---|---|
| CLI com `argparse` e `--help` em português | Fácil de usar e de documentar |
| Saída em **tabela**, **JSON** e **CSV** (`--format`) | Humano lê a tabela; SIEM/SOAR consome o JSON; o ticket recebe o CSV |
| Leitura de **stdin** (`-`) | Permite encadear ferramentas com `\|` |
| **Códigos de saída** consistentes (`0` ok · `1` achado · `2` erro) | Uso em `cron`, scripts e pipelines |
| Mapeamento **MITRE ATT&CK** | Linguagem comum entre SOC, CTI e resposta a incidentes |
| Segredos em `.env`, nunca no código | Boa prática básica de segurança |
| Amostras em `samples/` | Qualquer pessoa testa sem precisar de dados reais |

---

## 🗂️ Estrutura

```text
blue-team-scripts/
├── README.md
├── LICENSE
├── .env.example                 ← modelo das chaves de API (sem valores)
├── requirements.txt             ← dependências de execução
├── requirements-dev.txt         ← + pytest e ruff
├── pyproject.toml               ← configuração de lint e testes
├── .github/workflows/ci.yml     ← CI: lint + testes a cada push
├── brute-force-detector/
│   ├── README.md
│   ├── detector.py
│   └── samples/                 ← auth.log e CSV do Windows
├── ioc-checker/
│   ├── README.md
│   ├── checker.py
│   └── samples/
├── ioc-extractor/
│   ├── README.md
│   ├── extractor.py
│   └── samples/
├── email-header-analyzer/
│   ├── README.md
│   ├── analyzer.py
│   └── samples/                 ← .eml de phishing e legítimo
└── tests/                       ← testes unitários (pytest)
```

---

## 🧪 Desenvolvimento

```bash
pip install -r requirements-dev.txt
ruff check .        # lint
pytest -v           # testes
```

O mesmo fluxo roda automaticamente no **GitHub Actions** a cada push e pull request.

---

## 🗺️ Roadmap

- [ ] `brute-force-detector`: detecção de ataques distribuídos (agregação por usuário) e suporte a logs de RDP/VPN
- [ ] `ioc-checker`: cache local para não repetir consultas e integração com Shodan / URLScan
- [ ] `ioc-extractor`: suporte a IPv6 e leitura direta de PDF
- [ ] `email-header-analyzer`: extração e hash de anexos
- [ ] Versões em PowerShell para ambientes Windows sem Python

---

## ⚠️ Aviso

Ferramentas criadas para **fins educacionais e defensivos**. Use apenas em sistemas e dados que você tem autorização para analisar. Os logs e e-mails em `samples/` são simulados e usam domínios fictícios e, sempre que possível, IPs de documentação (RFC 5737).

---

[![GitHub](https://img.shields.io/badge/GitHub-rootyuugen-181717?logo=github)](https://github.com/rootyuugen)

Licenciado sob a [MIT License](LICENSE).
