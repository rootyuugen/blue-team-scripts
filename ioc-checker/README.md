# 🔎 IOC Checker

Consulta a reputação de **IPs, domínios, URLs e hashes** em várias fontes de threat intelligence ao mesmo tempo e devolve um **veredito consolidado** — o primeiro passo da triagem de qualquer alerta.

---

## 🌐 Fontes integradas

| Fonte | IP | Domínio | URL | Hash | Variável no `.env` | Plano gratuito |
|---|:-:|:-:|:-:|:-:|---|---|
| [VirusTotal](https://www.virustotal.com) | ✅ | ✅ | ✅ | ✅ | `VT_API_KEY` | 4 req/min · 500/dia |
| [AbuseIPDB](https://www.abuseipdb.com) | ✅ | — | — | — | `ABUSEIPDB_API_KEY` | 1.000 checks/dia |
| [AlienVault OTX](https://otx.alienvault.com) | ✅ | ✅ | ✅ | ✅ | `OTX_API_KEY` | gratuito |

Fontes sem chave são **puladas automaticamente** — dá para começar só com uma.

**Contexto MITRE ATT&CK:** enriquecimento de infraestrutura adversária — [TA0011 Command and Control](https://attack.mitre.org/tactics/TA0011/), [T1583 Acquire Infrastructure](https://attack.mitre.org/techniques/T1583/) — e de artefatos de [TA0002 Execution](https://attack.mitre.org/tactics/TA0002/).

---

## ⚙️ Configuração

```bash
# Na raiz do repositório
cp .env.example .env
# edite o .env e cole suas chaves
```

> 🔒 O `.env` está no `.gitignore`. **Nunca** coloque chaves direto no código nem faça commit delas.

---

## 🚀 Como usar

```bash
# IOCs direto na linha de comando (aceita defanged)
python checker.py 185.220.101[.]47 example.com 44d88612fea8a8f36de82e1278abb02f

# A partir de arquivo (um por linha, '#' = comentário)
python checker.py -f samples/iocs.txt

# Exportar para anexar no ticket
python checker.py -f samples/iocs.txt --format csv  -o resultado.csv
python checker.py -f samples/iocs.txt --format json -o resultado.json

# Com chave premium do VT, sem espera entre consultas
python checker.py -f lista.txt --delay 0
```

### 🔗 Pipeline completo: relatório → IOCs → reputação

```bash
python ../ioc-extractor/extractor.py ../ioc-extractor/samples/threat_report.txt \
    --types ipv4,domain,sha256 --format plain \
  | python checker.py - --format csv -o enriquecido.csv
```

### Parâmetros

| Opção | Padrão | Descrição |
|---|---|---|
| `iocs` | — | IOCs a consultar, ou `-` para ler do stdin |
| `-f`, `--file` | — | Arquivo com um IOC por linha |
| `-d`, `--delay` | `15` | Segundos entre IOCs (respeita o limite do VT free) |
| `--format` | `table` | `table`, `json` ou `csv` |
| `-o`, `--output` | — | Salva o resultado em arquivo |
| `--include-private` | — | Consulta IPs privados (por padrão são ignorados) |
| `-q`, `--quiet` | — | Esconde o progresso |
| `--no-color` | — | Desativa cores |

**Código de saída:** `0` = tudo limpo/desconhecido · `1` = há IOC suspeito ou malicioso · `2` = erro (ex.: nenhuma chave configurada).

---

## ⚖️ Como o veredito é calculado

Regras simples e **explicáveis** — você consegue justificar o veredito no ticket:

| Veredito | Condição (qualquer uma) |
|---|---|
| 🔴 `MALICIOUS` | VirusTotal ≥ 5 engines maliciosas · AbuseIPDB score ≥ 75 |
| 🟡 `SUSPICIOUS` | VirusTotal ≥ 1 maliciosa ou ≥ 2 suspeitas · AbuseIPDB ≥ 25 · presente em ≥ 1 pulse do OTX |
| 🟢 `CLEAN` | Consultado, sem nenhum dos sinais acima |
| ⚪ `UNKNOWN` | Nenhuma fonte retornou dados |

Os limiares ficam na função `compute_verdict()` — ajuste à tolerância a risco do seu ambiente.

---

## 📸 Exemplo de saída

```text
$ python checker.py -f samples/iocs.txt
[*] Fontes ativas: VirusTotal, AbuseIPDB, AlienVault OTX
[1/6] 185.220.101.47 (ip)
[2/6] 8.8.8.8 (ip)
[-] Ignorado (IP privado/reservado): 192.168.56.101
[4/6] example.com (domain)
[5/6] 44d88612fea8a8f36de82e1278abb02f (md5)
[6/6] 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f (sha256)
VEREDITO    TIPO    IOC                                                VT ABUSE  OTX  PAÍS DONO/ASN
-------------------------------------------------------------------------------------------------------------
MALICIOUS   ip      185.220.101.47                                  17/94   100   45  DE   Tor exit
CLEAN       ip      8.8.8.8                                          0/94     0    0  US   Google LLC
CLEAN       domain  example.com                                      0/94     -    0  -    -
MALICIOUS   md5     44d88612fea8a8f36de82e1278abb02f                66/76     -   45  -    -
MALICIOUS   sha256  275a021bbfb6489e54d471899f7db9d1663fc695ec...   66/76     -   45  -    -

[*] Resumo — MALICIOUS: 3 | CLEAN: 2
```

> Os números variam conforme a data da consulta — reputação muda o tempo todo.

---

## 🧪 Amostras (`samples/`)

| Arquivo | Conteúdo |
|---|---|
| `iocs.txt` | Mistura de IOCs maliciosos conhecidos (nó Tor, hashes do arquivo de teste **EICAR**), controles limpos e um IP privado para validar o filtro |

> O EICAR é um arquivo de teste inofensivo, padrão da indústria, que todo antivírus detecta — ótimo para validar a integração sem lidar com malware real.

## ⚠️ Boas práticas

- **Hash ≠ upload:** o script só consulta hashes; ele **nunca** envia arquivos. Enviar um arquivo interno ao VirusTotal o torna público para assinantes.
- Reputação é **um** sinal, não a verdade absoluta: IPs de cloud/CDN mudam de dono, e "não encontrado" não significa "seguro".
- Respeite os termos de uso e limites de cada API.
