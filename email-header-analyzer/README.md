# 📧 Email Header Analyzer

Analisa os **cabeçalhos** de um e-mail suspeito e responde, em segundos, as perguntas que todo analista faz ao receber um reporte de phishing:

- O e-mail passou em **SPF, DKIM e DMARC**?
- O remetente exibido é o **mesmo** que realmente enviou?
- Para onde vão as **respostas**?
- Por quais **servidores** a mensagem passou e qual o **IP de origem**?

---

## 🎯 O que é verificado

| Categoria | Verificação | Pontos |
|---|---|:-:|
| Autenticação | SPF `fail` / `softfail` / ausente | 25 / 15 / 5 |
| | DKIM inválido / ausente | 20 / 5 |
| | DMARC `fail` | 25 |
| Alinhamento | `Return-Path` de domínio diferente do `From` | 15 |
| | `Reply-To` apontando para outro domínio | 20 |
| | DKIM assinado por domínio de terceiro (`d=`) | 5 |
| | `Message-ID` gerado por outro domínio | 3 |
| Engenharia social | Display name contendo **outro e-mail** (`"no-reply@microsoft.com" <x@golpe.top>`) | 25 |
| | Display name citando **marca** conhecida com domínio que não é dela | 15 |
| Rota | Timestamps fora de ordem nos `Received` | 5 |

**Risco final:** `LOW` (< 30) · `MEDIUM` (30–59) · `HIGH` (≥ 60)

**MITRE ATT&CK:** [T1566 — Phishing](https://attack.mitre.org/techniques/T1566/) (.001 anexo, .002 link) · [T1672 — Email Spoofing](https://attack.mitre.org/techniques/T1672/)

---

## 🚀 Como usar

```bash
python analyzer.py samples/phishing_sample.eml

# Saída em JSON (integração com SOAR, ticket, outro script)
python analyzer.py samples/phishing_sample.eml --format json -o analise.json

# Só os headers colados num .txt também funciona
python analyzer.py headers.txt

# Ou direto do clipboard / stdin
cat suspeito.eml | python analyzer.py -
```

### Como obter o `.eml` / os headers

| Cliente | Caminho |
|---|---|
| **Outlook (desktop)** | Abrir o e-mail → *Arquivo* → *Propriedades* → copiar "Cabeçalhos da Internet" — ou arrastar o e-mail para uma pasta (gera `.msg`; salve como `.eml`) |
| **Outlook Web / M365** | `⋯` → *Exibir* → *Exibir detalhes da mensagem* |
| **Gmail** | `⋮` → *Mostrar original* → *Fazer download do original* |
| **Thunderbird** | *Arquivo* → *Salvar como* → `.eml` |

### Parâmetros

| Opção | Padrão | Descrição |
|---|---|---|
| `file` | — | `.eml`, `.txt` com headers, ou `-` para stdin |
| `-f`, `--format` | `text` | `text` ou `json` |
| `-o`, `--output` | — | Salva o resultado em arquivo |
| `--no-color` | — | Desativa cores |

**Código de saída:** `0` = risco baixo/médio · `1` = risco alto · `2` = erro de entrada.

---

## 📸 Exemplo de saída

```text
$ python analyzer.py samples/phishing_sample.eml
══════════════════════════════════════════════════════════════════════
  ANÁLISE DE CABEÇALHO DE E-MAIL
══════════════════════════════════════════════════════════════════════
  Assunto     : [Ação necessária] Sua senha expira hoje
  Data        : Wed, 28 Oct 2026 17:20:57 +0000
  From        : Microsoft 365 <no-reply@microsoft.com> <seguranca@micros0ft-verify.top>
  Return-Path : bounce-7731@hostingbarato.top
  Reply-To    : suporte.contas@gmail-recovery.xyz
  Message-ID  : <20261028172057.1B3C5D7E@vps-4471.hostingbarato.top>
  X-Mailer    : PHPMailer 6.8.1 (https://github.com/PHPMailer/PHPMailer)

── AUTENTICAÇÃO ──────────────────────────────────────────────────────
  SPF   : ⚠️  softfail
  DKIM  : ➖ none
  DMARC : ❌ fail

── ROTA (origem → destino) ───────────────────────────────────────────
  [1] localhost  (127.0.0.1)
       └─ por vps-4471.hostingbarato.top
  [2] vps-4471.hostingbarato.top  (45.142.212.61)
       └─ por mx01.empresa-exemplo.com.br  +9s
  [3] mx01.empresa-exemplo.com.br  (10.0.0.5)
       └─ por mbx01.empresa-exemplo.com.br  +2s

  IP de origem provável : 45.142.212.61
  IPs públicos na rota  : 45.142.212.61

── ACHADOS ───────────────────────────────────────────────────────────
  [HIGH  ] DMARC fail
            From não está alinhado com SPF nem DKIM — típico de spoofing.
  [HIGH  ] Display name contém outro e-mail
            Exibe 'no-reply@microsoft.com' mas o remetente real é seguranca@micros0ft-verify.top.
  [HIGH  ] Reply-To aponta para outro domínio
            As respostas irão para suporte.contas@gmail-recovery.xyz (From: micros0ft-verify.top).
  [MEDIUM] SPF softfail
            O servidor de origem não está autorizado a enviar pelo domínio do envelope.
  [MEDIUM] Return-Path diferente do From
            From: micros0ft-verify.top  |  Return-Path: hostingbarato.top
  [MEDIUM] Possível personificação de marca
            Display name cita 'microsoft', mas o domínio é micros0ft-verify.top.
  [LOW   ] Sem DKIM
            Mensagem não assinada.
  [INFO  ] Message-ID de outro domínio
            Message-ID gerado por vps-4471.hostingbarato.top.

══════════════════════════════════════════════════════════════════════
  RISCO: HIGH  (score 123)
══════════════════════════════════════════════════════════════════════

  Próximo passo: python ../ioc-checker/checker.py 45.142.212.61
```

### 🔗 Fluxo completo de triagem de phishing

```bash
# 1. Cabeçalho: autenticação, spoofing, IP de origem
python analyzer.py suspeito.eml

# 2. Corpo: extrair links, domínios e hashes
python ../ioc-extractor/extractor.py suspeito.eml --types url,domain,ipv4 --format plain > iocs.txt

# 3. Reputação de tudo
python ../ioc-checker/checker.py -f iocs.txt
```

---

## 🧪 Amostras (`samples/`)

| Arquivo | Cenário | Risco esperado |
|---|---|---|
| `phishing_sample.eml` | Falso alerta de "senha expirando" do Microsoft 365, enviado de VPS via PHPMailer, com display name forjado e Reply-To externo | 🔴 HIGH |
| `legit_sample.eml` | Comunicado interno com SPF, DKIM e DMARC alinhados | 🟢 LOW |

> Os IPs usam faixas de documentação/exemplo e os domínios são fictícios.

## ⚠️ Limitações

- **Headers podem ser forjados:** só os `Received` adicionados pelos **seus** servidores são confiáveis — tudo abaixo deles foi escrito pelo remetente.
- O resultado de SPF/DKIM/DMARC vem do `Authentication-Results` do seu gateway; o script **não** refaz as consultas DNS.
- O domínio organizacional é aproximado (sem Public Suffix List completa).
- Não analisa anexos — para isso, extraia os hashes e use o [`ioc-checker`](../ioc-checker/).
