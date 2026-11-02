# 🔐 Brute Force Detector

Analisa logs de autenticação e identifica **força bruta**, **password spraying** e — o mais importante — **logins bem-sucedidos depois de uma sequência de falhas** (indício forte de conta comprometida).

Ideal para triagem rápida em um incidente, quando ainda não há um SIEM ou você precisa validar um alerta direto no log bruto.

---

## 🎯 O que detecta

| Cenário | Lógica | Severidade | MITRE ATT&CK |
|---|---|---|---|
| Força bruta | `N` falhas do mesmo IP dentro de uma janela deslizante de `W` segundos | 🟡 MEDIUM | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) — Password Guessing |
| Password spraying | Um IP testando `≥ S` usuários distintos (mesmo que devagar) | 🟠 HIGH | [T1110.003](https://attack.mitre.org/techniques/T1110/003/) — Password Spraying |
| Conta comprometida | Login com **sucesso** do mesmo IP depois das falhas | 🔴 CRITICAL | [T1110](https://attack.mitre.org/techniques/T1110/) → [T1078](https://attack.mitre.org/techniques/T1078/) — Valid Accounts |

### Fontes de log suportadas

| Sistema | Arquivo | Eventos usados |
|---|---|---|
| Linux (OpenSSH) | `/var/log/auth.log` (Debian/Ubuntu) ou `/var/log/secure` (RHEL) | `Failed password`, `Failed publickey`, `Accepted ...` |
| Windows | CSV exportado do Security Log | **4625** (falha) e **4624** (sucesso) |

> O formato é detectado pela extensão: `.csv` → Windows; qualquer outra → auth.log.

---

## 🚀 Como usar

```bash
# Linux / SSH
python detector.py samples/auth.log

# Windows
python detector.py samples/windows_security.csv

# Ajustando a sensibilidade: 10 falhas em 2 minutos
python detector.py /var/log/auth.log --threshold 10 --window 120

# Exportando para JSON ou CSV (para anexar no ticket / importar no SIEM)
python detector.py samples/auth.log --format json --output alertas.json
python detector.py samples/auth.log --format csv  --output alertas.csv
```

### Parâmetros

| Opção | Padrão | Descrição |
|---|---|---|
| `-t`, `--threshold` | `5` | Falhas dentro da janela para gerar alerta de força bruta |
| `-w`, `--window` | `60` | Tamanho da janela deslizante (segundos) |
| `-s`, `--spray-users` | `5` | Usuários distintos por IP para caracterizar spraying |
| `-y`, `--year` | ano atual | Ano a assumir em logs syslog (o formato clássico não grava o ano) |
| `-f`, `--format` | `table` | `table`, `json` ou `csv` |
| `-o`, `--output` | — | Salva o resultado em arquivo |
| `--no-color` | — | Desativa cores no terminal |

**Código de saída:** `0` = nada suspeito · `1` = há alertas · `2` = erro de entrada. Isso permite usar o script em `cron` ou pipelines:

```bash
python detector.py /var/log/auth.log --format json -o /tmp/bf.json || echo "ALERTA: força bruta detectada"
```

---

## 📸 Exemplo de saída

```text
$ python detector.py samples/auth.log
[*] 90 eventos de autenticação analisados

[!] 3 alerta(s) gerado(s)

SEVERIDADE  IP ORIGEM         FALHAS  PICO  USERS  MITRE            DESCRIÇÃO
-----------------------------------------------------------------------------------------------------------
CRITICAL    203.0.113.45          22    22      1  T1110 -> T1078   Login bem-sucedido após série de falhas — possível conta comprometida
            └─ contas com login após falhas: svc_backup
HIGH        198.51.100.23         12     3     12  T1110.003        Password spraying: 12 usuários distintos testados
MEDIUM      192.168.56.101        48    48      1  T1110.001        Força bruta: 48 falhas em 60s
```

Repare que o spraying tem **pico de só 3 falhas por minuto** — um detector baseado apenas em volume não pegaria. É por isso que a contagem de usuários distintos existe.

---

## 🧪 Amostras (`samples/`)

Logs simulados de um homelab (VirtualBox, rede host-only `192.168.56.0/24`):

| Arquivo | Cenário reproduzido |
|---|---|
| `auth.log` | Ubuntu Server com SSH exposto: Hydra a partir do Kali (`192.168.56.101`), spraying lento de IP externo, brute force bem-sucedido contra `svc_backup` e tráfego legítimo (incluindo um erro de digitação do admin, que **não** deve alertar) |
| `windows_security.csv` | Controlador de domínio: força bruta no `Administrator` e spraying que termina em login válido da conta `helpdesk` |

> Os IPs "externos" usam faixas reservadas para documentação (RFC 5737: `198.51.100.0/24`, `203.0.113.0/24`).

### Reproduzindo no seu lab

```bash
# No Kali, contra a VM Ubuntu
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.56.20 -t 4
```

### Exportando os eventos do Windows (PowerShell, como administrador)

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624,4625} -MaxEvents 5000 |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $d = @{}; $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
    [pscustomobject]@{
      TimeCreated    = $_.TimeCreated.ToString('s')
      Id             = $_.Id
      TargetUserName = $d.TargetUserName
      IpAddress      = $d.IpAddress
      LogonType      = $d.LogonType
      MachineName    = $_.MachineName
    }
  } | Export-Csv security_events.csv -NoTypeInformation -Encoding UTF8
```

---

## 🛡️ Resposta recomendada

1. **CRITICAL:** isolar o host, resetar a senha da conta, revisar a sessão aberta (`last`, `w`, Event 4624 + 4672) e procurar persistência.
2. **HIGH/MEDIUM:** bloquear o IP no firewall/WAF, checar a reputação com o [`ioc-checker`](../ioc-checker/) e verificar se o serviço precisa mesmo estar exposto.
3. **Hardening:** desativar login por senha no SSH (`PasswordAuthentication no`), habilitar `fail2ban`, MFA e política de bloqueio de conta no AD.

## ⚠️ Limitações

- Não correlaciona entre múltiplos hosts (cada arquivo é analisado isoladamente).
- Ataques distribuídos (muitos IPs, poucas tentativas cada) exigem agregação por usuário — está no roadmap.
