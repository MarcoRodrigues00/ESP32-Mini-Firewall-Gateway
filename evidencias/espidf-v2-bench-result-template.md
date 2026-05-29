# Resultado de bancada ESP-IDF Appliance v2

Smoke HTTP v2: PASS
Falhas: 0
Duração: 0.6s
Base URL: http://192.168.4.1
Interface ESP32: wlx503eaae54c47
IP cliente no AP: 192.168.4.3
Rota principal preservada: default via 192.168.18.1 dev wlp3s0
NAT: active=true
SNTP: synced=true
Display: enabled=true, available=true
DNS suspeito validado: malware.test


## Identificacao

- Data/hora:
- Responsavel:
- Placa/modulo ESP32:
- Display/controlador:
- Branch: `experiment/espidf-appliance-v2`
- Commit curto:
- Firmware/build:
- Config local usada sem senha: SIM / NAO
- `config.local.h` ignorado pelo Git: SIM / NAO
- Upstream SSID mascarado:
- AP SSID:
- Cliente usado no teste:

## Ambiente

- Fonte/cabo:
- Local da bancada:
- Observacao de flash detectada:
- Tempo de estabilidade planejado:
- Tempo de estabilidade executado:

## Checklist PASS/FAIL

| Item | Resultado | Evidencia | Observacoes |
| --- | --- | --- | --- |
| Build SUCCESS | PENDENTE | | |
| Upload SUCCESS | PENDENTE | | |
| Monitor AP started | PENDENTE | | |
| Cliente conecta no AP | PENDENTE | | |
| Dashboard `/` responde | PENDENTE | | |
| STA got IP | PENDENTE | | |
| NAPT enabled | PENDENTE | | |
| Navegacao pelo NAT | PENDENTE | | |
| SNTP synchronized | PENDENTE | | |
| DNS normal observado | PENDENTE | | |
| `/dns` funcional | PENDENTE | | |
| `/clients` funcional | PENDENTE | | |
| `risk_score` altera com `malware.test` | PENDENTE | | |
| Display NORMAL | PENDENTE | | |
| Display DNS SUS | PENDENTE | | |
| Display ATTACK | PENDENTE | | |
| `/traffic` funcional | PENDENTE | | |
| `/logs` funcional | PENDENTE | | |
| `/report` funcional | PENDENTE | | |
| Estabilidade 10 minutos | PENDENTE | | |
| Smoke HTTP v2 | PENDENTE | | |

## Config local sem segredos

Registrar somente parametros nao sensiveis:

```text
APPLIANCE_V2_ENABLE_DISPLAY=
APPLIANCE_V2_DISPLAY_DRIVER=
APPLIANCE_V2_DISPLAY_WIDTH=
APPLIANCE_V2_DISPLAY_HEIGHT=
APPLIANCE_V2_AP_SSID=
APPLIANCE_V2_UPSTREAM_SSID=<mascarado>
Senha upstream registrada? NAO
```

## Evidencias coletadas

- [ ] `espidf-v2-01-build-success.png`
- [ ] `espidf-v2-02-upload-success.png`
- [ ] `espidf-v2-03-monitor-ap-started.txt`
- [ ] `espidf-v2-04-monitor-sta-ip.txt`
- [ ] `espidf-v2-05-monitor-napt.txt`
- [ ] `espidf-v2-06-sntp.png`
- [ ] `espidf-v2-07-dns-normal.png`
- [ ] `espidf-v2-08-dns-malware-test.png`
- [ ] `espidf-v2-09-display-normal.jpg`
- [ ] `espidf-v2-10-display-dns-sus.jpg`
- [ ] `espidf-v2-11-display-attack.jpg`
- [ ] `espidf-v2-12-api-status.json`
- [ ] `espidf-v2-13-dns-page.png`
- [ ] `espidf-v2-14-clients-page.png`
- [ ] `espidf-v2-15-traffic-page.png`
- [ ] `espidf-v2-16-logs-page.png`
- [ ] `espidf-v2-17-report-page.png`

## Observacoes

- Falhas encontradas:
- Comportamentos intermitentes:
- Pendencias para nova bancada:
- Decisao final para defesa:
