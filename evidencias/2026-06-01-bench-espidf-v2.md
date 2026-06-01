# Evidência de bancada — ESP-IDF Appliance v2

> Documento de evidência da validação funcional em hardware, preenchido a partir de
> execução real na bancada com ESP32 físico.
> Para o checklist detalhado PASS/FAIL por funcionalidade, usar em conjunto
> `evidencias/espidf-v2-bench-result-template.md`.
>
> Esta é uma PoC didática (gateway/AP + dashboard + DNS/NAPT). Não é firewall de produção.

## Identificação

- Data do teste: 2026-06-01
- Responsável: equipe do TDE (bancada)
- Branch: `experiment/espidf-appliance-v2`
- Commit testado (`git rev-parse --short HEAD`): `f52e276`
- Firmware/build de referência: ver `evidencias/2026-06-01-build-espidf-v2.md`

## Ambiente

- PlatformIO Core: 6.1.19
- Placa/módulo ESP32: ESP32 dev (USB serial CH340)
- Fonte/cabo USB: cabo USB com conversor serial CH340
- Sistema do host (ex.: WSL2 + usbipd): WSL2 Ubuntu (porta exposta como `/dev/ttyUSB0`)
- `config.local.h` presente e ignorado pelo Git: SIM

## Porta serial

- Porta detectada (`pio device list`): `/dev/ttyUSB0` (conversor CH340)

## Upload / flash

- Comando executado:

  ```bash
  pio run -d experiments/espidf-appliance-v2 -t upload --upload-port /dev/ttyUSB0
  ```
- Resultado do upload: SUCCESS
- Observações: gravação concluída e verificada em 20.79 s. Trechos finais relevantes:

  ```text
  Hash of data verified.
  Leaving...
  Hard resetting via RTS pin...
  [SUCCESS] Took 20.79 seconds
  ```

## Monitor serial (trecho curto)

- Comando: `pio device monitor -d experiments/espidf-appliance-v2 -b 115200`
- Trecho relevante (AP, cliente, DHCP, DNS e camada IDS de metadados; **sem log cru gigante**):

  ```text
  Client connected: aid=1
  DHCP server assigned IP to a client, IP is: 192.168.4.2
  First DNS query observed: client-update.fastly.steamstatic.com from 192.168.4.3 type=A
  DNS burst detected from 192.168.4.2
  Suspicious DNS domain=malware.test client=192.168.4.2 type=A
  GET /demo/security ... containment_test_event
  ```

## Conexão Wi-Fi / AP

- SSID AP usado (somente SSID de laboratório): `ESP32-APPLIANCE-V2` (canal 6, máx. 4 clientes)
- Senha: NÃO REGISTRADA (senha de laboratório fica fora da evidência)
- IP do AP: `192.168.4.1`
- IP recebido pelo cliente (`192.168.4.x`): `192.168.4.2` e `192.168.4.3` observados via DHCP
- Upstream SSID (mascarado, sem senha): rede upstream configurada e conectada (STA com IP `192.168.18.23`)

## Dashboard HTTP

- `http://192.168.4.1/` respondeu: SIM
- Observações de UI: painel local servido pelo `esp_http_server`; rotas de status, DNS, clientes,
  tráfego, logs e relatório acessíveis. Estado de display indicado como `ATTACK` após simulação.

## Smoke HTTP

- Comando: `python3 tools/smoke_espidf_v2_http.py --base-url http://192.168.4.1`
- Resumo (`PASS/FAIL; falhas=N; duracao=Xs`): `PASS; falhas=0; duracao=0.7s`

### Endpoints testados (resultado por rota)

| Endpoint | Tipo | Resultado |
| --- | --- | --- |
| `/` | html | PASS |
| `/api/status` | json | PASS |
| `/dns` | html | PASS |
| `/api/dns` | json | PASS |
| `/clients` | html | PASS |
| `/api/clients` | json | PASS |
| `/traffic` | html | PASS |
| `/logs` | html | PASS |
| `/report` | html | PASS |
| `/demo/security` | html | PASS |

## Métricas observadas

> Campos disponíveis em `/api/status`, `/api/dns`, `/api/clients` e no diagnóstico de boot.
> Registrar só o que foi observado.

- Projeto / versão: `ESP32 Mini Firewall Gateway - ESP-IDF Appliance v2` / `0.1.0-poc`
- NAT (`nat.active`): compilado=`true`, tentado=`true`, ativo=`true`
- Upstream STA: configurado=`true`, conectado=`true`, IP `192.168.18.23`
- Clientes: `clients count`=1; clientes ativos observados=2 (`192.168.4.2`, `192.168.4.3`)
- DNS (total/suspeitos): total=101, suspeitos=10, burst detectado=1
- DNS — monitoramento: `monitoring_enabled=true`; `malware.test` suspeito=`true`;
  `suspicious.example` suspeito=`false`; último domínio suspeito: `malware.test`
- `risk_score` após `/demo/security`: maior score=53 (cliente `192.168.4.2`, classificação `suspeito`)
  - Cliente `192.168.4.2`: dns_query_count=100, suspicious_dns_count=10, unique_domain_count=60,
    risk_score=53, classificação `suspeito`, último evento `suspicious_dns`
  - Cliente `192.168.4.3`: risk_score=0, classificação `baixo`
- Display (`enabled`/`available`/`state`): `enabled=true`, `available=true`, `state=ATTACK`
- Limitações declaradas pela própria API (`/api/dns`): `dns_queries_only`,
  `no_https_content_inspection`, `a_aaaa_queries_recorded`, `best_effort_udp_proxy`, `ram_only`

### DNS simulado (consultas didáticas)

- Comandos usados:
  - `nslookup malware.test 192.168.4.1`
  - `nslookup suspicious.example 192.168.4.1`
  - `nslookup phishing.local 192.168.4.1`
- Observações:
  - As consultas retornaram NXDOMAIN, mas foram observadas pelo monitor DNS do ESP32.
  - `malware.test` foi classificado como suspeito.
  - `suspicious.example` apareceu no log, porém **não** foi classificado como suspeito.
  - Houve uma digitação anterior (`phising.local`) que apareceu como não suspeita — registrada
    apenas como ressalva, não como caso de sucesso.

## Evidências capturadas

- [x] Print do upload com sucesso
- [x] Trecho do monitor (AP + IP)
- [x] Saída do smoke HTTP
- [x] Print do dashboard `/`
- [x] `api-status.json` enxuto
- [x] (Opcional) estado do display lógico (`ATTACK`) refletido na API

> Material cru vai em `evidencias/raw/` (ignorado pelo Git). Não commitar logs crus,
> `.pio/`, SSID/senha real de rede externa.

## Riscos / ressalvas

- Projeto didático/acadêmico: **não** é firewall profissional de produção.
- Não faz inspeção de conteúdo HTTPS; o monitor DNS observa apenas metadados/consultas
  (registros A/AAAA), não conteúdo criptografado.
- Eventos e métricas são majoritariamente mantidos em RAM (sem persistência nesta sprint).
- O score de risco é heurístico, apenas indicativo.
- Capacidade de clientes é pequena (máx. 4).
- Classificação de domínio é heurística: `suspicious.example` e a digitação `phising.local`
  não foram marcados como suspeitos — comportamento esperado da heurística atual, não falha de bancada.

## Próximos passos

- Consolidar o checklist PASS/FAIL detalhado em `evidencias/espidf-v2-bench-result-template.md`.
- Avaliar persistência de eventos/métricas (hoje em RAM) como item de roadmap.
- Revisar a heurística de classificação de domínios suspeitos com mais amostras controladas.
