# ESP32 Mini Firewall Gateway / Monitor Ciberfísico

Projeto acadêmico da disciplina **Performance de Sistemas Ciberfísicos**, implementado em
ESP32 físico. O sistema funciona como gateway/ponto de acesso (AP) Wi-Fi com dashboard web
embarcado, monitor de DNS, NAT real, camada didática de IDS por metadados, métricas de
performance e coleta de evidências de bancada.

> **Natureza didática.** Este é um sistema de laboratório/educacional. Não é um firewall
> profissional de produção e não substitui pfSense, OPNsense, Mikrotik, Fortinet, IDS/IPS,
> WAF, SIEM ou roteador comercial. Não inspeciona tráfego HTTPS e não promete VPN nem
> segurança corporativa real.

---

## Resumo

O protótipo demonstra, em hardware real, conceitos de sistema ciberfísico aplicados a um
mini appliance de rede: um ESP32 atua como AP local, encaminha tráfego para uma rede
upstream via NAT/NAPT, observa as consultas DNS dos clientes, calcula um score de risco
heurístico por cliente e expõe tudo em um painel web local sem dependência de CDN. Toda a
operação é instrumentada com métricas e logs para fins de apresentação acadêmica.

## Objetivo acadêmico

Construir uma base demonstrável e defensável de um monitor ciberfísico, com foco em
performance, telemetria de rede didática, dashboard local e geração de evidências
reproduzíveis para a defesa do TDE. O escopo prioriza honestidade técnica: cada limitação é
documentada e nenhum recurso é apresentado como mais robusto do que realmente é.

## O que o sistema faz

- **AP Wi-Fi local** com IP fixo `192.168.4.1` e DHCP para clientes na rede `192.168.4.x`.
- **STA upstream opcional**, com reconexão por backoff simples.
- **NAT/NAPT real** habilitado somente após o STA obter IP (`IP_EVENT_STA_GOT_IP`),
  permitindo que clientes do AP naveguem pela rede upstream.
- **Monitor/proxy DNS didático** em UDP:53 — o AP entrega `192.168.4.1` como DNS via DHCP e
  encaminha consultas para upstream (`1.1.1.1` com fallback `8.8.8.8`), observando domínios,
  cliente de origem e tipo de consulta (A/AAAA).
- **Camada de IDS por metadados (v0.3)**: clientes observados, contagem de consultas DNS,
  domínios únicos aproximados, detecção de burst e score de risco heurístico por cliente.
- **Dashboard web embarcado** servido pelo `esp_http_server`, com páginas de status, DNS,
  clientes, tráfego, logs e relatório.
- **Logs em RAM** com níveis e filtragem de polling comum para reduzir ruído.
- **SNTP** iniciado após o STA conectar (timezone documentado `America/Sao_Paulo`).
- **Display local opcional** atrás da feature flag `APPLIANCE_V2_ENABLE_DISPLAY`, com estados
  visuais NORMAL / DNS suspeito / ATTACK (driver/pinout ainda não confirmados em hardware).

## Arquitetura em alto nível

```
        Clientes Wi-Fi                 ESP32 (AP + STA)                 Rede upstream
   ┌──────────────────┐         ┌──────────────────────────┐         ┌──────────────┐
   │ celular / notebook│ ──AP──▶ │ DHCP + DNS:53 (monitor)  │         │              │
   │  192.168.4.x      │         │ NAT/NAPT (pós STA GOT_IP)│ ──STA──▶│  internet /  │
   │                   │ ◀─HTTP─ │ esp_http_server (painel) │         │  roteador    │
   └──────────────────┘         │ IDS metadados + score    │         │              │
                                 │ logs RAM + SNTP + display│         └──────────────┘
                                 └──────────────────────────┘
```

Responsabilidades separadas por módulo/task: Wi-Fi (AP+STA), servidor HTTP, monitor DNS
(task dedicada com stack ampliada e buffers em heap), camada IDS/clientes, logs e display.

## Stack e tecnologias

- ESP32 (`board = esp32dev`), flash de 4 MB.
- **ESP-IDF** como framework, orquestrado via **PlatformIO** (PlatformIO Core 6.1.19).
- Código em C puro (`main/main.c`).
- `esp_http_server`, Wi-Fi AP+STA, lwIP com `CONFIG_LWIP_IP_FORWARD` / `CONFIG_LWIP_NAPT`,
  proxy DNS UDP, SNTP.
- Tabela de partições `partitions_4mb.csv` (`nvs` / `phy_init` / `factory`) — sem
  filesystem nesta sprint.

## Trilha atual validada: ESP-IDF Appliance v2

O repositório mantém **duas trilhas que coexistem**, e o histórico de ambas é preservado:

- **Trilha A — Firmware principal (PlatformIO + Arduino)**, na raiz (`src/main.cpp`,
  `platformio.ini` com `framework = arduino`). Painel web com `WebServer.h` síncrono, firewall
  didático sobre HTTP, INA219 e LittleFS. Mantida como histórico do projeto.
- **Trilha B — ESP-IDF Appliance v2**, em `experiments/espidf-appliance-v2/`. **É a trilha
  ativa e validada atualmente** (branch `experiment/espidf-appliance-v2`), com build e
  validação funcional em bancada registrados em `evidencias/`.

Esta sprint trata a **Trilha B (ESP-IDF v2) como a trilha validada atual**. A Trilha A não foi
removida nem depreciada formalmente; a decisão definitiva ESP-IDF vs Arduino permanece como
item de roadmap.

> Os comandos abaixo assumem a trilha ESP-IDF v2. O diretório do experimento é
> `experiments/espidf-appliance-v2/`; o smoke tester fica em `tools/` (rodado a partir da raiz
> do repositório).

## Como compilar

```bash
cd experiments/espidf-appliance-v2
pio run
```

A configuração local de bancada (SSID/senha da rede upstream) vive em
`experiments/espidf-appliance-v2/include/config.local.h`, **ignorado pelo Git**. Use o
template `config.example.h` com placeholders.

## Como fazer upload/flash

> ⚠️ **Cuidado:** o upload grava firmware no ESP32 físico. Só execute com a placa correta
> conectada e mediante intenção explícita. Confirme a porta serial com `pio device list`
> antes de gravar.

```bash
# a partir de experiments/espidf-appliance-v2
pio run -t upload --upload-port /dev/ttyUSB0
```

Na bancada de referência a porta foi `/dev/ttyUSB0` (conversor USB-serial CH340).

## Como abrir o monitor serial

```bash
pio device monitor -p /dev/ttyUSB0 -b 115200
```

A velocidade do monitor da v2 é `115200`.

## Como acessar o dashboard / AP

1. Grave o firmware no ESP32 (passo de upload acima).
2. Conecte o computador ou celular ao Wi-Fi `ESP32-APPLIANCE-V2` (canal 6, máx. 4 clientes).
   A senha é de laboratório e não consta nas evidências.
3. Acesse `http://192.168.4.1/` no navegador.

## Endpoints principais

| Rota | Tipo | Descrição |
| --- | --- | --- |
| `/` | HTML | Dashboard / painel local |
| `/api/status` | JSON | Estado operacional, NAT, upstream, DNS, clientes, IDS, display |
| `/dns` | HTML | Consultas DNS observadas |
| `/api/dns` | JSON | Histórico recente de DNS (domínio, cliente, tipo, flags de suspeita) |
| `/clients` | HTML | Clientes observados e classificação |
| `/api/clients` | JSON | Clientes em RAM, contadores DNS, score e classificação |
| `/traffic` | HTML | Total de requests, DNS queries, clientes e top routes |
| `/logs` | HTML | Eventos recentes em RAM (INFO/WARN/ERROR/SECURITY) |
| `/report` | HTML | Relatório técnico resumido do estado atual |
| `/demo`, `/demo/scan`, `/demo/security`, `/demo/info` | HTML | Demos didáticas controladas |

Rotas sensíveis didáticas reconhecidas pela camada IDS: `/admin`, `/login`, `/wp-admin`,
`/etc/passwd`, `/api`, `/config`, `/debug`.

## Como rodar o smoke HTTP

Conectado ao AP do ESP32, a partir da raiz do repositório:

```bash
python3 tools/smoke_espidf_v2_http.py --base-url http://192.168.4.1
```

O tester valida 10 rotas principais (`/`, `/api/status`, `/dns`, `/api/dns`, `/clients`,
`/api/clients`, `/traffic`, `/logs`, `/report`, `/demo/security`) e checa campos de JSON.

## Evidências já validadas

Evidências reproduzíveis registradas em `evidencias/` (datadas de 2026-06-01):

- **Build** — `evidencias/2026-06-01-build-espidf-v2.md`
  - `pio run` em `experiments/espidf-appliance-v2`: **SUCCESS** em 119,03 s.
  - RAM 15,3% (50260 / 327680 bytes); Flash 42,9% (899873 / 2097152 bytes).
  - `firmware.bin` 880K; `firmware.elf` 8.4M (artefatos em `.pio/`, não versionados).
- **Bancada (validação funcional)** — `evidencias/2026-06-01-bench-espidf-v2.md`
  - Upload/flash: **SUCCESS** em 20,79 s, porta `/dev/ttyUSB0` (CH340), monitor a 115200.
  - AP `ESP32-APPLIANCE-V2` em `192.168.4.1`; upstream STA conectado; **NAT `active=true`**.
  - Smoke HTTP: **PASS, 10/10 endpoints**.
  - DNS: total 101, suspeitos 10; `malware.test` classificado como suspeito.
  - Cliente `192.168.4.2` com `risk_score=53`, classificação `suspeito`.
  - Estado de display lógico: `ATTACK`.

Material cru (logs, prints brutos) fica em `evidencias/raw/` e não é versionado.

## Estado atual do projeto

- Branch de trabalho: `experiment/espidf-appliance-v2`.
- Trilha ESP-IDF v2 com **build e validação funcional de bancada concluídos e evidenciados**.
- AP, NAT real, monitor DNS, IDS de metadados, dashboard e smoke HTTP funcionando em hardware.
- Eventos e métricas mantidos majoritariamente em RAM (sem persistência nesta sprint).
- Display local validado em estado lógico (`ATTACK`), mas driver/pinout físico ainda não
  confirmados — recurso permanece atrás de feature flag.

## Limitações conhecidas

- Sistema **didático/acadêmico**: não é firewall profissional de produção.
- **Sem inspeção de conteúdo HTTPS** — o monitor DNS observa apenas metadados de consultas
  (A/AAAA), não conteúdo criptografado.
- Eventos e métricas são **RAM-only** nesta sprint; sem histórico de 24 h persistido.
- **Score de risco é heurístico** e apenas indicativo (+5 por domínio suspeito, +1 por burst
  DNS, +2 por muitos domínios únicos; faixas 0–4 baixo, 5–14 atenção, 15+ suspeito).
- **Capacidade pequena de clientes** (máx. 4 no AP).
- Classificação de domínios é heurística e tem falsos negativos conhecidos: na bancada,
  `suspicious.example` e a digitação `phising.local` **não** foram marcados como suspeitos.
  Isso é comportamento esperado da heurística atual, **registrado como limitação, não como
  sucesso**.
- Proxy DNS é mínimo, experimental e de melhor esforço (sem bloqueio de tráfego).

## Roadmap próximo

1. Estabilizar a documentação operacional (README, docs/).
2. Confirmar formalmente a trilha ativa: ESP-IDF Appliance v2 vs firmware Arduino.
3. Avaliar persistência de eventos/métricas (hoje em RAM) rumo ao histórico de 24 h do TDE.
4. Revisar a heurística de classificação de domínios suspeitos com mais amostras controladas.
5. Confirmar controlador/pinout do display físico para habilitar a camada visual.
6. Consolidar evidências finais e preparar a documentação ABNT / apresentação do TDE.

## Segurança e escopo didático

Este projeto é de laboratório e existe para fins de ensino e demonstração. Ele **não**:
inspeciona HTTPS, substitui firewall/roteador profissional, entrega IDS/IPS, WAF, SIEM ou
VPN reais. Credenciais reais (SSID/senha upstream) ficam apenas em arquivos locais ignorados
pelo Git (`include/config.local.h`); nunca devem ser commitadas. Evidências não contêm
senhas, IPs públicos reais nem identidades sensíveis. O upload no ESP32 e o smoke HTTP só
devem ser executados em bancada controlada, com intenção explícita.

## Documentação de apoio

- Plano da PoC v2: `docs/espidf-v2-plan.md`
- Checklist de bancada v2: `docs/espidf-v2-bench-qa.md`
- Guia de evidências v2: `docs/espidf-v2-evidence-guide.md`
- Sanidade de flash/partição: `docs/espidf-v2-flash-partition-sanity.md`
- Smoke test: `docs/smoke-test.md` · Offline check: `docs/offline-check.md`
- Arquitetura, hardware, hardening, runbook e testes: pasta `docs/`
