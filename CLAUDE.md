# CLAUDE.md — Guia para agentes no ESP32 Mini Firewall Gateway

> Arquivo de orientação para agentes de desenvolvimento (Claude/Codex) trabalhando neste
> repositório. **Não é documento acadêmico/ABNT** e não deve ser incluído no pacote de
> entrega do TDE. As regras do projeto (ver `AGENTS.md`) proíbem mencionar IA/ferramentas
> geradoras nos documentos finais; este guia é meta/dev e fica fora dessa entrega.
>
> Leia também `AGENTS.md` na raiz, que contém os requisitos obrigatórios do TDE, a stack
> definida, as regras de implementação e os papéis de revisão. Em caso de conflito, os
> requisitos do TDE em `AGENTS.md` prevalecem.

---

## 1. Visão geral do projeto

O **ESP32 Mini Firewall Gateway / Monitor Ciberfísico** é um TDE acadêmico da disciplina
**Performance de Sistemas Ciberfísicos**. É um sistema embarcado real baseado em ESP32 que
funciona como gateway/ponto de acesso (AP) Wi-Fi com:

- painel web embarcado (dashboard local, sem CDN obrigatório);
- métricas de performance (uptime, heap, stack por task, flash/LittleFS, tempo de execução de funções);
- logs com níveis (INFO/WARN/ERROR/SECURITY) e persistência;
- display local opcional;
- simulações **didáticas** de firewall/IDS (rate limit, blocklist, contadores, score de risco de clientes, demo de scan/flood).

**Importante — natureza didática:** este é um sistema de laboratório/educacional. **Não é
segurança real de produção.** Não substitui pfSense, OPNsense, Mikrotik, Fortinet, IDS/IPS,
WAF ou SIEM. Não inspeciona tráfego HTTPS. O NAT/NAPT "real" existe apenas em uma PoC
isolada (ESP-IDF), não como requisito obrigatório do TDE.

---

## 2. Stack e arquitetura

O repositório tem **duas trilhas que coexistem hoje**. Documente sempre com honestidade qual
está ativa antes de mexer.

### Trilha A — Firmware principal (PlatformIO + Arduino) — raiz do repo

- `platformio.ini`: `platform = espressif32`, `board = esp32dev`, `framework = arduino`.
- Dependência: `adafruit/Adafruit INA219@^1.2.3`.
- Código: `src/main.cpp` (arquivo único, ~2700 linhas; versão interna `0.12.0-sprint-nat-experimental`).
- Usa `WebServer.h` síncrono, `WiFi.h`, `LittleFS`, FreeRTOS do Arduino-ESP32, INA219 para energia.
- AP padrão: SSID `ESP32-Firewall-Lab`, IP `192.168.4.1`.
- Rotas/endpoints (validados em `tools/offline_project_check.py`): `/`, `/demo`, `/gateway`,
  `/wifi`, `/traffic`, `/report`, `/evidencias`, `/logs`, `/eventos`, `/api/status`,
  `/api/events`, `/api/events/persistent`, `/api/traffic`, `/api/report`,
  `/logs/clear-persistent`, `/demo/info|warn|security|flood|ids|scan`.

### Trilha B — ESP-IDF Appliance v2 (PoC experimental) — `experiments/espidf-appliance-v2/`

- **É a trilha de trabalho da branch ativa atual: `experiment/espidf-appliance-v2`.**
- `platformio.ini`: `framework = espidf`, `board = esp32dev`, `flash_size = 4MB`,
  `partitions = partitions_4mb.csv`.
- Build nativo ESP-IDF: `CMakeLists.txt` + `main/CMakeLists.txt` (`idf_component_register`),
  `sdkconfig.defaults`, `sdkconfig.esp32dev`, `partitions_4mb.csv` (nvs/phy_init/factory, sem FS nesta sprint).
- Código: `main/main.c` (~2360 linhas, C puro).
- Recursos: Wi-Fi AP+STA, **NAPT real** (`CONFIG_LWIP_IP_FORWARD`/`CONFIG_LWIP_NAPT`, habilitado
  só após `IP_EVENT_STA_GOT_IP`), servidor `esp_http_server`, monitor/proxy DNS UDP:53 didático,
  camada IDS de metadados v0.3 (clientes/DNS por cliente/score), SNTP, display local opcional
  atrás de feature flag `APPLIANCE_V2_ENABLE_DISPLAY` (driver/pinout ainda não confirmados).
- Config local da bancada em `include/config.local.h` (Wi-Fi upstream) — **ignorado pelo Git**.

### Outras pastas

- `experiments/nat-router-poc/`: PoC anterior de roteador NAT (ESP-IDF).
- `docs/`: documentação (arquitetura, hardware, hardening, runbook, testes, planos/QA da v2, evidências).
- `evidencias/`: prints, logs, fotos, vídeos, relatórios de smoke/offline-check.
- `tools/`: scripts Python de validação offline/smoke e geração de apresentação.
- `include/`, `lib/`, `test/`: padrão PlatformIO (em uso conforme a trilha).

**Não migrar, apagar ou unificar as trilhas nesta sprint.** A decisão ESP-IDF vs Arduino é um
item de roadmap, não desta tarefa.

---

## 3. Regras de segurança para agentes

- **Nunca** commitar secrets: SSID/senha real de Wi-Fi, tokens, chaves, dados pessoais.
- Credenciais de bancada vivem em `include/config.local.h` / `config.local.h` — **ignorados pelo Git**
  (ver `.gitignore`). Use `config.example.h` como template com placeholders.
- Não colocar IPs públicos reais, credenciais, MACs/identidades reais ou dados sensíveis em evidências.
- Não prometer firewall/VPN/IDS-IPS/WAF/SIEM reais. Manter o enquadramento didático.
- Não executar comandos destrutivos (`rm -rf`, reset de histórico git, `git push --force`, etc.).
- **Não rodar flash/upload no ESP32 sem pedido humano explícito.**
- Não mexer em `partition table`, `sdkconfig*`, bootloader, `flash_size` ou `framework`
  sem uma sprint específica autorizando.
- Não inventar resultado de teste/build. Se não rodou, diga "Não rodei teste/build".
- Não mencionar IA/Claude/ChatGPT/Codex/Cowork nos **documentos finais/acadêmicos** (regra de `AGENTS.md`).

---

## 4. Regras de firmware/performance

- Evitar `delay()` em lógica crítica/fluxo principal. Preferir `vTaskDelay`, timers ou lógica
  não bloqueante por `millis()`/`esp_timer`. (O offline check da trilha A barra `delay()` indevido.)
- Não fazer trabalho pesado em ISR: ISR mínima, `IRAM_ATTR`, sem `Serial`/`String`/`malloc`/
  arquivo/JSON/Wi-Fi; apenas sinalizar uma task.
- Separar responsabilidades por módulo/task: webserver, métricas, logs, display, sensores/energia,
  firewall/IDS demo, DNS/NAT (na v2).
- Preservar a estabilidade de AP + UI web + logs **antes** de adicionar features novas.
- Tratar sensores físicos como opcionais quando dependem de solda ou hardware ainda não validado
  (ex.: INA219 está preparado no código, mas o sensor físico/solda exige cuidado). Sensor ausente
  gera WARN e mostra `n/d`; nunca derruba o sistema. Nunca simular valor de sensor como se fosse real.
- Cada fase precisa compilar antes de avançar.

---

## 5. Fluxo de trabalho (Vibez)

Fluxo padrão por sprint pequena:

1. **Objetivo pequeno da sprint** — escopo mínimo e claro, alinhado à rubrica do TDE.
2. **Prompt para Claude/Codex** — descrever objetivo, contexto, limites e formato de resposta.
3. **Resposta / diff / checks** — gerar a mudança e rodar os checks aplicáveis (build/offline check).
4. **Auditoria ChatGPT** — revisão cruzada do diff (papéis de revisor de `AGENTS.md`).
5. **Validação visual/física** — quando aplicável, testar na bancada com o ESP32.
6. **Correções** — aplicar ajustes apontados na auditoria/validação.
7. **Estudo de 1 peça técnica** — aprofundar 1 conceito por sprint (ver seção 8).
8. **Commit** — só com build OK, sem secrets, docs coerentes (ver política de commits em `AGENTS.md`).
9. **Registro de ressalvas/evidências** — anotar limitações e salvar evidências de marcos.

---

## 6. Comandos úteis

> Comandos reais encontrados no repositório. Onde houver dúvida, **confirmar no repositório antes de usar.**

### Git
```bash
git status --short
git log --oneline -10
git diff --check
```

### Trilha A — firmware principal (raiz, Arduino/PlatformIO)
```bash
# Build (na raiz)
pio run

# Validação offline (build + py_compile + smoke --help; gera relatório em evidencias/)
python3 tools/offline_project_check.py

# Smoke HTTP real — SOMENTE quando for seguro conectar ao AP
python3 tools/smoke_test_http.py --base-url http://192.168.4.1
```

### Trilha B — ESP-IDF Appliance v2 (`experiments/espidf-appliance-v2/`)
```bash
# Build (rodar dentro da pasta do experimento)
pio run

# Smoke HTTP leve da v2 — SOMENTE conectado ao AP / com rota válida
python3 tools/smoke_espidf_v2_http.py --base-url http://192.168.4.1
```

### Upload/monitor — confirmar no repositório antes de usar
> `pio run -t upload` e `pio device monitor` existem no PlatformIO, mas **não rode sem pedido
> humano explícito** (ver seção 3). Velocidade de monitor da v2: `115200`.

Documentação de apoio: `docs/offline-check.md`, `docs/smoke-test.md`,
`docs/espidf-v2-bench-qa.md`, `docs/espidf-v2-evidence-guide.md`, `docs/RUNBOOK.md`.

---

## 7. Evidências acadêmicas

- Salvar prints/evidências **apenas em marcos importantes**, não a cada iteração.
- Evidências úteis: `build PASS`, `upload PASS`, serial monitor, AP/painel web, endpoints/API,
  logs (e logs exportados), display, sensores, consumo/INA219 **quando o sensor estiver validado**.
- Evitar poluir o repo com prints repetidos. Note que `.gitignore` já ignora `evidencias/raw/`
  e `evidencias/smoke-test-*.md` (relatórios temporários).
- Relatórios de offline check ficam em `evidencias/offline-check-*.md`; QA de bancada da v2 tem
  template em `evidencias/espidf-v2-bench-result-template.md`.

---

## 8. Roadmap curto sugerido

Sem implementar agora — apenas próximos passos sugeridos:

1. Estabilizar a documentação operacional (este `CLAUDE.md` + `AGENTS.md` + docs/).
2. Confirmar a trilha ativa: **ESP-IDF Appliance v2** vs firmware principal Arduino/PlatformIO.
3. Rodar validação offline / build nas duas trilhas conforme a sprint.
4. Testar em bancada com o ESP32 real (AP, painel web, DNS/NAT na v2, logs).
5. Capturar evidências finais dos marcos.
6. Preparar apresentação/documentação ABNT do TDE.

---

## 9. Limites desta sprint

- Criar apenas o `CLAUDE.md`.
- Não alterar firmware (`src/main.cpp`, `main/main.c`).
- Não alterar configs de build/flash/partition (`platformio.ini`, `CMakeLists.txt`, `sdkconfig*`,
  `partitions_4mb.csv`).
- Não alterar docs existentes, salvo se for estritamente necessário referenciar este `CLAUDE.md`.
- Não criar backlog gigante ainda.
