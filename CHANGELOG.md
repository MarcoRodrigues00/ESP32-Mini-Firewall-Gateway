# Changelog

## Não lançado

- Corrigido XSS armazenado: rota acessada, mensagem e valor dos eventos, último erro e SSID upstream agora passam por escape em todas as páginas que os exibem (dashboard, `/logs`, `/eventos`, `/evidencias`, `/wifi` e `/gateway`).
- Senha do AP de laboratório movida para `include/secrets.h`, fora do git, com modelo em `include/secrets_example.h`.
- Adicionado CI no GitHub Actions: build do firmware com PlatformIO e varredura de segredos com Gitleaks em todo push e pull request.
- README reescrito; preenchidos `docs/ARQUITETURA.md`, `docs/HARDENING.md`, `docs/RUNBOOK.md` e `docs/REFERENCIAS.md`.

## 0.12.0-sprint-nat-experimental

- Adicionada tentativa controlada de NAT/NAPT para clientes do AP, com a feature flag `NAT_EXPERIMENTAL_ENABLED` e status `nao suportado` quando o lwIP não oferece NAPT.
- Adicionado Traffic Monitor em `/traffic` e `/api/traffic`, com a simulação controlada de scan em `/demo/scan`.
- Adicionado relatório técnico embarcado em `/report` e `/api/report`.
- Eventos passam a exibir `time_label` (horário relativo ao boot).
- Adicionada checagem offline do projeto (`tools/offline_project_check.py`).
- Interface ajustada para apresentar o sistema como mini appliance.

## 0.11.0

- Adicionada configuração do Wi-Fi upstream pela página `/wifi`, gravada em LittleFS (`/wifi.json`), sem exibir a passphrase depois de salva.
- Adicionada a página `/demo` com o roteiro guiado da apresentação.
- Adicionados os documentos de arquitetura técnica e roteiro de demo.

## 0.10.0

- Adicionada a página `/gateway` com o estado do modo AP+STA, clientes do AP e upstream.
- Adicionado IDS didático: contagem de 404, acessos a caminhos sensíveis e simulação em `/demo/ids`.

## 0.9.0-sprint-littlefs

- Adicionada inicializacao do LittleFS no boot com continuidade do firmware em caso de falha.
- Adicionada persistencia seletiva em `/events.log` para WARN, ERROR, SECURITY e eventos importantes de sistema, storage, firewall, sensor e energia.
- Adicionada rotacao simples por limite de 16 KB, apagando o arquivo antigo quando o limite e ultrapassado.
- Adicionada rota `/api/events/persistent` com estado do storage e linhas persistidas.
- Adicionada rota didatica `/logs/clear-persistent` para limpeza manual dos logs persistentes.
- Atualizadas paginas `/`, `/logs` e `/evidencias` para exibir status da persistencia.
- Atualizada documentacao sobre eventos em RAM versus eventos persistentes.

## 0.6.0-sprint-visual

- Aplicada identidade visual de mini SOC ciberfisico com tema escuro, cards, badges de status e hierarquia mais forte.
- Melhorado dashboard `/` com hero de sistema, IP AP, uptime, eventos usados/capacidade e cards de metricas.
- Atualizada pagina `/evidencias` para formato de relatorio de execucao pronto para print academico.
- Atualizada pagina `/logs` e alias `/eventos` com timeline/cards por severidade, exibindo level, source, message, id, uptime e value.
- Mantidas APIs `/api/status` e `/api/events` sem remocao de campos legados.
- Atualizada documentacao de evidencias e prints recomendados.

## 0.4.0-sprint-evidencias

- Adicionada rota `/evidencias` com nome do projeto, versao do firmware, IP local, status do Wi-Fi, uptime, heap livre, modulos principais e placeholder honesto para eventos.
- Ampliada rota `/api/status` com os campos `project_name`, `firmware_version`, `wifi_connected`, `ip`, `uptime_ms`, `free_heap` e `modules`.
- Mantidos campos legados da API para preservar compatibilidade com o dashboard atual.
- Atualizada documentacao base do README e criado roteiro de evidencias em `docs/evidencias.md`.
- Mantido escopo sem novas dependencias externas e sem leitura simulada de sensores.

## 0.3.0-fase2

- Adicionada estrutura mínima com tasks FreeRTOS `taskWebServer`, `taskMetrics` e `taskHeartbeat`.
- Movido atendimento do `WebServer.h` para task dedicada com `server.handleClient()` em intervalo curto.
- Adicionado snapshot de métricas protegido por mutex FreeRTOS.
- Atualizada rota `/api/status` com uptime, heap, flash, sketch, SSID/IP do AP, tasks planejadas e tempos medidos.
- Atualizada aba Performance com métricas de memória, Wi-Fi AP, tabela de tasks e medições iniciais por `micros()`.
- Mantido escopo sem firewall, sensores, persistência, ISR ou gerenciamento de energia nesta fase.

## 0.2.0-fase1

- Adicionado Wi-Fi AP mínimo com SSID `ESP32-Firewall-Lab`.
- Adicionado servidor web embarcado com `WebServer.h` na porta 80.
- Adicionada rota `/` com dashboard base e sete abas obrigatórias.
- Adicionada rota `/api/status` com estado básico do sistema.
- Mantido escopo didático/de laboratório, sem firewall real, sensores ou persistência nesta fase.

## 0.1.0-fase0

- Adicionado firmware mínimo PlatformIO para ESP32.
- Adicionado boot serial, contador de uptime e heartbeat sem uso de `delay()`.
