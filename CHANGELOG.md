# Changelog

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
