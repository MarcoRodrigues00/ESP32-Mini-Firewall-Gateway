# Changelog

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
