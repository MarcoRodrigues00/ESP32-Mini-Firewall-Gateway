# Changelog

## 0.2.0-fase1

- Adicionado Wi-Fi AP mínimo com SSID `ESP32-Firewall-Lab`.
- Adicionado servidor web embarcado com `WebServer.h` na porta 80.
- Adicionada rota `/` com dashboard base e sete abas obrigatórias.
- Adicionada rota `/api/status` com estado básico do sistema.
- Mantido escopo didático/de laboratório, sem firewall real, sensores ou persistência nesta fase.

## 0.1.0-fase0

- Adicionado firmware mínimo PlatformIO para ESP32.
- Adicionado boot serial, contador de uptime e heartbeat sem uso de `delay()`.
