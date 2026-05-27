# ESP32 Mini Firewall Gateway

Projeto academico da disciplina Performance de Sistemas Ciberfisicos, implementado em ESP32 fisico com PlatformIO, framework Arduino e servidor web embarcado com `WebServer.h` sincrono.

## Objetivo academico

Construir uma base demonstravel para um monitor ciberfisico com foco em performance, seguranca de rede didatica, dashboard local e coleta de evidencias para apresentacao. O sistema e de laboratorio: nao substitui firewall profissional, roteador real, IDS/IPS, WAF, SIEM, pfSense, OPNsense, Mikrotik ou Fortinet.

## Estado atual

A base atual compila para `esp32dev` e inclui:

- Wi-Fi em modo AP com SSID `ESP32-Firewall-Lab`;
- servidor web embarcado na porta 80;
- dashboard principal em `/` com abas obrigatorias;
- API de status em `/api/status`;
- pagina leve de evidencias em `/evidencias`;
- tasks FreeRTOS para web server, metricas e heartbeat;
- metricas iniciais de uptime, heap, flash, sketch, Wi-Fi AP e tempos de funcoes.

Ainda estao planejados para fases posteriores: firewall didatico completo, sensores reais, atuadores, logs persistentes, configuracao dinamica, interrupcao de hardware e gerenciamento de energia.

## Componentes planejados

- ESP32 com display, se o driver for confirmado;
- INA219 para corrente, tensao e potencia;
- DHT22/AM2302 para temperatura e umidade;
- MQ-2 para gas/fumaca;
- rele 5V;
- ventoinha 5V com acionamento adequado, nunca ligada direto no GPIO;
- buzzer apenas como apoio, nao como atuador principal do TDE;
- botoes fisicos;
- fonte 5V externa quando necessario, GND comum, protoboard, jumpers e caixa fisica.

## Bibliotecas e arquitetura

O `platformio.ini` usa apenas o ambiente `esp32dev` com framework Arduino. As bibliotecas usadas nesta base sao as fornecidas pelo core Arduino-ESP32:

- `WiFi.h`;
- `WebServer.h`;
- FreeRTOS nativo do Arduino-ESP32.

A arquitetura ainda esta concentrada em `src/main.cpp`, mas preserva separacao logica por funcoes e estruturas para Wi-Fi, web server, metricas, tasks, API e pagina de evidencias. Separar em modulos fisicos sera feito quando o volume de codigo justificar.

## Como compilar

```bash
pio run
```

## Como gravar no ESP32

```bash
pio run -t upload
```

## Como abrir o monitor serial

```bash
pio device monitor -b 115200
```

## Como acessar o dashboard

1. Grave o firmware no ESP32.
2. Conecte o computador ou celular ao Wi-Fi `ESP32-Firewall-Lab`.
3. Use a senha de laboratorio configurada no firmware.
4. Acesse `http://192.168.4.1/` no navegador.

Rotas principais:

- Dashboard: `http://192.168.4.1/`
- Evidencias: `http://192.168.4.1/evidencias`
- API de status: `http://192.168.4.1/api/status`

## API de status

A rota `/api/status` retorna JSON sem dados sensiveis, incluindo:

- `project_name`;
- `firmware_version`;
- `wifi_connected`;
- `ip`;
- `uptime_ms`;
- `free_heap`;
- `modules`.

Campos legados tambem foram mantidos para compatibilidade com o dashboard atual.

## Evidencias

O roteiro de prints fica em [docs/evidencias.md](docs/evidencias.md). A pagina `/evidencias` foi desenhada para ser simples e legivel em prints no Ubuntu.
