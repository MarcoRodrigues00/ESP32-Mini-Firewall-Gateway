# ESP32 Mini Firewall Gateway

Projeto acadêmico da disciplina Performance de Sistemas Ciberfísicos.

## Objetivo

Construir um sistema ciberfísico real baseado em ESP32, com interface web embarcada, métricas de performance, logs, configuração dinâmica, persistência, gerenciamento de energia, sensores e atuadores físicos.

## Escopo

Este é um projeto didático/de laboratório. Não substitui firewall profissional, pfSense, OPNsense, Mikrotik, Fortinet, IDS/IPS, WAF ou SIEM.

## Hardware previsto

- ESP32
- INA219
- DHT22 ou DS18B20
- Botão físico
- Relé 5V
- Cooler 5V
- Fonte 5V externa
- Protoboard/jumpers
- Caixa física

## Requisitos principais

- Dashboard web embarcado
- Aba Performance
- Logs exportáveis
- Configuração via web
- Persistência mínima de 24h
- Mais de uma task
- Interrupção de hardware
- Gerenciamento de energia
- Dois sensores
- Dois atuadores não LED/buzzer

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

## Como acessar a interface web

1. Ligue o ESP32 com o firmware gravado.
2. Conecte o computador ou celular na rede Wi-Fi `ESP32-Firewall-Lab`.
3. Use a senha `esp32lab123`.
4. Acesse:

```text
http://192.168.4.1
```

## Estado atual

Fase 1: Wi-Fi AP mínimo e dashboard web base com abas obrigatórias.

Ainda não foram implementados firewall didático, sensores, persistência, logs exportáveis, configuração dinâmica, gerenciamento de energia e múltiplas tasks dedicadas.
