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
- pagina de evidencias em `/evidencias` com visual de relatorio academico;
- sistema de eventos em memoria com buffer circular;
- API de eventos em `/api/events`;
- pagina de eventos em `/logs` e alias `/eventos`;
- rotas demo controladas para gerar eventos de apresentacao;
- firewall didatico sobre acessos HTTP ao painel;
- deteccao didatica de flood por janela de requisicoes;
- leitura do INA219 para tensao, corrente e potencia;
- alertas didaticos de tensao baixa, corrente alta e potencia alta;
- tasks FreeRTOS para web server, metricas e heartbeat;
- metricas iniciais de uptime, heap, flash, sketch, Wi-Fi AP, energia e tempos de funcoes.

Ainda estao planejados para fases posteriores: sensores adicionais, atuadores, logs persistentes em LittleFS, configuracao dinamica, interrupcao de hardware e gerenciamento de energia mais completo. O firewall atual e didatico e limitado aos acessos HTTP ao painel.

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

O `platformio.ini` usa o ambiente `esp32dev` com framework Arduino. A base usa o core Arduino-ESP32 e a biblioteca do INA219:

- `WiFi.h`;
- `WebServer.h`;
- FreeRTOS nativo do Arduino-ESP32;
- `Adafruit INA219` para tensao, corrente e potencia via I2C.

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
3. Use a credencial de laboratorio configurada no firmware.
4. Acesse `http://192.168.4.1/` no navegador.

Rotas principais:

- Dashboard: `http://192.168.4.1/`
- Evidencias: `http://192.168.4.1/evidencias`
- Eventos: `http://192.168.4.1/logs`
- Alias de eventos: `http://192.168.4.1/eventos`
- Gateway AP+STA: `http://192.168.4.1/gateway`
- Demo guiada: `http://192.168.4.1/demo`
- API de status: `http://192.168.4.1/api/status`
- API de eventos: `http://192.168.4.1/api/events`
- Demo INFO: `http://192.168.4.1/demo/info`
- Demo WARN: `http://192.168.4.1/demo/warn`
- Demo SECURITY: `http://192.168.4.1/demo/security`
- Demo flood: `http://192.168.4.1/demo/flood`
- Demo IDS: `http://192.168.4.1/demo/ids`


## Demo guiada

A rota `/demo` centraliza o roteiro de apresentacao do TDE. Ela mostra um resumo do sistema, links rapidos para dashboard, gateway, evidencias, logs e APIs, e uma sequencia de etapas para gerar eventos INFO, WARN, SECURITY, flood didatico e IDS didatico. A pagina tambem lista limitacoes honestas: NAT/roteamento real nao implementado nesta fase, IDS baseado em HTTP do painel, ausencia de inspecao HTTPS e sensores fisicos deixados para fase final.

## API de status

A rota `/api/status` retorna JSON sem dados sensiveis, incluindo:

- `project_name`;
- `firmware_version`;
- `wifi_connected`;
- `ip`;
- `uptime_ms`;
- `free_heap`;
- `modules`.

Campos legados tambem foram mantidos para compatibilidade com o dashboard atual. A resposta tambem informa `eventCount`, `eventCapacity`, os objetos `energy`, `storage`/`persistence`, `gateway`, `ids` e o objeto `firewall` com `enabled`, `total_requests`, `security_events`, `last_client_ip`, `last_route`, `last_request_ms`, `flood_window_ms`, `flood_threshold`, `ids_enabled`, `ids_events`, `suspicious_404_count` e `sensitive_path_hits`.

## Firewall didatico

O firewall desta fase e uma camada didatica baseada nos acessos HTTP ao painel embarcado. Ele nao inspeciona trafego HTTPS, nao faz NAT, nao substitui roteador real e nao substitui pfSense, OPNsense, Mikrotik, Fortinet, IDS/IPS ou WAF.

Metricas expostas no dashboard e em `/api/status`:

- total de requisicoes HTTP desde o boot;
- total de eventos `SECURITY`;
- ultimo IP cliente visto;
- ultima rota acessada;
- `millis` da ultima requisicao;
- regra de flood configurada.

Regra didatica atual: mais de 20 requisicoes em 10 segundos gera evento `SECURITY`, com cooldown para evitar spam no buffer. A rota `/demo/flood` gera uma simulacao controlada de excesso de requisicoes, sem executar ataque real. O IDS didatico tambem registra acessos a rotas inexistentes e caminhos sensiveis simulados, como `/admin`, `/login`, `/etc/passwd` e `/wp-admin`. A rota `/demo/ids` gera uma simulacao controlada de assinatura IDS.


## Gateway AP+STA e IDS didatico

O firmware usa `WiFi.mode(WIFI_AP_STA)` para manter o AP local `ESP32-Firewall-Lab` em `http://192.168.4.1` e, opcionalmente, tentar conexao a uma rede Wi-Fi upstream configurada por constantes didaticas no firmware. Os placeholders upstream ficam vazios por padrao, portanto o status esperado sem configuracao e `nao configurado`.

A pagina `/gateway` mostra modo Wi-Fi, SSID/IP do AP, status do upstream, RSSI quando conectado, clientes no AP e contadores do IDS didatico. Nesta sprint, NAT e roteamento sao tratados como tentativa experimental, com status claro quando o core/lwIP nao oferece suporte. O objetivo e telemetria de bancada e eventos de seguranca, nao compartilhar internet nem atuar como firewall profissional de pacotes.

## INA219 e metricas de energia

O INA219 e lido periodicamente pela task de metricas. As paginas e APIs usam um snapshot em memoria; requests HTTP nao fazem leitura direta no barramento I2C.

Ligacao prevista no ESP32:

- `VIN` do INA219 em `3V3` do ESP32;
- `GND` do INA219 em `GND` comum;
- `SDA` do INA219 em `GPIO 21`;
- `SCL` do INA219 em `GPIO 22`;
- entrada de medicao do INA219 em serie com a carga/fonte conforme o modulo usado na bancada.

Metricas exibidas:

- tensao do barramento em V;
- tensao no shunt em mV;
- corrente em mA;
- potencia em mW;
- ultimo update em `millis`;
- estado de alerta.

Se o INA219 nao for detectado no boot, o firmware continua funcionando, registra evento `WARN` e mostra Energia como `indisponivel`. Os thresholds de tensao baixa, corrente alta e potencia alta sao didaticos nesta fase e devem ser calibrados conforme a montagem real.

## API de eventos

A rota `/api/events` retorna JSON leve sem dados sensiveis, com:

- `count`;
- `capacity`;
- `events`.

Cada evento contem `id`, `uptime_ms`, `level`, `source`, `message` e, quando aplicavel, `value`. O buffer circular em RAM guarda os ultimos 40 eventos. Eventos relevantes tambem sao persistidos em LittleFS em `/events.log`, enquanto acessos comuns permanecem apenas em RAM para evitar escrita excessiva na flash.

Eventos automaticos atuais:

- boot do sistema;
- inicio do Wi-Fi AP;
- inicio do servidor web;
- acesso a `/evidencias`;
- acesso a `/api/status`;
- acesso a `/api/events`;
- acesso a `/logs` ou `/eventos`;
- eventos `SECURITY` de flood didatico ou simulacao controlada.

As rotas `/demo/info`, `/demo/warn`, `/demo/security`, `/demo/flood` e `/demo/ids` geram eventos simulados e controlados para apresentacao. Elas nao representam falha real de hardware nem ataque real; servem para demonstrar os niveis INFO, WARN e SECURITY no dashboard.

## Smoke test HTTP

O projeto inclui um smoke tester local para validar as principais rotas do ESP32 e gerar relatorio Markdown em `evidencias/`. Consulte [docs/smoke-test.md](docs/smoke-test.md).

Comando basico:

```bash
python3 tools/smoke_test_http.py --base-url http://192.168.4.1
```

## Documentacao tecnica da sprint

Documentos de apoio para arquitetura, defesa e escopo:

- [Arquitetura tecnica](docs/arquitetura-tecnica.md)
- [Roteiro de demo](docs/roteiro-demo.md)
- [Referencia de API e rotas](docs/api-reference.md)
- [Decisoes de escopo](docs/decisoes-escopo.md)
- [Backlog final](docs/backlog-final.md)
- [Diagrama de arquitetura Mermaid](docs/diagrama-arquitetura.mmd)

## Evidencias

O roteiro de prints fica em [docs/evidencias.md](docs/evidencias.md). A pagina `/evidencias` mostra versao, IP local, Wi-Fi, uptime, heap livre, resumo de seguranca, resumo de energia, status dos modulos, quantidade de eventos e os ultimos 5 eventos reais. Prints recomendados: dashboard principal, `/demo`, `/gateway`, `/evidencias`, `/logs`, `/api/status`, `/api/events` e uma sequencia gerando eventos por `/demo/info`, `/demo/warn`, `/demo/security`, `/demo/flood` e `/demo/ids`.


## Logs persistentes em LittleFS

O firmware usa LittleFS para persistir apenas eventos relevantes em `/events.log`. O objetivo e manter evidencias importantes apos reboot sem gravar na flash em todo request comum.

Politica de persistencia:

- persistir `WARN`, `ERROR` e `SECURITY`;
- persistir eventos importantes de `SYSTEM`, `STORAGE`, `SENSOR`, `ENERGY` e flood do `FIREWALL`;
- nao persistir acessos comuns como `/api/status` e `/api/events`;
- nao gravar em loop rapido nem em leitura normal de sensor.

Formato: JSON Lines, uma linha por evento, com `persisted_id`, `id`, `uptime_ms`, `level`, `source`, `message` e `value` quando existir. O limite atual e de 16 KB. Ao ultrapassar o limite, a decisao adotada nesta fase e rotacao simples: apagar `/events.log` e iniciar um novo arquivo. Essa escolha prioriza simplicidade e reduz risco de travamento em bancada.

Rotas relacionadas:

- `/api/events`: eventos recentes em RAM;
- `/api/events/persistent`: linhas persistidas no LittleFS;
- `/logs/clear-persistent`: limpa o arquivo persistente e registra evento de limpeza manual.

A rota de limpeza e didatica de laboratorio e nao possui autenticacao nesta fase. Nao usar em rede publica.

## Configuracao Wi-Fi upstream

A rota `/wifi` permite configurar a rede Wi-Fi upstream usada pela interface AP+STA didatica. O AP local `ESP32-Firewall-Lab` continua ativo em `192.168.4.1` para recuperacao mesmo se a conexao upstream falhar.

A configuracao salva mostra apenas SSID e indicadores de estado. A senha/passphrase nao e exibida na pagina, em `/api/status`, em logs ou no Serial. Nesta fase a pagina nao possui autenticacao; usar apenas em ambiente de laboratorio controlado. NAT agora e experimental e continua sem promessa de roteador profissional.

## NAT experimental

A sprint `0.12.0-sprint-nat-experimental` adiciona uma tentativa controlada de NAT/NAPT para clientes conectados ao AP `ESP32-Firewall-Lab` usarem o upstream Wi-Fi configurado em `/wifi`. A feature flag `NAT_EXPERIMENTAL_ENABLED` permite desabilitar a tentativa rapidamente se houver instabilidade.

No core Arduino-ESP32 instalado neste ambiente, os headers de NAPT existem, mas a biblioteca lwIP usada pelo build pode nao exportar suporte NAPT/IP forward. Quando isso ocorrer, `/gateway` e `/api/status` mostram NAT como `nao suportado`, sem travar o firmware. O AP local, `/wifi`, dashboard e logs continuam acessiveis.

Teste manual: conectar o ESP32 ao upstream pela pagina `/wifi`, conectar um cliente ao AP do ESP32 e tentar abrir um site HTTP/HTTPS. O resultado depende do core/lwIP, da rede upstream e do cliente. NAT experimental nao substitui roteador, firewall profissional ou IDS/IPS.
