# Arquitetura tecnica

Este documento descreve a arquitetura atual do ESP32 Mini Firewall Gateway na sprint de documentacao. O sistema e um monitor ciberfisico didatico para bancada academica, executado em ESP32 fisico com PlatformIO, framework Arduino e interface web embarcada.

## Visao geral

O firmware inicializa o ESP32, monta o LittleFS, configura a rede Wi-Fi, inicia o servidor HTTP local e cria tasks FreeRTOS para separar atendimento web, metricas e heartbeat. A interface principal roda no proprio microcontrolador e pode ser acessada por navegador conectado ao AP local.

O objetivo atual e demonstrar uma base funcional para performance, logs, eventos, seguranca didatica, gateway AP+STA e coleta de evidencias. O projeto nao e um firewall profissional, nao substitui roteador real e nao implementa inspecao HTTPS.

## ESP32 como AP local

O ESP32 cria o ponto de acesso `ESP32-Firewall-Lab` e atende por padrao em `http://192.168.4.1/`. Esse AP e o caminho principal para o professor acessar dashboard, demo guiada, gateway, logs, eventos e APIs durante a apresentacao.

O AP local e obrigatorio para a demonstracao porque permite operar o sistema sem depender da rede da sala. O navegador do avaliador conversa diretamente com o servidor web embarcado no ESP32.

## Gateway AP+STA didatico

O firmware usa modo Wi-Fi AP+STA para manter o AP local ativo e, quando houver configuracao de upstream no firmware, tentar conexao a uma rede Wi-Fi externa. A pagina `/gateway` mostra SSID e IP do AP, estado da STA, RSSI quando conectado, IP upstream, quantidade de clientes no AP e contadores relacionados ao IDS didatico.

Nesta fase, o gateway e telemetrico e didatico. NAT e roteamento sao tratados como tentativa experimental, com fallback documentado quando o core/lwIP nao oferece suporte.

## WebServer sincrono

O servidor HTTP usa `WebServer.h` sincrono do framework Arduino. O projeto nao usa servidor web assincrono de terceiros.

As rotas sao registradas em `setupWebServer()` e atendidas pela task `taskWebServer`, que chama `server.handleClient()` em ciclo curto com `vTaskDelay`. Isso mantem a implementacao simples e adequada ao escopo academico atual.

## FreeRTOS e tasks

O firmware cria tasks com `xTaskCreatePinnedToCore`:

- `taskWebServer`: atende requisicoes HTTP.
- `taskMetrics`: atualiza snapshots de metricas, gateway e energia.
- `taskHeartbeat`: mantem batimento periodico e eventos de saude basicos.

As tasks usam `vTaskDelay`, evitando `delay()` no fluxo principal. A separacao permite que metricas e atendimento web avancem sem concentrar toda a logica no `loop()`.

## Eventos em RAM

O sistema mantem um buffer circular de eventos em RAM. Cada evento tem identificador, uptime, nivel, origem, mensagem e valor opcional. A rota `/api/events` expoe os eventos recentes em JSON, e as paginas `/logs` e `/eventos` mostram a mesma base em HTML.

Niveis usados:

- `INFO`: eventos normais de operacao.
- `WARN`: alertas didaticos ou falhas recuperaveis.
- `ERROR`: falhas de inicializacao ou operacao.
- `SECURITY`: eventos de seguranca didatica.

O buffer em RAM e temporario. Ele ajuda na apresentacao e na validacao rapida, mas nao e uma trilha historica permanente.

## Persistencia em LittleFS

O LittleFS e usado para persistir eventos relevantes em `/events.log`. A politica e seletiva para reduzir escrita na flash: eventos comuns de consulta nao sao gravados, enquanto WARN, ERROR, SECURITY e eventos importantes de sistema, sensor, energia e storage podem ser persistidos.

A rota `/api/events/persistent` retorna as linhas persistidas. A rota `/logs/clear-persistent` limpa o arquivo persistente para uso controlado em laboratorio. Essa rota nao possui autenticacao nesta fase e nao deve ser exposta em rede publica.

## Firewall didatico

O firewall didatico observa acessos HTTP ao painel embarcado. Ele registra contadores de requisicoes, ultimo IP, ultima rota, eventos de seguranca e uma regra simples de flood por janela de tempo.

A rota `/demo/flood` gera uma simulacao controlada para demonstrar o comportamento sem executar ataque real. O mecanismo nao filtra pacotes de rede gerais, nao faz NAT, nao inspeciona HTTPS e nao substitui firewall profissional.

## IDS didatico

O IDS atual tambem e didatico e baseado no trafego HTTP recebido pelo painel. Ele registra eventos para flood, rotas inexistentes e caminhos sensiveis simulados usados em demonstracao. A rota `/demo/ids` adiciona uma assinatura controlada para a apresentacao.

O IDS nao e IDS/IPS profissional. Ele nao analisa payloads complexos, nao inspeciona HTTPS e nao monitora trafego externo ao servidor web embarcado.

## Paginas HTML embarcadas

As paginas sao geradas no firmware como HTML embarcado:

- `/`: dashboard principal.
- `/demo`: roteiro guiado de apresentacao.
- `/gateway`: visao AP+STA e IDS didatico.
- `/evidencias`: pagina de apoio para coleta de evidencias.
- `/logs` e `/eventos`: visualizacao de eventos.

O dashboard nao depende de recurso externo. CSS e JavaScript necessarios ficam embarcados na resposta gerada pelo ESP32.

## APIs JSON

As APIs JSON permitem validar o sistema com navegador, ferramentas HTTP e smoke tester:

- `/api/status`: estado geral, performance, armazenamento, gateway, firewall, IDS, energia e tasks.
- `/api/events`: eventos recentes em RAM.
- `/api/events/persistent`: eventos persistidos em LittleFS.

Essas APIs nao devem expor dado sensivel. O foco e telemetria de laboratorio e verificacao tecnica.

## Smoke tester externo

O script `tools/smoke_test_http.py` executa validacao externa das principais paginas, APIs e rotas demo. Ele usa apenas Python 3 standard library e pode gerar relatorio Markdown em `evidencias/`.

Durante desenvolvimento, o smoke test documentado reduz a necessidade de prints a cada microteste. As evidencias finais continuam reservadas para os grandes marcos da entrega.

## Sensores fisicos como fase final

A integracao INA219 esta preparada no firmware para leitura de tensao, corrente e potencia via I2C. Se o sensor nao for detectado, o sistema continua operando e registra aviso.

Os sensores fisicos adicionais, como DHT22 e MQ-2, ficam para a fase final porque dependem de montagem, ligacao adequada, eventual solda e teste em bancada. A documentacao e a apresentacao devem deixar claro quando um dado ainda esta indisponivel ou depende de hardware real.

## Configuracao Wi-Fi upstream pelo painel

A sprint adiciona a pagina `/wifi` para salvar, limpar e reconectar a rede Wi-Fi upstream. O ESP32 preserva `WiFi.mode(WIFI_AP_STA)`: o AP local `ESP32-Firewall-Lab` segue como caminho principal de acesso e recuperacao, enquanto a interface STA tenta conectar ao upstream salvo.

A configuracao local usa LittleFS no arquivo `/wifi.json`, reaproveitando a infraestrutura ja inicializada para logs persistentes. A passphrase fica armazenada apenas localmente para permitir a conexao STA e nao e renderizada em HTML, nao entra em `/api/status`, nao aparece em logs e nao e impressa no Serial.

A tentativa de conexao usa timeout curto e controlado. Se o upstream falhar, o dashboard, `/wifi`, `/gateway` e demais rotas continuam acessiveis pelo AP local. NAT e experimental; monitoramento profundo de pacotes permanece fora do escopo.

## NAT experimental

O firmware possui a flag `NAT_EXPERIMENTAL_ENABLED` para tentar habilitar NAT/NAPT quando o AP esta ativo, a STA esta conectada ao upstream e ha IP upstream valido. A tentativa usa suporte lwIP quando disponivel no core Arduino-ESP32 instalado.

O snapshot NAT mantem `experimentalEnabled`, `supported`, `enabled`, `active`, `lastAttemptMs`, `lastStatus`, `lastError` e `note`. Esses dados aparecem em `/gateway`, `/evidencias` e `/api/status`.

Se o core/lwIP nao tiver NAPT/IP forward linkavel, o sistema registra evento e mostra `nao suportado`. O fallback esperado e manter AP, painel, `/wifi` e demais rotas funcionando sem travar.
