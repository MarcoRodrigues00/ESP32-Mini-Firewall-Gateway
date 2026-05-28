# Evidencias do Projeto

Este roteiro orienta os prints e registros para a defesa do ESP32 Mini Firewall Gateway. As evidencias devem mostrar o que foi realmente executado no hardware ou no ambiente de build. Se algum teste nao for realizado, registrar como pendente.

## 1. Build PlatformIO

Objetivo: comprovar que o firmware compila para `esp32dev`.

Comando:

```bash
pio run
```

Print recomendado: terminal exibindo `SUCCESS`, uso de RAM e uso de flash.

## 2. Upload para o ESP32

Objetivo: comprovar que o firmware foi gravado na placa fisica.

Comando:

```bash
pio run -t upload
```

Print recomendado: terminal com gravacao concluida sem erro.

## 3. Monitor serial

Objetivo: comprovar boot, versao do firmware, inicio do Wi-Fi AP e heartbeat.

Comando:

```bash
pio device monitor -b 115200
```

Print recomendado: linhas com nome do projeto, versao, IP do AP, heartbeat e evento de INA219 iniciado ou nao detectado.

## 4. Demo guiada

Objetivo: usar uma tela unica como roteiro da apresentacao ao professor.

Endereco:

```text
http://192.168.4.1/demo
```

Print recomendado: pagina mostrando status resumido, etapas da demonstracao, botoes para eventos demo, bloco Como apresentar e limitacoes de NAT, IDS, HTTPS e sensores fisicos.

## 5. Pagina `/evidencias`

Objetivo: obter uma tela com aparencia de relatorio academico para anexar na apresentacao.

Passos:

1. Conectar o computador ao Wi-Fi `ESP32-Firewall-Lab`.
2. Abrir `http://192.168.4.1/evidencias`.
3. Tirar print mostrando nome do projeto, versao, IP local, Wi-Fi, uptime, heap livre, resumo de energia, status dos modulos, quantidade de eventos e os ultimos 5 eventos reais.
4. Confirmar que o acesso a pagina gerou evento `WEB` para `/evidencias`.

## 6. Dashboard principal

Objetivo: comprovar a interface web embarcada com abas obrigatorias.

Endereco:

```text
http://192.168.4.1/
```

Print recomendado: painel principal com Resumo, Gateway, Firewall didatico, Metricas do sistema, Energia, Modulos, tasks e tempos de execucao.

## 7. API de status

Objetivo: comprovar endpoint JSON para coleta tecnica.

Endereco:

```text
http://192.168.4.1/api/status
```

Registrar o JSON retornado ou salvar em arquivo de evidencias. O retorno deve incluir `project_name`, `firmware_version`, `wifi_connected`, `ip`, `uptime_ms`, `free_heap`, `modules`, `energy`, `firewall`, `gateway`, `ids` e `storage`/`persistence`.

## 8. Firewall didatico

Objetivo: comprovar a camada didatica de seguranca baseada nos acessos HTTP ao painel.

Verificar em `/`, `/gateway` e `/evidencias`:

- firewall didatico ativo;
- modo Wi-Fi AP ou AP+STA;
- AP `ESP32-Firewall-Lab` ativo em `192.168.4.1`;
- upstream configurado, conectado ou nao configurado;
- clientes conectados ao AP, quando disponivel;
- total de requisicoes HTTP;
- eventos `SECURITY`;
- contadores IDS;
- ultima rota acessada;
- ultimo IP cliente, quando disponivel;
- regra de flood: mais de 20 requisicoes em 10 segundos.

Rotas de teste controlado:

```text
http://192.168.4.1/demo/security
http://192.168.4.1/demo/flood
http://192.168.4.1/demo/ids
```

A rota `/demo/flood` registra uma simulacao controlada de excesso de requisicoes. A rota `/demo/ids` registra uma assinatura IDS didatica. Nao executar ataque real para a apresentacao; a demonstracao deve usar as rotas demo e, se necessario, acessos normais ao painel.

Limite: esta camada nao e firewall profissional, nao inspeciona HTTPS, nao implementa NAT/roteamento real nesta sprint e nao substitui IDS/IPS, WAF, SIEM ou roteador real.

## 9. Gateway AP+STA e IDS

Objetivo: comprovar que o ESP32 mantem o AP local, expoe telemetria de gateway em `/gateway` e registra eventos de IDS didatico.

Prints recomendados:

- pagina `/gateway`;
- bloco Gateway no dashboard `/`;
- resumo Gateway/IDS em `/evidencias`;
- objeto `gateway` e campos IDS em `/api/status`;
- evento `SECURITY` gerado por `/demo/ids` em `/logs`.

Registrar como limitacao que NAT/roteamento real nao faz parte desta sprint.

## 10. INA219 e energia

Objetivo: comprovar metricas reais de tensao, corrente e potencia quando o sensor estiver conectado.

Ligacao prevista:

- `VIN` do INA219 em `3V3`;
- `GND` em `GND` comum;
- `SDA` em `GPIO 21`;
- `SCL` em `GPIO 22`;
- circuito de medicao do INA219 em serie com a carga/fonte monitorada.

Prints recomendados:

- bloco Energia no dashboard `/`;
- resumo Energia em `/evidencias`;
- objeto `energy` em `/api/status`;
- evento `INA219 iniciado` em `/logs`.

Se o sensor estiver desconectado, registrar print mostrando Energia `indisponivel` e evento `INA219 nao detectado`. Esse estado e esperado em teste sem hardware e nao deve travar o firmware. Os thresholds de tensao baixa, corrente alta e potencia alta sao didaticos nesta fase.

## 11. Logs e eventos em memoria

Objetivo: comprovar o buffer circular de eventos em RAM.

Enderecos:

```text
http://192.168.4.1/logs
http://192.168.4.1/eventos
http://192.168.4.1/api/events
```

Print recomendado: pagina `/logs` em tabela compacta mostrando quantidade/capacidade, badges por nivel, source, id, uptime, mensagem e value quando existir.

Registrar tambem o JSON de `/api/events`, que deve incluir `count`, `capacity` e a lista `events`.

## 12. Eventos demo para apresentacao

Objetivo: demonstrar os niveis INFO, WARN e SECURITY de forma controlada, sem depender de falha real.

Rotas:

```text
http://192.168.4.1/demo/info
http://192.168.4.1/demo/warn
http://192.168.4.1/demo/security
http://192.168.4.1/demo/flood
http://192.168.4.1/demo/ids
```

Passos:

1. Abrir `/logs`.
2. Acionar as rotas demo, incluindo `/demo/flood` e `/demo/ids`.
3. Voltar para `/logs` e tirar print dos eventos gerados, com destaque para `SECURITY`.
4. Abrir `/evidencias` e tirar print dos ultimos 5 eventos reais.

Observacao: os eventos demo sao simulacoes controladas para apresentacao. Eles nao indicam falha real de sensor, atuador ou ataque real; servem apenas para demonstrar a classificacao visual INFO, WARN e SECURITY, incluindo eventos IDS didaticos.

## 13. Limitacoes registradas

Os eventos recentes continuam em buffer circular de RAM e sao perdidos ao reiniciar. Eventos relevantes tambem sao gravados em LittleFS em `/events.log`, com limite atual de 16 KB e rotacao simples. Historico completo de 24 horas ainda depende de teste prolongado e deve ser documentado como pendente/parcial se nao for executado antes da defesa.


## 14. Prints recomendados

- Dashboard `/` com blocos Resumo, Firewall didatico, Metricas do sistema e Energia.
- Pagina `/evidencias` como relatorio de execucao com resumo do INA219.
- Pagina `/logs` com tabela de eventos e badges INFO/WARN/SECURITY.
- JSON de `/api/status` com objetos `firewall` e `energy`.
- JSON de `/api/events` para evidenciar eventos do sensor e eventos demo.


## 11. Persistencia controlada em LittleFS

Nesta fase, os prints devem confirmar que a persistencia esta disponivel, mas a coleta formal de evidencias completas pode ficar para a etapa final de documentacao.

Itens para verificar em bancada:

- `/logs` mostrando status do LittleFS, tamanho do arquivo e limite.
- `/evidencias` mostrando LittleFS ativo ou indisponivel e a politica resumida.
- `/api/status` contendo o objeto `storage` ou `persistence`.
- `/api/events/persistent` retornando `available`, `file_size`, `max_size`, `path`, `policy`, `rotated` e `lines`.
- `/logs/clear-persistent` limpando o arquivo e voltando para `/logs`.

Politica registrada:

- eventos em RAM continuam em `/api/events`;
- eventos persistentes ficam em `/events.log`;
- somente WARN, ERROR, SECURITY e eventos importantes de sistema, storage, firewall, sensor e energia sao gravados;
- acessos comuns de API nao sao persistidos para evitar desgaste da flash;
- limite atual: 16 KB;
- ao ultrapassar o limite, o arquivo antigo e apagado e um novo arquivo e iniciado.

As rotas demo continuam sendo simulacoes controladas de laboratorio. `/demo/warn`, `/demo/security`, `/demo/flood` e `/demo/ids` devem gerar registros persistentes pela politica atual; `/demo/info` permanece apenas como evento comum em RAM.
