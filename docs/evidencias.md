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

## 4. Pagina `/evidencias`

Objetivo: obter uma tela com aparencia de relatorio academico para anexar na apresentacao.

Passos:

1. Conectar o computador ao Wi-Fi `ESP32-Firewall-Lab`.
2. Abrir `http://192.168.4.1/evidencias`.
3. Tirar print mostrando nome do projeto, versao, IP local, Wi-Fi, uptime, heap livre, resumo de energia, status dos modulos, quantidade de eventos e os ultimos 5 eventos reais.
4. Confirmar que o acesso a pagina gerou evento `WEB` para `/evidencias`.

## 5. Dashboard principal

Objetivo: comprovar a interface web embarcada com abas obrigatorias.

Endereco:

```text
http://192.168.4.1/
```

Print recomendado: painel principal com Resumo, Metricas do sistema, Energia, Modulos, tasks e tempos de execucao.

## 6. API de status

Objetivo: comprovar endpoint JSON para coleta tecnica.

Endereco:

```text
http://192.168.4.1/api/status
```

Registrar o JSON retornado ou salvar em arquivo de evidencias. O retorno deve incluir `project_name`, `firmware_version`, `wifi_connected`, `ip`, `uptime_ms`, `free_heap`, `modules` e `energy`.

## 7. INA219 e energia

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

## 8. Logs e eventos em memoria

Objetivo: comprovar o buffer circular de eventos em RAM.

Enderecos:

```text
http://192.168.4.1/logs
http://192.168.4.1/eventos
http://192.168.4.1/api/events
```

Print recomendado: pagina `/logs` em tabela compacta mostrando quantidade/capacidade, badges por nivel, source, id, uptime, mensagem e value quando existir.

Registrar tambem o JSON de `/api/events`, que deve incluir `count`, `capacity` e a lista `events`.

## 9. Eventos demo para apresentacao

Objetivo: demonstrar os niveis INFO, WARN e SECURITY de forma controlada, sem depender de falha real.

Rotas:

```text
http://192.168.4.1/demo/info
http://192.168.4.1/demo/warn
http://192.168.4.1/demo/security
```

Passos:

1. Abrir `/logs`.
2. Acionar as tres rotas demo.
3. Voltar para `/logs` e tirar print dos eventos gerados.
4. Abrir `/evidencias` e tirar print dos ultimos 5 eventos reais.

Observacao: os eventos demo sao simulacoes controladas para apresentacao. Eles nao indicam falha real de sensor, atuador ou ataque real; servem apenas para demonstrar a classificacao visual INFO, WARN e SECURITY.

## 10. Limitacoes registradas

Os eventos desta fase ficam somente em RAM e sao perdidos ao reiniciar o ESP32. Logs persistentes em LittleFS e exportacao completa serao tratados em fase posterior.


## 11. Prints recomendados

- Dashboard `/` com blocos Resumo, Metricas do sistema e Energia.
- Pagina `/evidencias` como relatorio de execucao com resumo do INA219.
- Pagina `/logs` com tabela de eventos e badges INFO/WARN/SECURITY.
- JSON de `/api/status` com objeto `energy`.
- JSON de `/api/events` para evidenciar eventos do sensor e eventos demo.
