# Roteiro de demo

Este roteiro serve como guia de fala para apresentar o ESP32 Mini Firewall Gateway ao professor. A ideia e mostrar primeiro o sistema funcionando, depois os eventos e por fim as limitacoes honestas da sprint.

## Preparacao

1. Ligar o ESP32 e aguardar o boot.
2. No computador ou celular, conectar ao AP `ESP32-Firewall-Lab`.
3. Abrir o navegador em `http://192.168.4.1/demo`.
4. Manter tambem uma aba com `http://192.168.4.1/`.

Fala sugerida: "O sistema esta rodando fisicamente no ESP32. O proprio microcontrolador cria o ponto de acesso local e hospeda a interface web, entao a demonstracao nao depende de servidor externo."

## Abrir a demo guiada

Na rota `/demo`, mostrar o resumo da versao, os links principais e a lista de passos.

Fala sugerida: "Esta pagina concentra a apresentacao. Ela foi criada para evitar depender de comandos avulsos durante a defesa e para deixar as limitacoes visiveis no proprio sistema."

## Mostrar o dashboard

Abrir `/` pelo botao Dashboard.

Mostrar:

- uptime;
- heap livre e heap minimo;
- flash e sketch;
- tasks FreeRTOS;
- tempos de funcoes;
- modulos ativos;
- energia/INA219 quando disponivel;
- resumo de firewall, IDS e gateway.

Fala sugerida: "A aba principal concentra metricas de performance e estado do sistema. Algumas metricas sao reais do ESP32, como heap e uptime. Sensores fisicos aparecem como indisponiveis quando ainda nao estao montados."

## Mostrar o gateway

Abrir `/gateway`.

Mostrar:

- modo AP+STA;
- SSID e IP do AP;
- estado do upstream;
- quantidade de clientes no AP;
- contadores de IDS didatico.

Fala sugerida: "O gateway desta sprint e didatico. O ESP32 opera em AP+STA, mostra telemetria da rede local e do upstream quando configurado, e NAT aparece como tentativa experimental, dependendo do suporte do core/lwIP."

## Gerar eventos INFO, WARN e SECURITY

Voltar para `/demo` ou usar os botoes em `/logs`.

Acionar:

- `/demo/info`;
- `/demo/warn`;
- `/demo/security`.

Depois abrir `/logs`.

Fala sugerida: "Estas rotas geram eventos controlados para demonstrar os niveis de log. Elas nao representam falha real nem ataque real; sao gatilhos de apresentacao."

## Simular flood didatico

Acionar `/demo/flood` e voltar para `/logs`.

Fala sugerida: "Aqui eu gero uma simulacao controlada de flood sobre o proprio painel. O objetivo e mostrar o contador e o evento SECURITY sem executar ataque real contra rede externa."

## Simular IDS didatico

Acionar `/demo/ids` e abrir `/gateway` ou `/logs`.

Fala sugerida: "O IDS desta fase e baseado em HTTP do painel. Ele detecta cenarios didaticos como rotas suspeitas, caminhos sensiveis simulados e o evento controlado desta rota. Ele nao e IDS/IPS profissional."

## Mostrar logs em RAM

Abrir `/api/events` no navegador.

Fala sugerida: "Esta API mostra o buffer circular em RAM. Ele e util para verificar rapidamente os ultimos eventos, mas e temporario e pode ser perdido em reboot."

## Mostrar logs persistentes

Abrir `/api/events/persistent`.

Fala sugerida: "Os eventos relevantes tambem sao salvos no LittleFS. A persistencia e seletiva para reduzir escrita na flash. Eventos comuns de consulta nao precisam ir para arquivo."

Se for necessario limpar antes de uma nova apresentacao, usar `/logs/clear-persistent` somente de forma controlada.

## Rodar smoke test

No terminal, a partir da raiz do projeto:

```bash
python3 tools/smoke_test_http.py --base-url http://192.168.4.1
```

Fala sugerida: "O smoke test externo valida as principais paginas, APIs e rotas demo. Ele substitui prints repetitivos durante desenvolvimento, mas as evidencias finais ainda serao coletadas nos marcos grandes."

## Explicar limitacoes

Encerrar mostrando a secao de limitacoes em `/demo`.

Pontos obrigatorios:

- NAT e experimental e pode aparecer como nao suportado no core atual.
- O firewall e didatico e limitado aos acessos HTTP ao painel.
- O IDS e didatico e baseado em HTTP do painel.
- O sistema nao inspeciona HTTPS.
- O projeto nao substitui firewall profissional, roteador real ou IDS/IPS.
- Sensores fisicos adicionais ficam para a fase final.
- INA219 esta preparado, mas o teste fisico depende da montagem real.

Fala sugerida: "A proposta e academica e de bancada. O valor tecnico esta em mostrar um sistema ciberfisico real com ESP32, interface embarcada, metricas, eventos, persistencia seletiva e demonstracoes controladas, sem prometer comportamento de equipamento profissional."

## Mostrar configuracao Wi-Fi upstream

Abrir `/wifi` depois de mostrar `/gateway`.

Fala sugerida: "Esta tela permite configurar a rede Wi-Fi upstream sem regravar o firmware. Mesmo se a conexao externa falhar, o AP local do ESP32 continua ativo para recuperacao em `192.168.4.1`."

Mostrar:

- se ha SSID salvo;
- se ha passphrase configurada, sem exibir o valor;
- status conectado/desconectado;
- IP e RSSI quando conectado;
- ultimo erro ou ultima tentativa;
- botoes para salvar, reconectar e limpar.

Fala sugerida: "A passphrase nao aparece na interface, API, logs ou Serial. Esta tela ainda nao tem autenticacao e por isso e restrita ao laboratorio."

## Mostrar NAT experimental

Abrir `/gateway` depois de conectar o upstream em `/wifi`.

Fala sugerida: "Esta sprint tenta habilitar NAT experimental para clientes do AP usarem o upstream do ESP32. O firmware mostra se a flag esta ligada, se o core suporta NAPT e se o NAT ficou ativo."

Se aparecer `nao suportado`, explicar: "O firmware nao travou; ele detectou que o core/lwIP atual nao oferece NAPT linkavel. O AP local e o painel continuam funcionando."

Teste manual, se houver suporte: conectar outro cliente ao AP `ESP32-Firewall-Lab` e tentar acessar um site HTTP/HTTPS. O resultado nao e prometido como roteador profissional.
