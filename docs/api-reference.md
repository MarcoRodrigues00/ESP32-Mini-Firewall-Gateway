# Referencia de API e rotas

As rotas abaixo sao atendidas pelo `WebServer.h` sincrono embarcado no ESP32. Todas usam metodo `GET` na sprint atual.

## Resumo rapido

| Rota | Metodo | Resposta | Finalidade |
| --- | --- | --- | --- |
| `/` | GET | HTML | Dashboard principal |
| `/demo` | GET | HTML | Demo guiada |
| `/gateway` | GET | HTML | Telemetria AP+STA e IDS didatico |
| `/evidencias` | GET | HTML | Pagina de apoio para evidencias |
| `/logs` | GET | HTML | Eventos recentes |
| `/eventos` | GET | HTML | Alias de `/logs` |
| `/api/status` | GET | JSON | Estado geral e metricas |
| `/api/events` | GET | JSON | Eventos em RAM |
| `/api/events/persistent` | GET | JSON/texto estruturado | Eventos persistidos no LittleFS |
| `/logs/clear-persistent` | GET | HTML/redirecionamento | Limpeza manual de eventos persistentes |
| `/demo/info` | GET | HTML/redirecionamento | Gera evento INFO controlado |
| `/demo/warn` | GET | HTML/redirecionamento | Gera evento WARN controlado |
| `/demo/security` | GET | HTML/redirecionamento | Gera evento SECURITY controlado |
| `/demo/flood` | GET | HTML/redirecionamento | Simula flood didatico |
| `/demo/ids` | GET | HTML/redirecionamento | Simula assinatura IDS didatica |

## `/`

- Metodo: `GET`.
- Tipo de resposta: `text/html`.
- Finalidade: dashboard principal do sistema, com performance, modulos, tasks, firewall, IDS, gateway, energia e links principais.
- Observacao: a pagina consulta `/api/status` por JavaScript para atualizar metricas. Nao depende de recurso externo.

## `/demo`

- Metodo: `GET`.
- Tipo de resposta: `text/html`.
- Finalidade: roteiro embarcado para apresentacao do TDE, com links para dashboard, gateway, logs, APIs e eventos demo.
- Observacao: inclui limitacoes de escopo, como ausencia de NAT real, IDS didatico, ausencia de inspecao HTTPS e sensores fisicos pendentes.

## `/gateway`

- Metodo: `GET`.
- Tipo de resposta: `text/html`.
- Finalidade: mostrar telemetria do modo AP+STA, status do upstream Wi-Fi, clientes do AP e contadores de IDS didatico.
- Observacao: NAT/roteamento real nao esta implementado nesta fase. A pagina nao deve ser apresentada como gateway profissional.

## `/evidencias`

- Metodo: `GET`.
- Tipo de resposta: `text/html`.
- Finalidade: apoiar coleta de evidencias para defesa, mostrando versao, IP, uptime, memoria, armazenamento, seguranca, energia e eventos recentes.
- Observacao: e uma pagina de apoio visual; nao substitui relatorio final nem teste fisico.

## `/logs`

- Metodo: `GET`.
- Tipo de resposta: `text/html`.
- Finalidade: mostrar eventos recentes do buffer em RAM e oferecer links para APIs e rotas demo.
- Observacao: eventos em RAM sao temporarios. Para persistencia, consultar `/api/events/persistent`.

## `/eventos`

- Metodo: `GET`.
- Tipo de resposta: `text/html`.
- Finalidade: alias em portugues para `/logs`.
- Observacao: mantem compatibilidade com a nomenclatura usada no material da disciplina.

## `/api/status`

- Metodo: `GET`.
- Tipo de resposta: `application/json`.
- Finalidade: expor estado geral do sistema para dashboard, smoke test e validacao tecnica.
- Conteudo esperado: nome do projeto, versao, uptime, heap, flash, status Wi-Fi, tasks, tempos de funcoes, modulos, storage/persistencia, energia, gateway, firewall e IDS.
- Observacao: nao deve retornar dado sensivel. O campo de gateway e telemetrico; NAT real nao deve ser inferido a partir dele.

## `/api/events`

- Metodo: `GET`.
- Tipo de resposta: `application/json`.
- Finalidade: retornar o buffer circular de eventos recentes em RAM.
- Conteudo esperado: quantidade, capacidade e lista de eventos com nivel, origem, mensagem, uptime e valor opcional.
- Observacao: o buffer e volatil e pode ser perdido no reboot.

## `/api/events/persistent`

- Metodo: `GET`.
- Tipo de resposta: `application/json` ou conteudo textual estruturado gerado a partir do LittleFS.
- Finalidade: retornar eventos relevantes persistidos em `/events.log`.
- Observacao: a persistencia e seletiva para reduzir escrita na flash. Eventos comuns de consulta podem nao aparecer aqui.

## `/logs/clear-persistent`

- Metodo: `GET`.
- Tipo de resposta: `text/html` ou redirecionamento para pagina de logs.
- Finalidade: limpar manualmente o arquivo de eventos persistentes.
- Observacao de seguranca: rota didatica, sem autenticacao nesta fase. Usar apenas em rede local de laboratorio e nao expor em rede publica.

## `/demo/info`

- Metodo: `GET`.
- Tipo de resposta: `text/html` ou redirecionamento.
- Finalidade: gerar evento `INFO` controlado para demonstracao.
- Observacao: evento artificial de apresentacao, nao leitura de sensor real.

## `/demo/warn`

- Metodo: `GET`.
- Tipo de resposta: `text/html` ou redirecionamento.
- Finalidade: gerar evento `WARN` controlado para demonstracao.
- Observacao: evento artificial de apresentacao, nao falha real obrigatoria.

## `/demo/security`

- Metodo: `GET`.
- Tipo de resposta: `text/html` ou redirecionamento.
- Finalidade: gerar evento `SECURITY` controlado para demonstracao.
- Observacao: nao representa ataque real nem defesa profissional.

## `/demo/flood`

- Metodo: `GET`.
- Tipo de resposta: `text/html` ou redirecionamento.
- Finalidade: simular flood didatico contra o painel para gerar evento de seguranca.
- Observacao de escopo: simulacao controlada, sem trafego ofensivo real e sem teste de firewall profissional.

## `/demo/ids`

- Metodo: `GET`.
- Tipo de resposta: `text/html` ou redirecionamento.
- Finalidade: simular uma assinatura de IDS didatico e registrar evento relacionado.
- Observacao de escopo: IDS baseado no HTTP do painel. Nao inspeciona HTTPS e nao substitui IDS/IPS real.
