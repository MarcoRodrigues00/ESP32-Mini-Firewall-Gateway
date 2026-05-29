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

## `/wifi`

- Metodo: `GET`.
- Tipo de resposta: `text/html`.
- Finalidade: configurar e diagnosticar a rede Wi-Fi upstream mantendo o AP local de recuperacao ativo.
- Observacao de seguranca: exibe SSID e indicadores, mas nunca exibe a credencial/passphrase salva. Nao possui autenticacao nesta fase; usar somente em laboratorio.

## `/wifi/save`

- Metodo: `POST`.
- Tipo de resposta: redirecionamento `303` para `/wifi`.
- Finalidade: receber SSID e passphrase, validar tamanho, salvar em LittleFS e tentar conexao upstream com timeout controlado.
- Observacao de seguranca: a passphrase nao e registrada em eventos, Serial, API ou relatorio.

## `/wifi/clear`

- Metodo: `GET` ou `POST`.
- Tipo de resposta: redirecionamento `303` para `/wifi`.
- Finalidade: remover a configuracao upstream salva, desconectar a STA e manter o AP local ativo.
- Observacao: rota didatica sem autenticacao nesta fase.

## `/wifi/reconnect`

- Metodo: `GET`.
- Tipo de resposta: redirecionamento `303` para `/wifi`.
- Finalidade: tentar reconectar usando a configuracao upstream salva.
- Observacao: NAT real continua nao implementado.

## Campos de Wi-Fi em `/api/status`

O objeto `gateway` foi expandido e o alias `wifi_upstream` foi adicionado com campos de estado sem expor a passphrase: `configured`/`sta_configured`, `ssid_present`, `ssid_masked`, `passphrase_present`, `connected`/`sta_connected`, `ip`/`upstream_ip`, `rssi`/`upstream_rssi`, `last_attempt_ms`, `last_status` e `last_error`.

## Objeto `nat` em `/api/status`

A rota `/api/status` inclui o objeto `nat` para a sprint NAT experimental:

- `experimental_enabled`: indica a feature flag `NAT_EXPERIMENTAL_ENABLED`;
- `supported`: indica se o build/core tem suporte NAPT/IP forward disponivel;
- `enabled`: indica se a tentativa esta habilitada no firmware;
- `active`: indica se o NAT foi marcado como ativo;
- `last_attempt_ms`: instante da ultima avaliacao/tentativa;
- `last_status`: estado textual, como `ativo`, `aguardando upstream` ou `nao suportado`;
- `last_error`: ultimo erro textual;
- `note`: observacao de escopo.

Campos resumidos tambem aparecem em `gateway`: `nat_enabled`, `nat_active`, `nat_supported`, `nat_status`, `nat_error` e `nat_note`. NAT e experimental, pode nao funcionar no core atual e nao substitui roteador/firewall profissional.

## `/traffic`

- Metodo: `GET`
- Tipo: HTML
- Finalidade: mostrar o Traffic Monitor v0.1 com total de requests HTTP, top rotas, 404 suspeitos, rotas sensiveis, ultimo IP, ultima rota, User-Agent resumido e alerta didatico de scan.
- Observacao: monitora apenas o HTTP recebido pelo painel embarcado. Nao faz sniffing, nao inspeciona HTTPS e nao substitui IDS/IPS profissional.

## `/api/traffic`

- Metodo: `GET`
- Tipo: JSON
- Campos principais: `total_requests`, `not_found_count`, `sensitive_path_hits`, `suspicious_scan_count`, `ids_events`, `last_ip`, `last_route`, `last_user_agent_short`, `top_route`, `top_routes`, `scan_window_ms`, `scan_threshold` e `scan_cooldown_ms`.

## `/demo/scan`

- Metodo: `GET`
- Finalidade: simular acessos a rotas sensiveis e inexistentes, incrementar contadores do Traffic Monitor e gerar evento `SECURITY` com origem `IDS`.
- Observacao: simulacao controlada para demonstracao, sem ataque real.

## `/report`

- Metodo: `GET`
- Tipo: HTML
- Finalidade: relatorio tecnico embarcado de evidencia, com resumo de projeto, firmware, rede, gateway, NAT experimental, firewall/IDS didatico, Traffic Monitor, logs, eventos recentes, limitacoes e validacao.
- Observacao: nao e dashboard operacional nem PDF; e uma pagina simples para apresentacao e auditoria em bancada.

## `/api/report`

- Metodo: `GET`
- Tipo: JSON
- Campos principais: `project`, `version`, `uptime_ms`, `system`, `gateway`, `nat`, `firewall`, `ids`, `traffic`, `storage`, `recent_events_summary` e `limitations`.
- Observacao: nao remove nem substitui `/api/status`; e um resumo consolidado para evidencia.
