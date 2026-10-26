# Hardening

Controles de segurança que o firmware implementa hoje, riscos que continuam abertos e o que mudaria numa versão de produção. O projeto é didático e de laboratório; esta lista existe para deixar claro onde termina o que foi construído.

## Controles implementados

| Controle | Onde | Detalhe |
|---|---|---|
| Credencial do AP fora do código | `include/secrets.h` (ignorado pelo git) | O build falha com `#error` se o arquivo não existir. O modelo público é `include/secrets_example.h`. |
| Passphrase upstream nunca exibida | `/wifi`, `/gateway`, `/api/status`, logs e Serial | A interface informa apenas se existe uma passphrase salva (`passphrase_present`). |
| Validação de entrada no `/wifi` | `isValidSsidLength`, `isValidPassphraseLength` | SSID de 1 a 32 caracteres e passphrase de 8 a 63 (limites do WPA2). Entrada inválida gera evento `WARN` e não é salva. |
| Escape de saída | `appendHtmlEscaped`, `appendJsonEscaped` | Rotas, eventos, SSID e mensagens de erro passam por escape antes de entrar no HTML ou no JSON. |
| Detecção de flood HTTP | `FIREWALL_FLOOD_THRESHOLD`, `FIREWALL_FLOOD_WINDOW_MS` | Mais de 20 requisições em 10 s geram evento `SECURITY`, com cooldown para não lotar o buffer. |
| Detecção de varredura | `IDS_SCAN_404_THRESHOLD`, `IDS_SCAN_WINDOW_MS` | 5 respostas 404 em 15 s geram evento `SECURITY` de origem `IDS`. |
| Caminhos sensíveis | IDS didático | Acessos a rotas como `/admin`, `/login`, `/wp-admin` e `/etc/passwd` viram eventos do IDS. |
| Persistência seletiva | `/events.log` no LittleFS | Só `WARN`, `ERROR`, `SECURITY` e eventos de sistema vão para a flash, com rotação em 16 KB. |
| Falha segura de sensor | leitura do INA219 | Sensor ausente gera `WARN` e a interface mostra `n/d`; o restante do sistema continua. |
| Recuperação | AP local sempre ativo | Se o upstream falhar, o AP `ESP32-Firewall-Lab` continua em `192.168.4.1`. |

## Vulnerabilidade corrigida: XSS armazenado nos logs

Até outubro de 2026, a rota acessada e o valor dos eventos eram concatenados direto no HTML de `/logs`, `/eventos`, `/evidencias` e do dashboard. Esses valores vêm de `server.uri()`, ou seja, de quem faz a requisição. Uma requisição para uma rota contendo HTML, feita com qualquer cliente HTTP, gerava um evento do IDS que executava script no navegador de quem abrisse os logs.

É o cenário clássico de atacar o analista pelo próprio painel de monitoramento. A correção passou `message`, `value`, `lastRoute`, `lastError` e `upstreamSsid` por `appendHtmlEscaped`, como as demais saídas já faziam.

## Riscos conhecidos

| Risco | Impacto | Em produção |
|---|---|---|
| `/wifi`, `/wifi/save`, `/wifi/clear` e `/logs/clear-persistent` sem autenticação | qualquer cliente do AP troca o upstream ou apaga os logs persistentes | autenticação no painel e sessão com expiração |
| Ações que mudam estado aceitam `GET` (`/wifi/clear`, `/wifi/reconnect`, `/logs/clear-persistent`) | uma página maliciosa aberta pelo operador pode disparar a ação (CSRF) | só `POST`, com token anti-CSRF |
| Painel em HTTP, sem TLS | o tráfego do painel fica legível para quem está no mesmo AP | TLS no servidor ou acesso só por rede de gestão |
| Passphrase upstream em texto puro em `/wifi.json` (LittleFS) | quem tem acesso físico à placa consegue extrair a credencial | NVS criptografado com flash encryption e secure boot v2 |
| Firewall só detecta e registra | flood e varredura não são bloqueados | bloqueio por IP com expiração, allowlist e modo de contenção |
| Visão limitada ao HTTP do painel | tráfego entre clientes e outros protocolos não é observado | captura em modo promíscuo ou sensor dedicado |
| Buffer de 40 eventos em RAM e rotação que apaga o arquivo em 16 KB | um flood pode empurrar eventos antigos para fora | envio dos eventos para um coletor externo (syslog ou SIEM) |
| Horário relativo ao boot | difícil correlacionar com outros sistemas | NTP no upstream ou RTC |
| NAT experimental | com NAT ativo, clientes do AP chegam ao upstream sem filtragem | manter desligado fora do laboratório |

## Como validar

- `python3 tools/smoke_test_http.py --base-url http://192.168.4.1` confere as rotas e confirma que a passphrase não aparece nas respostas.
- `/demo/flood`, `/demo/ids` e `/demo/scan` geram eventos `SECURITY` controlados para conferir a detecção.
- O CI compila o firmware e roda o Gitleaks no histórico inteiro a cada push.
