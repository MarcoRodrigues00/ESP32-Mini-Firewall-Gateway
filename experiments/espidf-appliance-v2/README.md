# ESP-IDF Appliance v2

PoC isolada para unir NAT/NAPT real em ESP-IDF com um dashboard HTTP demonstrável. Esta pasta não migra o firmware principal Arduino/PlatformIO e não substitui a implementação principal do TDE.

## Escopo

- Framework ESP-IDF via PlatformIO.
- Wi-Fi em modo AP+STA.
- NAPT real via `CONFIG_LWIP_IP_FORWARD` e `CONFIG_LWIP_NAPT`.
- NAPT habilitado apenas após `IP_EVENT_STA_GOT_IP`.
- Servidor web com `esp_http_server`.
- Eventos filtrados de boot, Wi-Fi, NAT e segurança didática mantidos em RAM.
- Requests normais de dashboard/API não viram evento de log para evitar ruído de polling.
- Contadores de tráfego HTTP, 404, rotas sensíveis, demo scan, total requests e top routes simples.
- SNTP iniciado após IP no STA, com horário `America/Sao_Paulo` quando houver internet.
- Monitor/proxy DNS experimental em UDP porta 53 para consultas A/AAAA dos clientes do AP, com encaminhamento para `1.1.1.1` e fallback `8.8.8.8`.
- Camada IDS de metadados v0.3 com clientes observados em RAM, contagem DNS por cliente, domínios únicos aproximados, burst DNS e score didático.
- Lista didática de domínios suspeitos: `malware.test`, `phishing.test`, `suspicious.test` e `bad.example`.
- Dashboard local sem CDN.
- Display local opcional atras de feature flag, para estado visual do appliance quando o driver/pinout forem confirmados.

## Configuração local

Copie `include/config.example.h` para `include/config.local.h` e ajuste a rede upstream da bancada:

```c
#define APPLIANCE_V2_UPSTREAM_SSID "SSID_DA_BANCADA"
#define APPLIANCE_V2_UPSTREAM_PASSWORD "SENHA_DA_BANCADA"
```

`include/config.local.h` é ignorado pelo Git e não deve ser versionado.

## Display local opcional

A v2 tem uma camada defensiva de display local, desabilitada por padrao porque o controlador e o pinout do ESP32 com tela integrada ainda nao foram confirmados no repositorio. Sem configuracao explicita, o firmware mantem AP, NAT, DNS e HTTP funcionando como antes.

Para testar em bancada, preencha apenas em `include/config.local.h`:

```c
#define APPLIANCE_V2_ENABLE_DISPLAY 1
#define APPLIANCE_V2_DISPLAY_WIDTH 240
#define APPLIANCE_V2_DISPLAY_HEIGHT 240
#define APPLIANCE_V2_DISPLAY_DRIVER APPLIANCE_V2_DISPLAY_DRIVER_ST7789
#define APPLIANCE_V2_DISPLAY_PIN_MOSI 23
#define APPLIANCE_V2_DISPLAY_PIN_MISO -1
#define APPLIANCE_V2_DISPLAY_PIN_SCLK 18
#define APPLIANCE_V2_DISPLAY_PIN_CS 5
#define APPLIANCE_V2_DISPLAY_PIN_DC 16
#define APPLIANCE_V2_DISPLAY_PIN_RST 17
#define APPLIANCE_V2_DISPLAY_PIN_BL 4
```

Os drivers leves previstos sao `APPLIANCE_V2_DISPLAY_DRIVER_ST7789` e `APPLIANCE_V2_DISPLAY_DRIVER_ILI9341`, ambos via SPI do ESP-IDF. Os pinos acima sao exemplo e nao devem ser usados sem conferir o modulo real. Se algum pino obrigatorio ficar `-1` ou o SPI falhar, o display fica `available=false` e o firmware continua rodando.

Estados visuais:

- `NORMAL`: sem DNS suspeito recente, sem ataque recente e maior `risk_score` abaixo de 15.
- `SUSPICIOUS_DNS`: dominio suspeito observado nos ultimos 5 minutos; mostra `DNS SUS` e o ultimo dominio abreviado.
- `ATTACK`: evento `SECURITY` HTTP, burst DNS recente ou maior `risk_score >= 15`; o estado fica retido por ate 60 segundos quando vem de evento recente.

Checks no rodape do display:

- `UP`: verde com STA conectado/IP, amarelo reconectando, vermelho se configurado e indisponivel, cinza se sem upstream configurado.
- `NAT`: verde com `nat.active=true`, amarelo aguardando upstream, vermelho se tentou e falhou com upstream conectado, cinza quando ainda nao tentou.
- `IDS`: verde normal, amarelo em `SUSPICIOUS_DNS`, vermelho em `ATTACK`.

`/api/status`, dashboard `/` e `/report` mostram `display.enabled`, `display.available`, `display.state` e `display.last_update_ms`.

## Build

```bash
pio run -d experiments/espidf-appliance-v2
```

## Rotas

- `/`
- `/status`
- `/api`
- `/api/status`
- `/api/events`
- `/api/dns`
- `/api/clients`
- `/dns`
- `/clients`
- `/logs`
- `/traffic`
- `/report`
- `/demo`
- `/demo/scan`
- `/demo/security`
- `/demo/info`
- `/favicon.ico`

Rotas sensíveis registradas para demonstração didática:

- `/admin`
- `/login`
- `/wp-admin`
- `/etc/passwd`
- `/api`
- `/config`
- `/debug`

Essas rotas incrementam `sensitive_path_hits`; rotas com padrão de varredura simples incrementam também `suspicious_scan_count`. Requests normais como `/`, `/api/status`, `/api/events`, `/api/dns`, `/logs`, `/traffic`, `/dns` e `/report` continuam contabilizados em `/traffic`, mas não geram evento INFO a cada polling.

## DNS e horário

- O DHCP do AP entrega o próprio ESP32 (`192.168.4.1`) como DNS.
- O proxy DNS registra domínio, IP do cliente, tipo A/AAAA, uptime e timestamp quando SNTP estiver sincronizado.
- Consultas comuns ficam em uma lista própria `recent_queries` e não geram evento para cada domínio.
- O primeiro domínio observado gera evento INFO; domínios da lista didática suspeita geram evento SECURITY e incrementam `suspicious_count`.
- `/api/status` expõe `time.*`, resumo `dns.*` e os objetos `clients_observed`/`ids`.
- `/api/dns` expõe o histórico DNS recente.
- `/clients` e `/api/clients` expõem clientes observados, `first_seen`, `last_seen`, contadores DNS, último domínio, `risk_score` e classificação.

## IDS de metadados v0.3

- O modelo de clientes é pequeno e RAM-only, com capacidade de 8 slots.
- O score é heurístico e didático: +5 por domínio suspeito, +1 por burst DNS e +2 quando o cliente passa do limite de domínios únicos aproximados.
- Classificação: 0-4 baixo, 5-14 atenção, 15+ suspeito.
- Burst DNS usa janela curta por uptime e cooldown para evitar spam de eventos `SECURITY`.
- Consultas DNS comuns atualizam contadores e histórico, mas não geram evento INFO por consulta.
- A implementação observa DNS/metadados disponíveis no AP e não tenta descriptografar HTTPS nem ler conteúdo de páginas.

## Estabilidade

- A task do `esp_http_server` usa stack ampliada para reduzir risco de overflow nos handlers HTML/JSON.
- Buffers grandes de DNS e snapshots de `/api/dns`/`/api/clients` ficam em heap, não na stack do HTTPD.
- O proxy DNS usa timeout curto no upstream e não gera evento para cada consulta comum.
- Reconexão STA usa backoff simples fora do evento de disconnect para evitar tentativas em rajada.
- Há diagnóstico leve no boot com heap livre, heap mínimo e high-water mark das tasks próprias quando disponível.

## Pendências de bancada

- O build/upload observado na bancada mostrou aviso `Expected 4MB, found 2MB`. A flash real do módulo precisa ser confirmada no próximo teste físico.
- Não alterar `board_build.flash_size` nem partições no escuro; se a bancada confirmar 2MB, ajustar `platformio.ini` em sprint própria.

## Limitações

- Não há firewall profissional, IDS/IPS completo, WAF, SIEM, sniffing de conteúdo nem inspeção HTTPS.
- O monitor DNS mostra domínios consultados, não conteúdo das páginas.
- Eventos HTTP/DNS e clientes observados ficam somente em RAM e são perdidos ao reiniciar.
- Logs são filtrados; use `/traffic` para observar requests normais e top routes.
- Os contadores de rotas, DNS e risco por cliente são simples, RAM-only e não persistentes.
- O proxy DNS é mínimo, experimental e didático; registra consultas A/AAAA simples e encaminha por UDP em melhor esforço.
- NAT depende de upstream STA com IP válido.
- Sem persistência, sensores, atuadores e FreeRTOS completo nesta PoC.
- Sem senha real em arquivo versionável.
