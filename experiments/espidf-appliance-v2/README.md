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
- Lista didática de domínios suspeitos: `malware.test`, `phishing.test`, `suspicious.test` e `bad.example`.
- Dashboard local sem CDN.

## Configuração local

Copie `include/config.example.h` para `include/config.local.h` e ajuste a rede upstream da bancada:

```c
#define APPLIANCE_V2_UPSTREAM_SSID "SSID_DA_BANCADA"
#define APPLIANCE_V2_UPSTREAM_PASSWORD "SENHA_DA_BANCADA"
```

`include/config.local.h` é ignorado pelo Git e não deve ser versionado.

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
- `/dns`
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
- `/api/status` expõe `time.*` e resumo `dns.*`; `/api/dns` expõe o histórico DNS recente.

## Estabilidade

- A task do `esp_http_server` usa stack ampliada para reduzir risco de overflow nos handlers HTML/JSON.
- Buffers grandes de DNS e snapshots de `/api/dns` ficam em heap, não na stack do HTTPD.
- O proxy DNS usa timeout curto no upstream e não gera evento para cada consulta comum.
- Reconexão STA usa backoff simples fora do evento de disconnect para evitar tentativas em rajada.
- Há diagnóstico leve no boot com heap livre, heap mínimo e high-water mark das tasks próprias quando disponível.

## Pendências de bancada

- O build/upload observado na bancada mostrou aviso `Expected 4MB, found 2MB`. A flash real do módulo precisa ser confirmada no próximo teste físico.
- Não alterar `board_build.flash_size` nem partições no escuro; se a bancada confirmar 2MB, ajustar `platformio.ini` em sprint própria.

## Limitações

- Não há firewall profissional, IDS/IPS completo, WAF, SIEM, sniffing de conteúdo nem inspeção HTTPS.
- O monitor DNS mostra domínios consultados, não conteúdo das páginas.
- Eventos HTTP/DNS ficam somente em RAM e são perdidos ao reiniciar.
- Logs são filtrados; use `/traffic` para observar requests normais e top routes.
- Os contadores de rotas e DNS são simples, RAM-only e não persistentes.
- O proxy DNS é mínimo, experimental e didático; registra consultas A/AAAA simples e encaminha por UDP em melhor esforço.
- NAT depende de upstream STA com IP válido.
- Sem persistência, sensores, atuadores e FreeRTOS completo nesta PoC.
- Sem senha real em arquivo versionável.
