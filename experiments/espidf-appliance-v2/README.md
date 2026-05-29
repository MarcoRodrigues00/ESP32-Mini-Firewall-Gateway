# ESP-IDF Appliance v2

PoC isolada para unir NAT/NAPT real em ESP-IDF com um dashboard HTTP demonstrável. Esta pasta não migra o firmware principal Arduino/PlatformIO e não substitui a implementação principal do TDE.

## Escopo

- Framework ESP-IDF via PlatformIO.
- Wi-Fi em modo AP+STA.
- NAPT real via `CONFIG_LWIP_IP_FORWARD` e `CONFIG_LWIP_NAPT`.
- NAPT habilitado apenas após `IP_EVENT_STA_GOT_IP`.
- Servidor web com `esp_http_server`.
- Eventos HTTP, Wi-Fi, NAT e segurança didática mantidos em RAM.
- Contadores de tráfego HTTP, 404, rotas sensíveis, demo scan e top routes simples.
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

Essas rotas incrementam `sensitive_path_hits`; rotas com padrão de varredura simples incrementam também `suspicious_scan_count`.

## Limitações

- Não há firewall profissional, IDS/IPS completo, WAF, SIEM nem inspeção HTTPS.
- Eventos ficam somente em RAM e são perdidos ao reiniciar.
- Os contadores de rotas são simples e não persistentes.
- NAT depende de upstream STA com IP válido.
- Sem persistência, sensores, atuadores e FreeRTOS completo nesta PoC.
- Sem senha real em arquivo versionável.
