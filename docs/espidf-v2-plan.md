# Plano da PoC ESP-IDF Appliance v2

## Objetivo

Criar uma PoC isolada em `experiments/espidf-appliance-v2/` para validar AP+STA, NAT/NAPT real e dashboard mínimo em ESP-IDF antes de qualquer migração do firmware principal.

## Entregas desta sprint

- Projeto ESP-IDF compilável via PlatformIO.
- Configuração local separada e ignorada pelo Git.
- AP+STA com AP fixo em `192.168.4.1`.
- NAPT habilitado somente após `IP_EVENT_STA_GOT_IP`.
- Servidor `esp_http_server` com dashboard, páginas HTML e rotas de demonstração.
- Eventos em RAM para boot, Wi-Fi, NAT, SNTP, demos e sinais `SECURITY` didáticos, com polling normal filtrado para reduzir ruído.
- SNTP iniciado após `IP_EVENT_STA_GOT_IP`, usando `pool.ntp.org` e `time.google.com`, com timezone documentado como `America/Sao_Paulo`.
- DNS monitor/proxy didático e experimental em UDP 53; o AP entrega `192.168.4.1` como DNS via DHCP e encaminha consultas para `1.1.1.1` com fallback `8.8.8.8`.
- `/api/status` com estado operacional da PoC, `time.*`, resumo `dns.*`, contadores HTTP, `last_route`, `top_routes` sempre como array e limitações.
- `/api/dns` e `/dns` com total de consultas, histórico recente, cliente, domínio, tipo, uptime/timestamp e flags didáticas de suspeita.
- `/traffic`, `/logs` e `/report` em HTML local sem CDN; `/traffic` compensa a filtragem dos logs mostrando total requests, DNS queries e top routes.
- Rotas sensíveis didáticas: `/admin`, `/login`, `/wp-admin`, `/etc/passwd`, `/api`, `/config` e `/debug`.
- Rotas de demo: `/demo`, `/demo/scan`, `/demo/security` e `/demo/info`.

## Hardening de estabilidade

- `esp_http_server` usa stack ampliada para reduzir risco de overflow observado em bancada.
- Snapshots maiores de DNS foram movidos para heap e handlers JSON mantêm checagem de alocação.
- Task DNS usa stack ampliada, buffers no heap e timeout curto para o DNS upstream.
- Eventos DNS comuns ficam no ring buffer próprio; o log de eventos recebe apenas primeiro DNS observado e domínios suspeitos.
- Reconexão STA usa backoff simples processado no loop principal, fora do callback de disconnect.
- Próximo teste de bancada deve priorizar 2 minutos com celular conectado, navegação e `/dns` aberto sem reboot.

## Critérios de aceite

- `pio run -d experiments/espidf-appliance-v2` compila.
- `src/main.cpp` não é alterado.
- `experiments/nat-router-poc` não é alterado.
- Não há credenciais reais versionadas.
- `include/config.local.h` permanece ignorado.
- `/api/status` continua retornando JSON válido, com `traffic.top_routes` como array, `traffic.last_route` presente mesmo vazio, `time.synced`, `time.timestamp`, `dns.total_queries`, `dns.last_domain`, `dns.last_client` e `dns.monitoring_enabled`.
- A dashboard não imprime senha da STA nem senha do AP.

## Teste de bancada posterior

1. Criar `include/config.local.h` com SSID e senha reais da rede upstream local.
2. Compilar sem upload automático.
3. Fazer upload manual quando autorizado.
4. Conectar um cliente ao AP `ESP32-APPLIANCE-V2`.
5. Acessar `http://192.168.4.1/`.
6. Conferir `/api/status` e confirmar `upstream.connected=true` e `nat.active=true` após IP do STA.
7. Testar navegação HTTP/HTTPS a partir do cliente do AP.
8. Acessar `/demo/scan`, `/admin`, `/wp-admin` e uma rota inexistente para validar `demo_scan_count`, `sensitive_path_hits`, `suspicious_scan_count` e `not_found`.
9. Acessar sites HTTP/HTTPS pelo celular e conferir `/dns`, `/api/dns`, `/traffic` e `/api/status` para validar consultas DNS sem leitura de conteúdo HTTPS.
10. Testar domínio didático suspeito, por exemplo `malware.test`, e confirmar evento SECURITY em `/logs` e incremento de `dns.suspicious_count`.
11. Conferir `/traffic`, `/logs`, `/report`, `/dns` e `/api`.
12. Confirmar no log serial se persiste o aviso `Expected 4MB, found 2MB`; se persistir, validar a flash real do módulo antes de mudar `platformio.ini`.
13. Registrar evidências de tela, serial e JSON.

## Limitações planejadas

- Persistência de 24 horas fica fora desta PoC.
- Sensores, atuadores, interrupção e energia continuam no firmware principal ou em sprint posterior.
- Dashboard é operacional para demonstração da PoC, sem o conjunto completo de abas do TDE.
- NAT não implementa inspeção HTTPS, sniffing de conteúdo nem firewall profissional.
- DNS monitor mostra domínios consultados; HTTPS continua criptografado e o conteúdo das páginas não é lido.
- IDS/Traffic v0.3 é didático: usa rotas HTTP controladas, consultas DNS e contadores em RAM, sem bloqueio real de tráfego roteado.
- Proxy DNS é mínimo, experimental e de melhor esforço; a sprint cobre consultas A/AAAA simples e detecção por lista didática, sem bloqueio.
- Eventos são RAM-only e filtrados para não registrar polling normal de `/`, `/api/status`, `/api/events`, `/api/dns`, `/logs`, `/traffic`, `/dns` e `/report`.
- Flash mismatch `Expected 4MB, found 2MB` é pendência de bancada; não mexer em flash size nem partições até confirmação física.
