# Plano da PoC ESP-IDF Appliance v2

## Objetivo

Criar uma PoC isolada em `experiments/espidf-appliance-v2/` para validar AP+STA, NAT/NAPT real e dashboard mínimo em ESP-IDF antes de qualquer migração do firmware principal.

## Entregas desta sprint

- Projeto ESP-IDF compilável via PlatformIO.
- Configuração local separada e ignorada pelo Git.
- AP+STA com AP fixo em `192.168.4.1`.
- NAPT habilitado somente após `IP_EVENT_STA_GOT_IP`.
- Servidor `esp_http_server` com dashboard, páginas HTML e rotas de demonstração.
- Eventos em RAM para boot, Wi-Fi, NAT, requests HTTP e sinais `SECURITY` didáticos.
- `/api/status` com estado operacional da PoC, contadores HTTP, top routes simples e limitações.
- `/traffic`, `/logs` e `/report` em HTML local sem CDN.
- Rotas sensíveis didáticas: `/admin`, `/login`, `/wp-admin`, `/etc/passwd`, `/api`, `/config` e `/debug`.
- Rotas de demo: `/demo`, `/demo/scan`, `/demo/security` e `/demo/info`.

## Critérios de aceite

- `pio run -d experiments/espidf-appliance-v2` compila.
- `src/main.cpp` não é alterado.
- `experiments/nat-router-poc` não é alterado.
- Não há credenciais reais versionadas.
- `include/config.local.h` permanece ignorado.
- `/api/status` continua retornando JSON válido.
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
9. Conferir `/traffic`, `/logs`, `/report` e `/api`.
10. Registrar evidências de tela, serial e JSON.

## Limitações planejadas

- Persistência de 24 horas fica fora desta PoC.
- Sensores, atuadores, interrupção e energia continuam no firmware principal ou em sprint posterior.
- Dashboard é operacional para demonstração da PoC, sem o conjunto completo de abas do TDE.
- NAT não implementa inspeção HTTPS nem firewall profissional.
- IDS/Traffic v0.2 é didático: usa rotas HTTP controladas e contadores em RAM, sem bloqueio real de tráfego roteado.
