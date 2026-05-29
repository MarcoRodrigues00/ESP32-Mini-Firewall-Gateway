# Offline Project Check

O offline check existe para validar a branch `main` via SSH sem conectar o notebook ao AP `ESP32-Firewall-Lab`. Isso evita derrubar a sessao remota durante verificacoes pequenas antes da sprint de polish visual.

Ele executa comandos locais, varreduras estaticas, validacao de rotas registradas em `src/main.cpp`, checagem de campos importantes do firmware, revisao minima de documentacao e alerta se houver mudancas em `experiments/`.

## Como rodar

Na raiz do projeto:

```bash
python3 tools/offline_project_check.py
```

O script executa:

- `pio run`;
- `python3 -m py_compile tools/smoke_test_http.py`;
- `python3 tools/smoke_test_http.py --help`.

Depois gera um relatorio Markdown em:

```text
evidencias/offline-check-YYYYMMDD-HHMMSS.md
```

## O que ele valida

- Build PlatformIO local.
- Smoke tester compilavel e com `--help` funcional.
- Ausencia de `AsyncWebServer`/`ESPAsync` no firmware da `main`.
- Ausencia de `delay()` indevido em `src/main.cpp`.
- Ausencia de CDN ou frameworks externos no firmware.
- Termos sensiveis como `token`, `password`, `secret`, `api_key`, `apikey` e `senha`.
- Rotas principais: `/`, `/demo`, `/gateway`, `/wifi`, `/traffic`, `/report`, `/evidencias`, `/logs`, `/eventos`, `/api/status`, `/api/events`, `/api/events/persistent`, `/api/traffic`, `/api/report`, `/logs/clear-persistent`, `/demo/info`, `/demo/warn`, `/demo/security`, `/demo/flood`, `/demo/ids` e `/demo/scan`.
- Objetos e campos esperados: `gateway`, `nat`, `firewall`, `ids`, `traffic`, `storage`, `persistence`, `uptime_ms` e `time_label`.
- Documentacao minima sobre `/traffic`, `/api/traffic`, `/report`, `/api/report`, `/demo/scan`, limitacao de HTTPS e NAT real em PoC separada ESP-IDF.

## Offline check x smoke real

O offline check nao acessa o ESP32, nao conecta ao AP, nao valida sensores, atuadores, LittleFS no hardware, Wi-Fi real nem comportamento eletrico da montagem. Ele e a evidencia de desenvolvimento remoto via SSH e reduz risco antes dos testes de bancada.

O smoke real continua obrigatorio quando for seguro conectar ao AP:

```bash
python3 tools/smoke_test_http.py --base-url http://192.168.4.1
```

Se houver alteracoes em `experiments/` enquanto a sprint estiver na `main`, o offline check marca `WARN` e lembra para nao incluir esses arquivos no commit da `main`.
