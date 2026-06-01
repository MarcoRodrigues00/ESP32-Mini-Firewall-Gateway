# Evidência de build — ESP-IDF Appliance v2

- Data: 2026-06-01
- Branch: `experiment/espidf-appliance-v2`
- Commit: `81b0405`
- Tipo: build local (compilação), sem gravação no dispositivo
- Resultado geral: **SUCCESS**

## Ambiente

- PlatformIO Core 6.1.19 (instalado em `~/.platformio/penv`)
- Framework: ESP-IDF via PlatformIO
- Placa: `esp32dev`
- Diretório do build: `experiments/espidf-appliance-v2`

## Comando executado

```bash
pio run
```

## Resultado

- Status: `SUCCESS`
- Tempo de build: `119.03 seconds`

## Métricas de memória

| Recurso | Uso | Detalhe |
|---|---|---|
| RAM | 15.3% | 50260 bytes de 327680 bytes |
| Flash | 42.9% | 899873 bytes de 2097152 bytes |

## Artefatos gerados

| Artefato | Tamanho | Caminho |
|---|---|---|
| `firmware.bin` | 880K | `.pio/build/esp32dev/firmware.bin` |
| `firmware.elf` | 8.4M | `.pio/build/esp32dev/firmware.elf` |

Os artefatos ficam em `.pio/`, que é ignorado pelo Git e não é versionado.

## Checks de Git e configs

- `git status --short`: limpo
- `git diff --check`: limpo
- Sem diff em arquivos de configuração:
  - `experiments/espidf-appliance-v2/sdkconfig.defaults`
  - `experiments/espidf-appliance-v2/partitions_4mb.csv`
  - `experiments/espidf-appliance-v2/platformio.ini`

## Observação

Esta evidência cobre apenas a compilação do firmware. **Não houve upload, flash, monitor serial nem erase** no ESP32. A validação funcional em hardware (AP, dashboard, DNS, NAPT, SNTP, display) continua pendente e deve ser registrada na evidência de bancada.

## Próximos passos sugeridos

- Validação em bancada com o ESP32 real, usando o template `evidencias/espidf-v2-bench-result-template.md`.
- Smoke HTTP da v2 conectado ao AP: `python3 tools/smoke_espidf_v2_http.py --base-url http://192.168.4.1`.
- Coletar evidências dos marcos funcionais (build PASS já coberto aqui; upload, AP, rotas e display pendentes).
