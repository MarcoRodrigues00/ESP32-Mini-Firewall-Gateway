# Smoke test HTTP

Este roteiro valida rapidamente o firmware rodando no ESP32 e gera um relatorio Markdown em `evidencias/`. O teste usa apenas Python 3 standard library, sem `jq`, `pytest`, Node ou dependencias externas.

## Pre-requisitos

- Firmware gravado no ESP32.
- ESP32 ligado e com AP `ESP32-Firewall-Lab` ativo.
- Computador conectado ao AP do ESP32.
- Python 3 disponivel no computador.

## Como rodar

A partir da raiz do projeto:

```bash
python3 tools/smoke_test_http.py --base-url http://192.168.4.1
```

Se a URL padrao for usada, o argumento pode ser omitido:

```bash
python3 tools/smoke_test_http.py
```

Para ver as opcoes:

```bash
python3 tools/smoke_test_http.py --help
```

## O que o teste verifica

O script valida paginas HTML:

- `/`
- `/evidencias`
- `/logs`
- `/eventos`
- `/gateway`
- `/demo`

A pagina `/demo` deve conter os termos `Demo guiada`, `roteiro` e `TDE`, confirmando que o roteiro guiado esta embarcado no firmware.

Valida APIs JSON:

- `/api/status`
- `/api/events`
- `/api/events/persistent`

Em `/api/status`, o smoke test espera informacao clara de persistencia em objeto top-level `storage` ou `persistence`, objeto `gateway` e campos de IDS em `firewall` ou `ids`. O schema recomendado para persistencia e:

```json
{
  "storage": {
    "available": true,
    "file_size": 0,
    "max_size": 16384,
    "path": "/events.log",
    "policy": "selective"
  }
}
```

Schema esperado para gateway/IDS:

```json
{
  "gateway": {
    "mode": "AP_ONLY",
    "ap_enabled": true,
    "ap_ssid": "ESP32-Firewall-Lab",
    "ap_ip": "192.168.4.1",
    "sta_configured": false,
    "sta_connected": false,
    "nat_enabled": false,
    "nat_note": "experimental/not implemented"
  },
  "firewall": {
    "ids_enabled": true,
    "ids_events": 0,
    "suspicious_404_count": 0,
    "sensitive_path_hits": 0
  }
}
```

Aciona rotas demo controladas:

- `/demo/info`
- `/demo/warn`
- `/demo/security`
- `/demo/flood`
- `/demo/ids`

Depois das rotas demo, consulta novamente `/api/events`, `/api/events/persistent` e `/logs` para verificar eventos WARN/SECURITY/IDS e persistencia.

## Relatorio gerado

O relatorio e salvo automaticamente em:

```text
evidencias/smoke-test-YYYYMMDD-HHMMSS.md
```

O arquivo contem:

- data/hora local;
- base URL testada;
- resultado geral PASS/FAIL;
- tabela com cada teste executado;
- resumo de `/api/status`;
- orientacao de teste manual pos-reboot;
- limitacoes do smoke test.

Relatorios `evidencias/smoke-test-*.md` ficam ignorados pelo Git por padrao. Se um relatorio especifico precisar entrar como evidencia final, adicionar explicitamente com `git add -f` e registrar o motivo.

## Teste manual pos-reboot do LittleFS

Depois de gerar eventos e confirmar que `/api/events/persistent` responde:

1. Reiniciar o ESP32.
2. Reconectar ao AP `ESP32-Firewall-Lab`.
3. Abrir `http://192.168.4.1/api/events/persistent`.
4. Confirmar que eventos persistentes continuam disponiveis apos reboot.

## Limitacoes

- O smoke test nao substitui teste fisico dos sensores.
- O INA219 fisico fica para a fase final porque depende de solda/montagem.
- O firewall e IDS sao didaticos e baseados em acessos HTTP ao painel.
- O NAT e experimental e pode aparecer como nao suportado dependendo do core/lwIP.
- O teste nao executa ataque real; `/demo/flood` e `/demo/ids` sao simulacoes controladas.

## Validacao de Wi-Fi upstream

O smoke test tambem valida a pagina `/wifi` e o schema de Wi-Fi upstream em `/api/status`. Ele verifica campos de estado como configurado, conectado, IP, RSSI, ultima tentativa, ultimo status e ultimo erro.

O teste nao automatiza envio de credencial upstream. Isso evita colocar credencial real em terminal, relatorio Markdown ou historico do projeto. A validacao da conexao real deve ser feita manualmente pela pagina `/wifi` quando o ESP32 estiver em bancada.

## Validacao de NAT experimental

O smoke test valida que `/gateway` menciona NAT experimental e que `/api/status` contem objeto `nat` ou campos NAT dentro de `gateway`. Ele verifica schema e status, mas nao exige que a internet funcione pelo AP porque isso depende do core/lwIP, do upstream e do ambiente fisico.

## Validacao do Traffic Monitor

O smoke tester valida a pagina `/traffic`, o JSON `/api/traffic`, a presenca do objeto `traffic` em `/api/status` e a rota `/demo/scan`. Depois da simulacao de scan, o script consulta `/api/events` para confirmar evento `SECURITY`/`IDS` e consulta `/api/traffic` novamente para validar o schema atualizado.

O teste continua usando apenas Python standard library e nao executa ataque real. A rota `/demo/scan` e uma simulacao controlada sobre o HTTP do painel.

## Validacao do relatorio embarcado

O smoke tester valida `/report` como HTML e `/api/report` como JSON. O schema esperado contem `project`, `version`, `system`, `gateway`, `nat`, `firewall`, `ids`, `traffic`, `storage`, `recent_events_summary` e `limitations`.

`/report` e uma evidencia visual embarcada. O smoke test externo continua sendo o registro automatizado, com relatorio Markdown em `evidencias/`.
