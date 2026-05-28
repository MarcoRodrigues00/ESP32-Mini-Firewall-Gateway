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

Valida APIs JSON:

- `/api/status`
- `/api/events`
- `/api/events/persistent`

Em `/api/status`, o smoke test espera informacao clara de persistencia em objeto top-level `storage` ou `persistence`. O schema recomendado e:

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

Aciona rotas demo controladas:

- `/demo/info`
- `/demo/warn`
- `/demo/security`
- `/demo/flood`

Depois das rotas demo, consulta novamente `/api/events`, `/api/events/persistent` e `/logs` para verificar eventos WARN/SECURITY e persistencia.

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
- O firewall e didatico e baseado em acessos HTTP ao painel.
- O teste nao executa ataque real; `/demo/flood` e uma simulacao controlada.
