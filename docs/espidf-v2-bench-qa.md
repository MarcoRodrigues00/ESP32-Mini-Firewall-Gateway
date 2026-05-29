# Checklist de bancada ESP-IDF Appliance v2

Este checklist valida a PoC `experiments/espidf-appliance-v2` em hardware real. Ele nao altera firmware nem substitui observacao fisica. Marque PASS somente quando a etapa foi executada e evidenciada.

## Preparacao

- [ ] Confirmar branch `experiment/espidf-appliance-v2`.
- [ ] Confirmar commit a ser testado com `git rev-parse --short HEAD`.
- [ ] Confirmar que `experiments/espidf-appliance-v2/include/config.local.h` existe localmente e nao esta versionado.
- [ ] Registrar SSID upstream de forma mascarada, sem senha.
- [ ] Confirmar alimentacao estavel do ESP32 e cabo USB confiavel.
- [ ] Conectar computador/celular ao AP do ESP32 para testes HTTP.
- [ ] Separar celular ou notebook para foto do display fisico.

## Comandos base

Build:

```bash
pio run -d experiments/espidf-appliance-v2
```

Upload manual, somente quando a placa correta estiver conectada:

```bash
pio run -d experiments/espidf-appliance-v2 -t upload
```

Monitor serial:

```bash
pio device monitor -d experiments/espidf-appliance-v2
```

Smoke HTTP opcional, conectado ao AP do ESP32:

```bash
python3 tools/smoke_espidf_v2_http.py --base-url http://192.168.4.1
```

## Teste AP

Passos:

1. Ligar o ESP32.
2. Observar no monitor serial a inicializacao do AP.
3. No cliente, procurar o SSID configurado para o AP da v2.
4. Conectar ao AP.
5. Abrir `http://192.168.4.1/`.

PASS:

- AP aparece na lista Wi-Fi.
- Cliente conecta e recebe IP na rede `192.168.4.x`.
- Dashboard `/` responde HTTP 200.
- `/api/status` mostra objeto `ap` e `clients.count` coerente.

FAIL:

- AP nao aparece.
- Cliente nao obtem IP.
- Dashboard nao responde.

## Teste upstream STA

Passos:

1. Confirmar SSID upstream em `config.local.h`, sem registrar senha em evidencia.
2. Reiniciar o ESP32.
3. Observar monitor serial ate STA obter IP.
4. Abrir `/api/status`.

PASS:

- Monitor mostra conexao STA ou evento equivalente de IP obtido.
- `/api/status.upstream.connected` fica `true`.
- `/api/status.upstream.ip` nao e `0.0.0.0`.

FAIL:

- STA nao conecta apos tentativas esperadas.
- IP upstream permanece vazio ou `0.0.0.0`.

## Teste NAT/NAPT

Passos:

1. Manter cliente conectado ao AP do ESP32.
2. Confirmar STA conectado ao upstream.
3. Abrir `/api/status` e `/report`.
4. Tentar navegar de forma simples pelo cliente do AP, por exemplo abrir um site HTTP/HTTPS comum.

PASS:

- Monitor registra NAPT habilitado ou equivalente.
- `/api/status.nat.active` fica `true`.
- `/report` descreve NAT ativo ou tentativa coerente.
- Cliente do AP consegue trafegar quando upstream permite.

FAIL:

- STA esta conectado, mas NAPT nao fica ativo.
- Cliente do AP nao trafega e `/api/status.nat` mostra falha sem explicacao.

## Teste SNTP

Passos:

1. Confirmar upstream STA com internet.
2. Aguardar sincronizacao.
3. Verificar `/api/status.time` e monitor serial.
4. Observar hora no display.

PASS:

- Monitor mostra sincronizacao SNTP ou timestamp valido.
- `/api/status.time.synced` fica `true`.
- Timestamp nao fica `unsynced`.
- Display mostra hora `HH:MM` coerente.

FAIL:

- Sem sincronizacao apos upstream funcional.
- Timestamp permanece `unsynced`.

## Teste DNS

Passos:

1. Conectar cliente ao AP do ESP32.
2. Abrir um site comum ou forcar consulta DNS pelo cliente.
3. Abrir `/dns` e `/api/dns`.
4. Observar display nas linhas `DNS:` e `CLIENTE:`.

PASS:

- Monitor registra primeira consulta DNS observada.
- `/api/dns.recent_queries` contem dominio, cliente e tipo.
- `/api/status.dns.total_queries` aumenta.
- Display atualiza ultimo dominio e IP do cliente.

FAIL:

- Cliente navega, mas DNS nao aparece em `/dns`.
- `/api/dns` nao retorna JSON valido.

## Teste /clients

Passos:

1. Gerar pelo menos uma consulta DNS a partir de cliente do AP.
2. Abrir `/clients` e `/api/clients`.
3. Conferir IP, contadores DNS, ultimo dominio e score.

PASS:

- Cliente observado aparece com IP.
- `dns_query_count` aumenta.
- `last_domain` reflete consulta recente.
- `risk_score` existe e inicia baixo para trafego comum.

FAIL:

- `/clients` nao lista cliente apos DNS observado.
- `/api/clients` nao retorna JSON valido.

## Teste risk_score

Passos:

1. Em cliente conectado ao AP, acessar ou resolver `malware.test`.
2. Abrir `/clients`, `/api/clients`, `/dns` e `/api/status`.
3. Repetir consultas se necessario para observar score e classificacao.

PASS:

- `malware.test` aparece como suspeito em `/dns`.
- Cliente tem `risk_score` aumentado.
- `/api/status.clients_observed.highest_risk_score` reflete o maior score.
- Evento `SECURITY` aparece em `/logs`.

FAIL:

- Dominio suspeito nao altera score.
- Evento de seguranca nao aparece.

## Teste display NORMAL

Passos:

1. Reiniciar o ESP32.
2. Antes de gerar dominio suspeito ou demo security, observar display.
3. Fotografar tela.

PASS:

- Titulo mostra `NORMAL`.
- Micro-icone defensivo aparece ao lado do titulo.
- Linhas `CLI/OBS`, `RISK/DNS`, `DNS`, `CLIENTE`, `SUS`, `SRC` estao legiveis.
- Rodape mostra `UP`, `NAT`, `IDS`.

FAIL:

- Display nao inicializa.
- Texto fica ilegivel ou cortado de forma critica.

## Teste display DNS SUS

Passos:

1. Gerar consulta para `malware.test` a partir de cliente do AP.
2. Observar display por ate 5 segundos.
3. Fotografar tela.

PASS:

- Titulo mostra `DNS SUS`.
- Micro-caveira aparece ao lado do titulo.
- `SUS:` mostra `malware.test` ou dominio suspeito equivalente.
- `SRC:` mostra IP do cliente.
- Rodape `IDS` fica em aviso.

FAIL:

- Estado nao muda apos DNS suspeito confirmado em `/dns`.
- Campo suspeito nao aparece.

## Teste display ATTACK

Passos:

1. Acessar `http://192.168.4.1/demo/security` ou `/demo/scan`.
2. Observar display por ate 5 segundos.
3. Fotografar tela.
4. Verificar `/logs` e `/traffic`.

PASS:

- Titulo mostra `ATTACK`.
- Micro-icone vermelho/laranja aparece ao lado do titulo.
- `RISK` e contadores continuam legiveis.
- Rodape `IDS` fica vermelho.
- `/logs` registra evento de seguranca.

FAIL:

- Demo nao altera estado.
- Display deixa de atualizar dados uteis.

## Teste estabilidade 10 minutos

Passos:

1. Deixar ESP32 ligado por 10 minutos com AP ativo.
2. Manter um cliente conectado ao AP.
3. Abrir periodicamente `/api/status`, `/dns`, `/clients`, `/traffic`, `/logs` e `/report`.
4. Gerar algumas consultas DNS normais e uma consulta suspeita controlada.
5. Observar monitor serial e display.

PASS:

- Sem reboot inesperado.
- HTTP continua respondendo.
- DNS monitor continua atualizando.
- Display continua legivel.
- Heap em `/api/status.heap_free` nao apresenta queda continua evidente.

FAIL:

- Reboot, travamento, perda persistente de HTTP, display congelado ou queda continua de heap sem recuperacao.

## Registro PASS/FAIL

Use `evidencias/espidf-v2-bench-result-template.md` para registrar resultado. Nao marque PASS sem evidencia. Se um item nao foi executado, marcar como `NAO EXECUTADO` e explicar motivo.
