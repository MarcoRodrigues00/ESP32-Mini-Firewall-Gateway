# Evidência de bancada — ESP-IDF Appliance v2 (TEMPLATE A PREENCHER)

> Documento de evidência da validação funcional em hardware. Os campos estão como
> `PREENCHER APÓS TESTE`. **Não preencher com resultado sem ter executado e evidenciado.**
> Para o checklist detalhado PASS/FAIL por funcionalidade, usar em conjunto
> `evidencias/espidf-v2-bench-result-template.md`.
>
> Esta é uma PoC didática (gateway/AP + dashboard + DNS/NAPT). Não é firewall de produção.

## Identificação

- Data do teste: PREENCHER APÓS TESTE
- Responsável: PREENCHER APÓS TESTE
- Branch: `experiment/espidf-appliance-v2`
- Commit testado (`git rev-parse --short HEAD`): PREENCHER APÓS TESTE
- Firmware/build de referência: ver `evidencias/2026-06-01-build-espidf-v2.md`

## Ambiente

- PlatformIO Core: PREENCHER APÓS TESTE (esperado: 6.1.19)
- Placa/módulo ESP32: PREENCHER APÓS TESTE
- Fonte/cabo USB: PREENCHER APÓS TESTE
- Sistema do host (ex.: WSL2 + usbipd): PREENCHER APÓS TESTE
- `config.local.h` presente e ignorado pelo Git: SIM / NÃO

## Porta serial

- Porta detectada (`pio device list`): PREENCHER APÓS TESTE (ex.: `/dev/ttyUSB0`)

## Upload / flash

- Comando executado:

  ```bash
  pio run -d experiments/espidf-appliance-v2 -t upload
  ```
- Resultado do upload: PREENCHER APÓS TESTE (SUCCESS / FAIL)
- Observações: PREENCHER APÓS TESTE

## Monitor serial (trecho curto)

- Comando: `pio device monitor -d experiments/espidf-appliance-v2 -b 115200`
- Trecho relevante do boot (AP iniciado, IP do AP, e STA/NAPT/SNTP quando aplicável; **sem log cru gigante**):

  ```text
  PREENCHER APÓS TESTE (poucas linhas essenciais)
  ```

## Conexão Wi-Fi / AP

- SSID AP usado (somente SSID de laboratório): PREENCHER APÓS TESTE (default versionado: `ESP32-APPLIANCE-V2`)
- Senha: NÃO REGISTRAR (senha de laboratório fica fora da evidência)
- IP do AP: `192.168.4.1`
- IP recebido pelo cliente (`192.168.4.x`): PREENCHER APÓS TESTE
- Upstream SSID (mascarado, sem senha): PREENCHER APÓS TESTE

## Dashboard HTTP

- `http://192.168.4.1/` respondeu: PREENCHER APÓS TESTE (SIM / NÃO)
- Observações de UI: PREENCHER APÓS TESTE

## Smoke HTTP

- Comando: `python3 tools/smoke_espidf_v2_http.py --base-url http://192.168.4.1`
- Resumo (`PASS/FAIL; falhas=N; duracao=Xs`): PREENCHER APÓS TESTE

### Endpoints testados (resultado por rota)

| Endpoint | Tipo | Resultado |
| --- | --- | --- |
| `/` | html | PREENCHER APÓS TESTE |
| `/api/status` | json | PREENCHER APÓS TESTE |
| `/dns` | html | PREENCHER APÓS TESTE |
| `/api/dns` | json | PREENCHER APÓS TESTE |
| `/clients` | html | PREENCHER APÓS TESTE |
| `/api/clients` | json | PREENCHER APÓS TESTE |
| `/traffic` | html | PREENCHER APÓS TESTE |
| `/logs` | html | PREENCHER APÓS TESTE |
| `/report` | html | PREENCHER APÓS TESTE |
| `/demo/security` | html | PREENCHER APÓS TESTE |

## Métricas observadas

> Campos disponíveis em `/api/status` e no diagnóstico de boot. Registrar só o que foi observado.

- Heap livre: PREENCHER APÓS TESTE
- Heap mínimo: PREENCHER APÓS TESTE
- High-water mark de tasks: PREENCHER APÓS TESTE
- NAT (`nat.active`): PREENCHER APÓS TESTE
- SNTP (`time` sincronizado): PREENCHER APÓS TESTE
- DNS (total/suspeitos): PREENCHER APÓS TESTE
- `risk_score` após `/demo/security`: PREENCHER APÓS TESTE
- Display (`enabled`/`available`/`state`): PREENCHER APÓS TESTE

## Evidências capturadas

- [ ] Print do upload com sucesso
- [ ] Trecho do monitor (AP + IP)
- [ ] Saída do smoke HTTP
- [ ] Print do dashboard `/`
- [ ] `api-status.json` enxuto
- [ ] (Opcional) foto do display físico, só se habilitado/validado

> Material cru vai em `evidencias/raw/` (ignorado pelo Git). Não commitar logs crus,
> `.pio/`, SSID/senha real de rede externa.

## Riscos / ressalvas

- PREENCHER APÓS TESTE (ex.: porta USB não detectada em WSL2, instabilidade de display, NAPT sem upstream STA)

## Próximos passos

- PREENCHER APÓS TESTE
