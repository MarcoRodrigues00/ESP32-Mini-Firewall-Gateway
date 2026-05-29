# Guia de evidencias ESP-IDF Appliance v2

Este guia lista as evidencias esperadas para defesa tecnica da v2. Nao invente resultado: colete somente prints, fotos e trechos de log realmente observados em bancada.

## Identificacao da sessao

Registrar no template:

- data/hora local;
- branch;
- commit curto;
- placa usada;
- versao do PlatformIO/ambiente se relevante;
- SSID upstream mascarado;
- confirmacao de que `config.local.h` nao foi versionado.

## Prints e logs obrigatorios

1. Build SUCCESS
   - Print ou trecho do terminal com `pio run -d experiments/espidf-appliance-v2` finalizando em SUCCESS.
   - Incluir RAM/Flash reportado.

2. Upload SUCCESS
   - Print ou trecho do terminal com upload concluido.
   - Nao incluir porta serial se houver informacao sensivel do ambiente.

3. Monitor com AP started
   - Trecho do monitor serial mostrando AP iniciado ou evento equivalente.
   - Se o log exato mudar, registrar a linha disponivel e explicar.

4. Monitor com STA got IP
   - Trecho mostrando que STA obteve IP.
   - Mascare SSID se aparecer em log.

5. Monitor com NAPT enabled
   - Trecho mostrando NAPT habilitado ou `/api/status.nat.active=true` como evidencia complementar.

6. Monitor com SNTP synchronized
   - Trecho com sincronizacao SNTP ou `/api/status.time.synced=true` e timestamp valido.

7. Monitor com DNS query observed
   - Trecho da primeira consulta DNS observada ou print de `/dns` com query recente.

8. Monitor com suspicious DNS `malware.test`
   - Trecho de evento `SECURITY` ou print de `/dns` marcando consulta suspeita.

9. Tela display NORMAL
   - Foto fisica do display mostrando `NORMAL`, micro-icone, hora, dados e rodape.

10. Tela display DNS SUS
    - Foto fisica apos consulta `malware.test`, mostrando `DNS SUS`, `SUS:` e `SRC:`.

11. Tela display ATTACK
    - Foto fisica apos `/demo/security` ou `/demo/scan`, mostrando `ATTACK`.

12. `/api/status`
    - Print do navegador ou arquivo `.json` salvo.
    - Deve mostrar `ap`, `upstream`, `nat`, `dns`, `clients_observed`, `traffic`, `time` e `display`.

13. `/dns`
    - Print da pagina com consultas recentes.
    - Deve incluir pelo menos uma consulta normal e, se executado, `malware.test`.

14. `/clients`
    - Print mostrando clientes observados, contadores DNS, ultimo dominio e `risk_score`.

15. `/traffic`
    - Print mostrando total requests, rotas e contadores de demo/scan.

16. `/logs`
    - Print mostrando eventos importantes: boot, NAT, DNS suspeito, demo security.

17. `/report`
    - Print do relatorio embarcado usado como evidencia consolidada.

18. Smoke HTTP v2, se executado
    - Saida do comando:

```bash
python3 tools/smoke_espidf_v2_http.py --base-url http://192.168.4.1
```

## Nome sugerido dos arquivos

Use nomes simples e ordenados dentro de `evidencias/` ou subpastas:

- `espidf-v2-01-build-success.png`
- `espidf-v2-02-upload-success.png`
- `espidf-v2-03-monitor-ap-started.txt`
- `espidf-v2-04-monitor-sta-ip.txt`
- `espidf-v2-05-monitor-napt.txt`
- `espidf-v2-06-sntp.png`
- `espidf-v2-07-dns-normal.png`
- `espidf-v2-08-dns-malware-test.png`
- `espidf-v2-09-display-normal.jpg`
- `espidf-v2-10-display-dns-sus.jpg`
- `espidf-v2-11-display-attack.jpg`
- `espidf-v2-12-api-status.json`
- `espidf-v2-13-dns-page.png`
- `espidf-v2-14-clients-page.png`
- `espidf-v2-15-traffic-page.png`
- `espidf-v2-16-logs-page.png`
- `espidf-v2-17-report-page.png`

## Criterios de qualidade das evidencias

- Foto do display deve estar legivel, sem reflexo impedindo leitura.
- Prints devem incluir URL ou comando quando possivel.
- Logs devem conter horario ou uptime quando disponivel.
- Nao registrar senha real, token, SSID privado completo se isso for sensivel, MAC pessoal ou dados de terceiros sem necessidade.
- Se algo falhar, manter a evidencia da falha e registrar no template como FAIL.

## Evidencias que nao substituem teste real

- Print de codigo nao prova funcionamento fisico.
- Build SUCCESS nao prova AP/NAT/DNS em bancada.
- `/api/status` sozinho nao prova navegacao pelo NAT.
- Foto do display sozinha nao prova DNS; combine com `/dns` ou monitor serial.
