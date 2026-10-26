# Runbook

Passo a passo para colocar o ESP32 Mini Firewall Gateway no ar, validar e recuperar.

## 1. Preparar o build

```bash
cp include/secrets_example.h include/secrets.h
```

Edite `include/secrets.h` e troque `LAB_AP_PASSPHRASE` por uma senha de 8 a 63 caracteres. O arquivo é ignorado pelo git. Sem ele, o build para com uma mensagem de erro explicando este passo.

## 2. Compilar e gravar

```bash
pio run
pio run -t upload
pio device monitor -b 115200
```

No monitor serial, o boot deve mostrar o SSID `ESP32-Firewall-Lab` e o início do servidor web.

## 3. Conectar e conferir

1. Conecte o celular ou o notebook ao Wi-Fi `ESP32-Firewall-Lab` com a senha definida no passo 1.
2. Abra `http://192.168.4.1/`.
3. Confira `http://192.168.4.1/api/status`: `status` deve ser `ok` e `uptime_ms` deve aumentar a cada consulta.

## 4. Validar

```bash
python3 tools/smoke_test_http.py --base-url http://192.168.4.1
```

O relatório é gravado em `evidencias/`. Para gerar eventos de demonstração, abra `/demo` e use os botões de flood, IDS e scan.

Sem acesso ao AP (por exemplo, remotamente por SSH), rode a checagem offline:

```bash
python3 tools/offline_project_check.py
```

## 5. Conectar a um Wi-Fi upstream (opcional)

1. Abra `/wifi`, informe SSID e passphrase e salve.
2. Acompanhe o resultado em `/gateway`.
3. Se a conexão falhar, o AP local continua no ar. Use `/wifi/clear` para apagar a configuração.

## 6. Operação

| Tarefa | Como |
|---|---|
| Ver eventos recentes | `/logs` ou `/api/events` |
| Ver eventos persistidos | `/api/events/persistent` |
| Limpar eventos persistidos | `/logs/clear-persistent` (registra um evento de limpeza manual) |
| Exportar estado para apresentação | `/report` ou `/api/report` |

## Problemas comuns

| Sintoma | Causa provável | O que fazer |
|---|---|---|
| Build falha pedindo `LAB_AP_PASSPHRASE` | falta `include/secrets.h` | repita o passo 1 |
| Energia aparece como `indisponível` | INA219 não detectado no I2C | confira SDA no `GPIO 21`, SCL no `GPIO 22`, 3V3 e GND comum; o resto do sistema segue funcionando |
| Persistência aparece como indisponível | o LittleFS não montou, mesmo depois da formatação automática que o firmware tenta no boot | os eventos seguem em RAM; confira o evento de erro em `/logs` e, se repetir, regrave o firmware |
| AP não aparece | placa sem energia suficiente ou firmware não gravado | confira o monitor serial e a fonte |
| Upstream não conecta | SSID ou passphrase incorretos, ou rede fora de alcance | veja o último erro em `/wifi` e o RSSI em `/gateway` |
