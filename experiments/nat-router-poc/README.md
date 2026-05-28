# ESP32 NAT Router PoC

Prova de conceito isolada para testar NAT/NAPT real no ESP32. Esta PoC nao substitui o firmware principal do TDE e nao inclui dashboard, logs LittleFS, IDS, sensores ou smoke tester.

## Objetivo

Validar se o ambiente ESP-IDF/PlatformIO consegue:

- conectar o ESP32 a um Wi-Fi upstream como STA;
- criar um AP local `ESP32-NAT-POC` em `192.168.4.1`;
- habilitar NAPT no lwIP;
- permitir que um cliente conectado ao AP tente navegar usando o upstream.

## Diferenca para o firmware principal

O firmware principal continua em `src/main.cpp` na raiz do projeto e preserva AP `ESP32-Firewall-Lab`, `/wifi`, `/gateway`, `/demo`, logs e dashboard. Esta PoC fica isolada em `experiments/nat-router-poc/` e serve apenas para provar NAT real.

## Configuracao local

Copie o template e edite com credenciais locais:

```bash
cp include/config.example.h include/config.local.h
```

Preencha `NAT_POC_UPSTREAM_SSID` e `NAT_POC_UPSTREAM_PASSPHRASE` em `include/config.local.h`. Esse arquivo e ignorado pelo Git e nao deve ser commitado.

Se o arquivo local ainda usar `UPSTREAM_WIFI_SSID` ou `UPSTREAM_WIFI_PASSWORD`, troque para `NAT_POC_UPSTREAM_SSID` e `NAT_POC_UPSTREAM_PASSPHRASE`. Esses nomes antigos sao aceitos apenas como compatibilidade temporaria para evitar erro de macro ausente.

## Build

A partir da raiz do repositorio:

```bash
pio run -d experiments/nat-router-poc
```

## Upload e monitor serial

```bash
pio run -d experiments/nat-router-poc -t upload
pio device monitor -d experiments/nat-router-poc -b 115200
```


## Troubleshooting com hotspot do iPhone

Se o ESP32 nao conectar ao Acesso Pessoal do iPhone:

1. Ative `Acesso Pessoal` no iPhone antes de ligar ou reiniciar o ESP32.
2. Ative `Maximizar Compatibilidade` para forcar comportamento mais compativel com 2,4 GHz.
3. Mantenha a tela de `Acesso Pessoal` aberta enquanto o ESP32 tenta conectar.
4. Confira no monitor serial o `reason` de `WIFI_EVENT_STA_DISCONNECTED`:
   - `auth fail`: senha incorreta ou autenticacao recusada.
   - `no ap found`: SSID nao encontrado, hotspot desligado ou fora de alcance.
   - `assoc fail`: falha de associacao com o AP.
   - `handshake timeout`: falha durante negociacao WPA.
   - `beacon timeout`: sinal instavel ou AP parou de responder.
5. Se o SSID tiver caracteres especiais, teste temporariamente um nome simples, apenas com letras e numeros.
6. A senha nunca e impressa no Serial; confira o valor apenas no `include/config.local.h`, que e ignorado pelo Git.
7. O NAPT so e iniciado depois de `IP_EVENT_STA_GOT_IP`; se nao houver IP/gateway/netmask no Serial, o NAT ainda nao foi tentado.


## DHCP e DNS dos clientes AP

Clientes conectados ao AP `ESP32-NAT-POC` devem receber automaticamente via DHCP:

- IP na faixa `192.168.4.x`;
- gateway `192.168.4.1`;
- DNS externo `1.1.1.1` como primario;
- DNS externo `8.8.8.8` como backup, quando o cliente exibir mais de um servidor.

A PoC configura o DNS em dois pontos porque `esp_netif_set_dns_info()` sozinho nao garante que a opcao DNS seja anunciada ao cliente DHCP. A sequencia usada e:

1. parar o DHCP server do AP;
2. configurar IP/gateway/netmask do AP;
3. configurar DNS primario e backup no netif do AP;
4. habilitar a opcao DHCP `ESP_NETIF_DOMAIN_NAME_SERVER` com `esp_netif_dhcps_option(..., ESP_NETIF_OP_SET, ...)`;
5. reiniciar o DHCP server do AP.

No monitor serial, confira as linhas:

- `AP DNS configured on netif`;
- `AP DHCP server announces DNS`;
- `STA IP`;
- `STA gateway`;
- `NAPT active=yes`.

Para validar no Linux com NetworkManager/systemd-resolved, remova o perfil antigo do AP para evitar lease/cache anterior e reconecte:

```bash
nmcli connection delete "ESP32-NAT-POC"
# reconecte ao AP ESP32-NAT-POC pela interface grafica ou por nmcli
resolvectl status
ping -c 4 1.1.1.1
ping -c 4 google.com
```

Criterios esperados no cliente:

- `resolvectl status` deve mostrar DNS `1.1.1.1` ou `8.8.8.8` na interface Wi-Fi conectada ao AP;
- `ping 1.1.1.1` deve passar;
- `ping google.com` deve passar sem executar `resolvectl dns` manualmente.

Se `ping 1.1.1.1` funciona, mas `google.com` nao resolve, ainda ha problema de DNS ou cache/lease antigo no cliente. Apague a conexao `ESP32-NAT-POC`, reconecte e valide novamente.

## Teste manual de NAT real

1. Gravar a PoC no ESP32.
2. Conferir no monitor serial se o upstream conectou.
3. Conferir se aparece `IP_NAPT=1` e `IP_FORWARD=1`.
4. Conectar celular/notebook ao AP `ESP32-NAT-POC`.
5. Tentar abrir um site HTTP/HTTPS.
6. Se falhar, testar DNS/ping conforme o sistema do cliente permitir.
7. Registrar se o problema foi upstream, DNS, NAPT indisponivel ou estabilidade.

## Como voltar ao firmware principal

Volte para a branch principal e grave o firmware da raiz:

```bash
git switch main
pio run -t upload
```

## Limites e riscos

- NAT/NAPT depende de ESP-IDF/lwIP com `CONFIG_LWIP_IP_FORWARD`, `CONFIG_LWIP_L2_TO_L3_COPY` e `CONFIG_LWIP_IPV4_NAPT` habilitados.
- Pode nao compilar se o pacote ESP-IDF nao estiver instalado localmente pelo PlatformIO.
- Pode conectar ao upstream mas ainda falhar por DNS, isolamento da rede, restricoes do roteador ou suporte incompleto do core.
- Desempenho e estabilidade sao limitados; nao e roteador/firewall profissional.
- Nao usar senha real em arquivos versionados.
