# Flash e particao da ESP-IDF Appliance v2

## Contexto

Durante os builds/uploads de bancada da v2 aparecia o aviso:

```text
Warning! Flash memory size mismatch detected. Expected 4MB, found 2MB!
```

A v2 ja havia sido validada fisicamente com AP+STA, NAT/NAPT, SNTP, DNS monitor/proxy, paginas HTTP e display. Esta sprint nao adiciona persistencia, filesystem, watchdog ou mudanca funcional no firmware. O objetivo foi alinhar configuracao de flash e particao antes de qualquer escrita persistente.

## Investigacao

Configuracao inicial relevante:

- `platformio.ini` usava `board = esp32dev` sem `board_build.flash_size` nem `board_upload.flash_size`.
- O manifesto da placa `esp32dev` no PlatformIO anuncia 4MB, por isso o banner do build mostra `HARDWARE: ESP32 240MHz, 320KB RAM, 4MB Flash`.
- O `sdkconfig.esp32dev` local gerado apontava `CONFIG_ESPTOOLPY_FLASHSIZE="2MB"`, mesmo com o ambiente de placa esperando 4MB.
- A tabela padrao era `partitions_singleapp.csv`, com app factory de 1MB.
- O build antes do ajuste passava, mas reportava limite de app de `1048576 bytes` e firmware usando `899873 bytes`.

A deteccao nao destrutiva com `esptool.py flash_id` na unidade de bancada retornou `Detected flash size: 4MB`. Interpretacao: a unidade validada em bancada possui flash detectada como 4MB. O mismatch vinha do desalinhamento entre o ambiente `esp32dev` de 4MB e o `sdkconfig.esp32dev` local, que ainda gerava imagem marcada como 2MB. O firmware cabia, mas a configuracao ficava ambigua e a particao factory de 1MB deixava pouca margem.

## Configuracao escolhida

A v2 agora declara explicitamente flash de 4MB no ambiente PlatformIO:

```ini
board_build.flash_size = 4MB
board_upload.flash_size = 4MB
board_build.partitions = partitions_4mb.csv
```

O `sdkconfig.defaults` tambem fixa a escolha para ESP-IDF:

```text
CONFIG_ESPTOOLPY_FLASHSIZE_4MB=y
CONFIG_ESPTOOLPY_FLASHSIZE="4MB"
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions_4mb.csv"
CONFIG_PARTITION_TABLE_FILENAME="partitions_4mb.csv"
```

Observacao: `sdkconfig.esp32dev` e arquivo local gerado/ignorado pelo Git neste experimento. Ele tambem precisou ser alinhado no ambiente de bancada para remover a configuracao antiga de 2MB e validar o build atual.

## Tabela de particao

Arquivo: `experiments/espidf-appliance-v2/partitions_4mb.csv`.

```csv
# Name,   Type, SubType, Offset,   Size,     Flags
nvs,      data, nvs,     0x9000,   0x6000,
phy_init, data, phy,     0xf000,   0x1000,
factory,  app,  factory, 0x10000,  0x200000,
```

Decisoes:

- Preservar `nvs` para configuracoes internas do ESP-IDF/Wi-Fi.
- Preservar `phy_init`.
- Usar uma unica particao `factory`, sem OTA nesta PoC.
- Aumentar a particao de app para `0x200000` bytes (`2097152` bytes).
- Deixar aproximadamente `0x1F0000` bytes no fim da flash de 4MB para planejamento futuro.
- Nao criar LittleFS/SPIFFS/FAT nesta sprint.

## Resultado do build apos ajuste

Comando:

```bash
pio run -d experiments/espidf-appliance-v2
```

Resultado observado:

```text
RAM:   15.3% (used 50260 bytes from 327680 bytes)
Flash: 42.9% (used 899873 bytes from 2097152 bytes)
SUCCESS
```

O aviso `Expected 4MB, found 2MB` nao apareceu apos o alinhamento da configuracao.

Margem da particao de app:

- Maximo: `2097152` bytes.
- Usado: `899873` bytes.
- Livre aproximado: `1197279` bytes.

## Por que nao adicionar persistencia agora

Persistencia deve ser uma sprint separada porque ainda exige decisoes de projeto:

- escolher mecanismo: NVS adicional, LittleFS, SPIFFS ou outro;
- definir tamanho minimo e retencao dos eventos;
- limitar escrita em flash para nao degradar o modulo;
- validar comportamento apos reboot;
- decidir se a particao futura fica no espaco final reservado ou se a tabela deve ser redesenhada.

Adicionar filesystem agora misturaria duas mudancas: saneamento de flash e nova feature. Esta sprint deixa a base coerente para a proxima etapa.

## Riscos e variacoes de placa

- Algumas placas ESP32 DevKit vendidas como equivalentes podem ter 2MB, 4MB ou mais. Esta configuracao mira a unidade validada em bancada, detectada como 4MB.
- Em uma placa real de 2MB, esta tabela nao deve ser usada: o app factory de 2MB ultrapassaria o espaco fisico disponivel.
- Se outra unidade for confirmada como 2MB, criar um ambiente PlatformIO separado ou uma nova tabela de particao em sprint propria.
- Nao usar `erase_flash` como parte desta verificacao; upload manual deve ser feito apenas na bancada, com evidencia.

## Proximo passo recomendado

Antes da persistencia:

1. Fazer upload manual com a nova tabela 4MB.
2. Rodar smoke HTTP v2 novamente.
3. Confirmar AP+STA, NAT, SNTP, DNS, display e paginas.
4. So entao criar uma sprint de eventos persistentes com politica de escrita e particao dedicada.
