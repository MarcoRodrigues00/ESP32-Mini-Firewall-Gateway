# Hardware — ESP32 Mini Firewall Gateway

## Componentes previstos

- ESP32
- INA219
- DHT22 ou DS18B20
- Botão físico
- Relé 5V
- Cooler 5V
- Fonte 5V externa
- Protoboard/jumpers
- Caixa física

## Pinagem sugerida

| GPIO | Função | Observação |
|---|---|---|
| 27 | DHT22/DS18B20 | Sensor de temperatura |
| 21 | INA219 SDA | I2C |
| 22 | INA219 SCL | I2C |
| 26 | Botão | INPUT_PULLUP + ISR |
| 25 | Relé | Saída digital |
| GND | Comum | ESP32, relé, fonte e sensores |

## Cuidados

- Cooler nunca deve ser ligado direto no GPIO.
- Usar fonte 5V externa para cooler/relé quando necessário.
- Manter GND comum.
- Verificar ligações antes de energizar.
