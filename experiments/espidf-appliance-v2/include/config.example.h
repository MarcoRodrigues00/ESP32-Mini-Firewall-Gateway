#pragma once

// Copy this file to include/config.local.h and fill local credentials.
// Never commit config.local.h.

#define APPLIANCE_V2_UPSTREAM_SSID "YOUR_UPSTREAM_WIFI"
#define APPLIANCE_V2_UPSTREAM_PASSWORD "YOUR_UPSTREAM_PASSWORD"

#define APPLIANCE_V2_AP_SSID "ESP32-APPLIANCE-V2"
#define APPLIANCE_V2_AP_PASSWORD "change-me-lab"
#define APPLIANCE_V2_AP_CHANNEL 6
#define APPLIANCE_V2_AP_MAX_CLIENTS 4

// Display local opcional.
// O pinout/controlador do modulo de bancada ainda precisa ser confirmado.
// Deixe 0 ate preencher estes valores em include/config.local.h.
#define APPLIANCE_V2_ENABLE_DISPLAY 0
#define APPLIANCE_V2_DISPLAY_WIDTH 240
#define APPLIANCE_V2_DISPLAY_HEIGHT 240

// Drivers suportados pela camada leve:
// 0 = nao configurado, 1 = ST7789 SPI, 2 = ILI9341 SPI.
#define APPLIANCE_V2_DISPLAY_DRIVER 0

// Pinos SPI/display. Use -1 quando o sinal nao existir no modulo.
#define APPLIANCE_V2_DISPLAY_PIN_MOSI -1
#define APPLIANCE_V2_DISPLAY_PIN_MISO -1
#define APPLIANCE_V2_DISPLAY_PIN_SCLK -1
#define APPLIANCE_V2_DISPLAY_PIN_CS -1
#define APPLIANCE_V2_DISPLAY_PIN_DC -1
#define APPLIANCE_V2_DISPLAY_PIN_RST -1
#define APPLIANCE_V2_DISPLAY_PIN_BL -1
