#pragma once

#if __has_include("config.local.h")
#include "config.local.h"
#endif

#ifndef APPLIANCE_V2_PROJECT
#define APPLIANCE_V2_PROJECT "ESP32 Mini Firewall Gateway - ESP-IDF Appliance v2"
#endif

#ifndef APPLIANCE_V2_VERSION
#define APPLIANCE_V2_VERSION "0.1.0-poc"
#endif

#ifndef APPLIANCE_V2_UPSTREAM_SSID
#define APPLIANCE_V2_UPSTREAM_SSID "YOUR_UPSTREAM_WIFI"
#endif

#ifndef APPLIANCE_V2_UPSTREAM_PASSWORD
#define APPLIANCE_V2_UPSTREAM_PASSWORD "YOUR_UPSTREAM_PASSWORD"
#endif

#ifndef APPLIANCE_V2_AP_SSID
#define APPLIANCE_V2_AP_SSID "ESP32-APPLIANCE-V2"
#endif

#ifndef APPLIANCE_V2_AP_PASSWORD
#define APPLIANCE_V2_AP_PASSWORD "change-me-lab"
#endif

#ifndef APPLIANCE_V2_AP_CHANNEL
#define APPLIANCE_V2_AP_CHANNEL 6
#endif

#ifndef APPLIANCE_V2_AP_MAX_CLIENTS
#define APPLIANCE_V2_AP_MAX_CLIENTS 4
#endif
