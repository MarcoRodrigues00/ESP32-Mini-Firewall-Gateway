#include <Arduino.h>

namespace {
constexpr const char *PROJECT_NAME = "ESP32 Mini Firewall Gateway";
constexpr const char *PROJECT_VERSION = "0.1.0-fase0";
constexpr unsigned long HEARTBEAT_INTERVAL_MS = 5000UL;

unsigned long lastHeartbeatMs = 0;

unsigned long uptimeSeconds()
{
    return millis() / 1000UL;
}
} // namespace

void setup()
{
    Serial.begin(115200);

    Serial.println();
    Serial.println(PROJECT_NAME);
    Serial.print("Versao: ");
    Serial.println(PROJECT_VERSION);
    Serial.println("Fase 0: build minimo PlatformIO para ESP32.");
    Serial.println("Projeto didatico/de laboratorio; nao substitui firewall profissional.");

    lastHeartbeatMs = millis();
}

void loop()
{
    const unsigned long nowMs = millis();

    if (nowMs - lastHeartbeatMs >= HEARTBEAT_INTERVAL_MS) {
        lastHeartbeatMs = nowMs;
        Serial.print("Heartbeat Fase 0 | uptime=");
        Serial.print(uptimeSeconds());
        Serial.println("s");
    }

    vTaskDelay(pdMS_TO_TICKS(1000));
}
