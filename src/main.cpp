#include <Arduino.h>
#include <Adafruit_INA219.h>
#include <WebServer.h>
#include <WiFi.h>
#include <cstdio>
#include <cstring>

namespace {
constexpr const char *PROJECT_NAME = "ESP32 Mini Firewall Gateway";
constexpr const char *PROJECT_VERSION = "0.8.0-sprint-firewall";
constexpr const char *PROJECT_PHASE = "Sprint firewall didatico";
constexpr const char *AP_SSID = "ESP32-Firewall-Lab";
constexpr const char *AP_PASSPHRASE = "esp32lab123";
constexpr unsigned long HEARTBEAT_INTERVAL_MS = 5000UL;
constexpr uint32_t WEB_SERVER_INTERVAL_MS = 10UL;
constexpr uint32_t METRICS_INTERVAL_MS = 1000UL;
constexpr float ENERGY_LOW_VOLTAGE_V = 4.75F;
constexpr float ENERGY_HIGH_CURRENT_MA = 500.0F;
constexpr float ENERGY_HIGH_POWER_MW = 2500.0F;
constexpr unsigned long ENERGY_ALERT_COOLDOWN_MS = 60000UL;
constexpr unsigned long FIREWALL_FLOOD_WINDOW_MS = 10000UL;
constexpr uint16_t FIREWALL_FLOOD_THRESHOLD = 20;
constexpr unsigned long FIREWALL_SECURITY_COOLDOWN_MS = 30000UL;
constexpr unsigned long WEB_ACCESS_EVENT_COOLDOWN_MS = 5000UL;
constexpr size_t EVENT_CAPACITY = 40;
constexpr size_t EVENT_MESSAGE_SIZE = 72;
constexpr size_t EVENT_VALUE_SIZE = 24;
constexpr BaseType_t CORE_WEB = 1;
constexpr BaseType_t CORE_BACKGROUND = 0;

WebServer server(80);
Adafruit_INA219 ina219;
SemaphoreHandle_t metricsMutex = nullptr;
SemaphoreHandle_t eventsMutex = nullptr;
SemaphoreHandle_t firewallMutex = nullptr;
TaskHandle_t webServerTaskHandle = nullptr;
TaskHandle_t metricsTaskHandle = nullptr;
TaskHandle_t heartbeatTaskHandle = nullptr;

struct TaskInfo {
    const char *name;
    BaseType_t core;
    const char *status;
};

struct ModuleInfo {
    const char *name;
    const char *status;
};

const TaskInfo TASKS[] = {
    {"taskWebServer", CORE_WEB, "ativa"},
    {"taskMetrics", CORE_BACKGROUND, "ativa"},
    {"taskHeartbeat", CORE_BACKGROUND, "ativa"},
};

const ModuleInfo MODULES[] = {
    {"Wi-Fi AP", "ativo"},
    {"WebServer", "ativo"},
    {"Metricas", "ativo"},
    {"Firewall didatico", "ativo"},
    {"Sensores", "planejado"},
    {"Atuadores", "planejado"},
    {"Eventos em memoria", "ativo"},
    {"Logs persistentes", "planejado"},
    {"Energia", "planejado"},
};

struct EventRecord {
    uint32_t id;
    unsigned long uptimeMs;
    char level[10];
    char source[12];
    char message[EVENT_MESSAGE_SIZE];
    char value[EVENT_VALUE_SIZE];
    bool hasValue;
};

struct EnergySnapshot {
    bool available;
    float busVoltageV;
    float shuntVoltageMv;
    float currentMa;
    float powerMw;
    unsigned long lastUpdateMs;
    char alertStatus[48];
};

struct FirewallSnapshot {
    bool enabled;
    uint32_t totalRequests;
    uint32_t securityEvents;
    char lastClientIp[16];
    char lastRoute[32];
    unsigned long lastRequestMs;
    unsigned long floodWindowMs;
    uint16_t floodThreshold;
};

struct MetricsSnapshot {
    unsigned long uptimeSeconds;
    uint32_t freeHeap;
    uint32_t minFreeHeap;
    uint32_t flashSize;
    uint32_t sketchSize;
    char apIp[16];
    char apSsid[33];
    EnergySnapshot energy;
    uint32_t buildStatusJsonMicros;
    bool buildStatusJsonMeasured;
    uint32_t handleRootMicros;
    bool handleRootMeasured;
    uint32_t handleEvidencesMicros;
    bool handleEvidencesMeasured;
};

struct FunctionTiming {
    const char *name;
    uint32_t lastMicros;
    bool measured;
};

MetricsSnapshot metricsSnapshot = {};
FirewallSnapshot firewallSnapshot = {true, 0, 0, "n/d", "n/d", 0, FIREWALL_FLOOD_WINDOW_MS, FIREWALL_FLOOD_THRESHOLD};
EventRecord events[EVENT_CAPACITY] = {};
bool ina219Available = false;
unsigned long lastLowVoltageAlertMs = 0;
unsigned long lastHighCurrentAlertMs = 0;
unsigned long lastHighPowerAlertMs = 0;
size_t eventStart = 0;
size_t eventCount = 0;
uint32_t nextEventId = 1;
unsigned long firewallWindowStartMs = 0;
uint16_t firewallWindowRequests = 0;
unsigned long lastFloodSecurityEventMs = 0;
unsigned long lastWebAccessEventMs = 0;
char lastWebAccessEventRoute[32] = "";

unsigned long uptimeSeconds()
{
    return millis() / 1000UL;
}

void copyText(char *target, size_t targetSize, const char *source)
{
    if (targetSize == 0) {
        return;
    }

    std::strncpy(target, source, targetSize - 1);
    target[targetSize - 1] = '\0';
}

void appendJsonEscaped(String &json, const char *text)
{
    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor == '"' || *cursor == '\\') {
            json += '\\';
        }
        json += *cursor;
    }
}

void incrementSecurityEventCount()
{
    if (firewallMutex != nullptr && xSemaphoreTake(firewallMutex, pdMS_TO_TICKS(20)) == pdTRUE) {
        ++firewallSnapshot.securityEvents;
        xSemaphoreGive(firewallMutex);
    }
}

FirewallSnapshot readFirewallSnapshot()
{
    FirewallSnapshot snapshot = {true, 0, 0, "n/d", "n/d", 0, FIREWALL_FLOOD_WINDOW_MS, FIREWALL_FLOOD_THRESHOLD};
    if (firewallMutex != nullptr && xSemaphoreTake(firewallMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        snapshot = firewallSnapshot;
        xSemaphoreGive(firewallMutex);
    }
    return snapshot;
}

void addEvent(const char *level, const char *source, const char *message, const char *value = nullptr)
{
    if (eventsMutex == nullptr || xSemaphoreTake(eventsMutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        return;
    }

    const size_t writeIndex = (eventStart + eventCount) % EVENT_CAPACITY;
    EventRecord &event = events[writeIndex];
    event.id = nextEventId++;
    event.uptimeMs = millis();
    copyText(event.level, sizeof(event.level), level);
    copyText(event.source, sizeof(event.source), source);
    copyText(event.message, sizeof(event.message), message);
    event.hasValue = value != nullptr && value[0] != '\0';
    copyText(event.value, sizeof(event.value), event.hasValue ? value : "");

    if (std::strcmp(level, "SECURITY") == 0) {
        incrementSecurityEventCount();
    }

    if (eventCount < EVENT_CAPACITY) {
        ++eventCount;
    } else {
        eventStart = (eventStart + 1) % EVENT_CAPACITY;
    }

    xSemaphoreGive(eventsMutex);
}

size_t readEventCount()
{
    size_t count = 0;
    if (eventsMutex != nullptr && xSemaphoreTake(eventsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        count = eventCount;
        xSemaphoreGive(eventsMutex);
    }
    return count;
}

const char *levelClass(const char *level)
{
    if (std::strcmp(level, "WARN") == 0) {
        return "warn";
    }
    if (std::strcmp(level, "ERROR") == 0) {
        return "error";
    }
    if (std::strcmp(level, "SECURITY") == 0) {
        return "security";
    }
    return "info";
}

const char *moduleStatus(const ModuleInfo &module)
{
    if (std::strcmp(module.name, "Energia") == 0) {
        return ina219Available ? "ativo" : "indisponivel";
    }
    return module.status;
}

void formatFloat(char *target, size_t targetSize, float value, uint8_t decimals)
{
    if (targetSize == 0) {
        return;
    }
    std::snprintf(target, targetSize, "%.*f", decimals, value);
}

String formattedFloat(float value, uint8_t decimals)
{
    char buffer[20];
    formatFloat(buffer, sizeof(buffer), value, decimals);
    return String(buffer);
}

void registerHttpAccess(const char *route, bool logAccessEvent = true)
{
    char clientIp[16];
    copyText(clientIp, sizeof(clientIp), server.client().remoteIP().toString().c_str());

    bool shouldLogAccess = false;
    bool shouldLogFlood = false;
    const unsigned long now = millis();

    if (firewallMutex != nullptr && xSemaphoreTake(firewallMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        firewallSnapshot.enabled = true;
        ++firewallSnapshot.totalRequests;
        firewallSnapshot.lastRequestMs = now;
        firewallSnapshot.floodWindowMs = FIREWALL_FLOOD_WINDOW_MS;
        firewallSnapshot.floodThreshold = FIREWALL_FLOOD_THRESHOLD;
        copyText(firewallSnapshot.lastClientIp, sizeof(firewallSnapshot.lastClientIp), clientIp);
        copyText(firewallSnapshot.lastRoute, sizeof(firewallSnapshot.lastRoute), route);

        if (firewallWindowStartMs == 0 || now - firewallWindowStartMs > FIREWALL_FLOOD_WINDOW_MS) {
            firewallWindowStartMs = now;
            firewallWindowRequests = 1;
        } else if (firewallWindowRequests < UINT16_MAX) {
            ++firewallWindowRequests;
        }

        if (firewallWindowRequests > FIREWALL_FLOOD_THRESHOLD &&
            (lastFloodSecurityEventMs == 0 || now - lastFloodSecurityEventMs >= FIREWALL_SECURITY_COOLDOWN_MS)) {
            shouldLogFlood = true;
            lastFloodSecurityEventMs = now;
        }

        if (logAccessEvent &&
            (lastWebAccessEventMs == 0 || now - lastWebAccessEventMs >= WEB_ACCESS_EVENT_COOLDOWN_MS ||
             std::strcmp(lastWebAccessEventRoute, route) != 0)) {
            shouldLogAccess = true;
            lastWebAccessEventMs = now;
            copyText(lastWebAccessEventRoute, sizeof(lastWebAccessEventRoute), route);
        }

        xSemaphoreGive(firewallMutex);
    }

    if (shouldLogAccess) {
        addEvent("INFO", "WEB", "Acesso HTTP ao painel", route);
    }
    if (shouldLogFlood) {
        addEvent("SECURITY", "FIREWALL", "Possivel flood HTTP detectado", route);
    }
}

void addSecurityDemoEvent(const char *message, const char *value = nullptr)
{
    addEvent("SECURITY", "DEMO", message, value);
}

void maybeAddEnergyAlert(bool condition, unsigned long &lastAlertMs, const char *message, float value, const char *unit)
{
    const unsigned long now = millis();
    if (!condition || (lastAlertMs != 0 && now - lastAlertMs < ENERGY_ALERT_COOLDOWN_MS)) {
        return;
    }

    char eventValue[EVENT_VALUE_SIZE];
    std::snprintf(eventValue, sizeof(eventValue), "%.2f %s", value, unit);
    addEvent("WARN", "SENSOR", message, eventValue);
    lastAlertMs = now;
}

MetricsSnapshot readMetricsSnapshot()
{
    MetricsSnapshot snapshot = {};

    if (metricsMutex != nullptr && xSemaphoreTake(metricsMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        snapshot = metricsSnapshot;
        xSemaphoreGive(metricsMutex);
    }

    return snapshot;
}

void refreshMetricsSnapshot()
{
    EnergySnapshot energy = {};
    energy.available = ina219Available;
    copyText(energy.alertStatus, sizeof(energy.alertStatus), ina219Available ? "normal" : "sensor indisponivel");

    if (ina219Available) {
        energy.busVoltageV = ina219.getBusVoltage_V();
        energy.shuntVoltageMv = ina219.getShuntVoltage_mV();
        energy.currentMa = ina219.getCurrent_mA();
        energy.powerMw = ina219.getPower_mW();
        energy.lastUpdateMs = millis();

        bool hasAlert = false;
        if (energy.busVoltageV < ENERGY_LOW_VOLTAGE_V) {
            copyText(energy.alertStatus, sizeof(energy.alertStatus), "tensao baixa");
            maybeAddEnergyAlert(true, lastLowVoltageAlertMs, "Tensao baixa no INA219", energy.busVoltageV, "V");
            hasAlert = true;
        }
        if (energy.currentMa > ENERGY_HIGH_CURRENT_MA) {
            copyText(energy.alertStatus, sizeof(energy.alertStatus), "corrente alta");
            maybeAddEnergyAlert(true, lastHighCurrentAlertMs, "Corrente alta no INA219", energy.currentMa, "mA");
            hasAlert = true;
        }
        if (energy.powerMw > ENERGY_HIGH_POWER_MW) {
            copyText(energy.alertStatus, sizeof(energy.alertStatus), "potencia alta");
            maybeAddEnergyAlert(true, lastHighPowerAlertMs, "Potencia alta no INA219", energy.powerMw, "mW");
            hasAlert = true;
        }
        if (!hasAlert) {
            copyText(energy.alertStatus, sizeof(energy.alertStatus), "normal");
        }
    }

    if (metricsMutex == nullptr || xSemaphoreTake(metricsMutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        return;
    }

    metricsSnapshot.uptimeSeconds = uptimeSeconds();
    metricsSnapshot.freeHeap = ESP.getFreeHeap();
    metricsSnapshot.minFreeHeap = ESP.getMinFreeHeap();
    metricsSnapshot.flashSize = ESP.getFlashChipSize();
    metricsSnapshot.sketchSize = ESP.getSketchSize();
    metricsSnapshot.energy = energy;
    copyText(metricsSnapshot.apSsid, sizeof(metricsSnapshot.apSsid), AP_SSID);
    copyText(metricsSnapshot.apIp, sizeof(metricsSnapshot.apIp), WiFi.softAPIP().toString().c_str());

    xSemaphoreGive(metricsMutex);
}

void updateFunctionTiming(const char *name, uint32_t elapsedMicros)
{
    if (metricsMutex == nullptr || xSemaphoreTake(metricsMutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        return;
    }

    if (std::strcmp(name, "buildStatusJson") == 0) {
        metricsSnapshot.buildStatusJsonMicros = elapsedMicros;
        metricsSnapshot.buildStatusJsonMeasured = true;
    } else if (std::strcmp(name, "handleRoot") == 0) {
        metricsSnapshot.handleRootMicros = elapsedMicros;
        metricsSnapshot.handleRootMeasured = true;
    } else if (std::strcmp(name, "handleEvidences") == 0) {
        metricsSnapshot.handleEvidencesMicros = elapsedMicros;
        metricsSnapshot.handleEvidencesMeasured = true;
    }

    xSemaphoreGive(metricsMutex);
}

void appendModulesJson(String &json)
{
    json += "[";
    for (size_t index = 0; index < sizeof(MODULES) / sizeof(MODULES[0]); ++index) {
        if (index > 0) {
            json += ",";
        }
        json += "{\"name\":\"";
        json += MODULES[index].name;
        json += "\",\"status\":\"";
        json += moduleStatus(MODULES[index]);
        json += "\"}";
    }
    json += "]";
}

void appendEventJsonObject(String &json, const EventRecord &event)
{
    json += "{\"id\":";
    json += event.id;
    json += ",\"uptime_ms\":";
    json += event.uptimeMs;
    json += ",\"level\":\"";
    appendJsonEscaped(json, event.level);
    json += "\",\"source\":\"";
    appendJsonEscaped(json, event.source);
    json += "\",\"message\":\"";
    appendJsonEscaped(json, event.message);
    json += "\"";
    if (event.hasValue) {
        json += ",\"value\":\"";
        appendJsonEscaped(json, event.value);
        json += "\"";
    }
    json += "}";
}

String buildEventsJson()
{
    String json;
    json.reserve(3600);
    json += "{\"count\":";

    if (eventsMutex == nullptr || xSemaphoreTake(eventsMutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        json += "0,\"capacity\":";
        json += EVENT_CAPACITY;
        json += ",\"events\":[]}";
        return json;
    }

    json += eventCount;
    json += ",\"capacity\":";
    json += EVENT_CAPACITY;
    json += ",\"events\":[";
    for (size_t offset = 0; offset < eventCount; ++offset) {
        if (offset > 0) {
            json += ",";
        }
        const size_t index = (eventStart + offset) % EVENT_CAPACITY;
        appendEventJsonObject(json, events[index]);
    }
    json += "]}";
    xSemaphoreGive(eventsMutex);
    return json;
}

void appendEventsTableHtml(String &html, size_t limit)
{
    if (eventsMutex == nullptr || xSemaphoreTake(eventsMutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        html += F("<p class=\"note\">Eventos indisponiveis.</p>");
        return;
    }

    if (eventCount == 0) {
        html += F("<p class=\"note\">Nenhum evento registrado.</p>");
        xSemaphoreGive(eventsMutex);
        return;
    }

    const size_t rows = eventCount < limit ? eventCount : limit;
    html += F("<table><thead><tr><th>ID</th><th>Uptime</th><th>Level</th><th>Source</th><th>Mensagem</th><th>Valor</th></tr></thead><tbody>");
    for (size_t offset = 0; offset < rows; ++offset) {
        const size_t newestOffset = eventCount - 1 - offset;
        const size_t index = (eventStart + newestOffset) % EVENT_CAPACITY;
        const EventRecord &event = events[index];
        html += F("<tr><td>#");
        html += event.id;
        html += F("</td><td>");
        html += event.uptimeMs;
        html += F(" ms</td><td><span class=\"badge ");
        html += levelClass(event.level);
        html += F("\">");
        html += event.level;
        html += F("</span></td><td>");
        html += event.source;
        html += F("</td><td>");
        html += event.message;
        html += F("</td><td>");
        html += event.hasValue ? event.value : "-";
        html += F("</td></tr>");
    }
    html += F("</tbody></table>");
    xSemaphoreGive(eventsMutex);
}

String sharedPageStyle()
{
    String css;
    css.reserve(3600);
    css += F(":root{color-scheme:light;--bg:#eef1f5;--panel:#fff;--panel2:#f8fafc;--text:#17202a;--muted:#5d6876;--line:#d5dce5;--head:#172635;--head2:#223447;--link:#145ea8;--ok:#16735b;--warn:#9a6700;--err:#b42318;--sec:#5f6470}");
    css += F("*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif;font-size:15px}a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}");
    css += F("header{background:var(--head);color:#fff;border-bottom:4px solid var(--head2)}header .wrap,main{width:min(1120px,100%);margin:0 auto}header .wrap{padding:18px}h1{margin:0 0 5px;font-size:24px;line-height:1.2}header p{margin:0;color:#d6dee8;line-height:1.4}.header-row{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap}");
    css += F("main{padding:16px}.toolbar,.toplinks{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 14px}.btn,.linkbtn{display:inline-block;border:1px solid #b9c4d0;background:#fff;color:#1d3550;padding:8px 11px;border-radius:4px;min-height:34px}.btn.primary,.linkbtn.primary{background:#1f4f78;border-color:#1f4f78;color:#fff}.btn.warn{border-color:#c58b22}.btn.security{border-color:#9ba1aa}");
    css += F(".panel{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:14px}.panel.tight{padding:12px}h2,h3{margin:0 0 10px}h2{font-size:18px}h3{font-size:16px;margin-top:14px}.note,.muted{color:var(--muted);line-height:1.45}.note{margin:8px 0 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:10px}");
    css += F(".metric{border:1px solid var(--line);border-radius:5px;padding:10px;background:var(--panel2)}.metric strong{display:block;font-size:12px;color:var(--muted);margin-bottom:5px}.metric span{font-size:16px;word-break:break-word}.summary .metric span{font-size:17px}.badge{display:inline-block;border-radius:3px;padding:3px 7px;font-size:12px;font-weight:700;border:1px solid transparent;line-height:1.2}.ok,.info{background:#e7f4ef;color:var(--ok);border-color:#b7d9ce}.planned,.wait,.warn{background:#fff3d7;color:var(--warn);border-color:#e2c06d}.error{background:#fde8e5;color:var(--err);border-color:#f3b7af}.security{background:#eceff3;color:#4f5661;border-color:#c7ccd3}");
    css += F("table{width:100%;border-collapse:collapse;margin-top:8px;background:#fff}th,td{border:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}th{background:#f1f5f9;color:#445160;font-size:12px;font-weight:700}td{font-size:14px}.table-wrap{overflow-x:auto}.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}code{background:#eef2f6;border:1px solid var(--line);padding:2px 4px;border-radius:3px}");
    css += F("@media(max-width:760px){main{padding:12px}.cols{grid-template-columns:1fr}header .wrap{padding:15px}h1{font-size:21px}.toolbar,.toplinks{gap:6px}.btn,.linkbtn{padding:8px 9px}.metric span{font-size:15px}} ");
    return css;
}

void appendPageHead(String &html, const char *title)
{
    html += F("<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><title>");
    html += title;
    html += F("</title><style>");
    html += sharedPageStyle();
    html += F("</style></head>");
}

void appendHeader(String &html, const char *title, const char *subtitle)
{
    html += F("<body><header><div class=\"wrap\"><div class=\"header-row\"><div><h1>");
    html += title;
    html += F("</h1><p>");
    html += subtitle;
    html += F("</p></div><span class=\"badge ok\">ativo</span></div></div></header>");
}

String evidencePage()
{
    const MetricsSnapshot snapshot = readMetricsSnapshot();
    const size_t count = readEventCount();
    String html;
    html.reserve(7600);
    appendPageHead(html, "Evidencia de execucao - ESP32 Mini Firewall Gateway");
    appendHeader(html, "Evidencia de execucao", "Resumo tecnico para print do firmware em execucao no ESP32.");
    html += F("<main><div class=\"toolbar\"><a class=\"btn primary\" href=\"/\">Dashboard</a><a class=\"btn\" href=\"/logs\">Logs</a><a class=\"btn\" href=\"/api/status\">/api/status</a><a class=\"btn\" href=\"/api/events\">/api/events</a></div>");
    html += F("<div class=\"panel\"><h2>Resumo</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Versao</strong><span>");
    html += PROJECT_VERSION;
    html += F("</span></div><div class=\"metric\"><strong>IP AP</strong><span>");
    html += snapshot.apIp[0] != '\0' ? snapshot.apIp : "n/d";
    html += F("</span></div><div class=\"metric\"><strong>Wi-Fi</strong><span><span class=\"badge ok\">AP ativo</span></span></div><div class=\"metric\"><strong>Uptime</strong><span>");
    html += snapshot.uptimeSeconds;
    html += F("s</span></div><div class=\"metric\"><strong>Heap livre</strong><span>");
    html += snapshot.freeHeap;
    html += F(" bytes</span></div><div class=\"metric\"><strong>Eventos</strong><span>");
    html += count;
    html += F("/");
    html += EVENT_CAPACITY;
    html += F("</span></div></div></div>");
    const FirewallSnapshot firewall = readFirewallSnapshot();
    html += F("<div class=\"panel\"><h2>Seguranca de rede</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Firewall didatico</strong><span><span class=\"badge ok\">ativo</span></span></div><div class=\"metric\"><strong>Requisicoes HTTP</strong><span>");
    html += firewall.totalRequests;
    html += F("</span></div><div class=\"metric\"><strong>Eventos SECURITY</strong><span>");
    html += firewall.securityEvents;
    html += F("</span></div><div class=\"metric\"><strong>Ultima rota</strong><span>");
    html += firewall.lastRoute;
    html += F("</span></div></div><p class=\"note\">Deteccao didatica baseada em acessos HTTP ao painel; nao substitui firewall profissional.</p></div>");
    html += F("<div class=\"panel\"><h2>Energia</h2><div class=\"grid summary\"><div class=\"metric\"><strong>INA219</strong><span><span class=\"badge ");
    html += snapshot.energy.available ? "ok" : "planned";
    html += F("\">");
    html += snapshot.energy.available ? "detectado" : "indisponivel";
    html += F("</span></span></div><div class=\"metric\"><strong>Tensao</strong><span>");
    html += snapshot.energy.available ? formattedFloat(snapshot.energy.busVoltageV, 2) + " V" : "n/d";
    html += F("</span></div><div class=\"metric\"><strong>Corrente</strong><span>");
    html += snapshot.energy.available ? formattedFloat(snapshot.energy.currentMa, 1) + " mA" : "n/d";
    html += F("</span></div><div class=\"metric\"><strong>Potencia</strong><span>");
    html += snapshot.energy.available ? formattedFloat(snapshot.energy.powerMw, 1) + " mW" : "n/d";
    html += F("</span></div><div class=\"metric\"><strong>Alerta</strong><span>");
    html += snapshot.energy.alertStatus;
    html += F("</span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Modulos do firmware</h2><div class=\"table-wrap\"><table><thead><tr><th>Modulo</th><th>Status</th></tr></thead><tbody>");
    for (size_t index = 0; index < sizeof(MODULES) / sizeof(MODULES[0]); ++index) {
        const char *status = moduleStatus(MODULES[index]);
        const bool active = std::strcmp(status, "ativo") == 0;
        html += F("<tr><td>");
        html += MODULES[index].name;
        html += F("</td><td><span class=\"badge ");
        html += active ? "ok" : "planned";
        html += F("\">");
        html += status;
        html += F("</span></td></tr>");
    }
    html += F("</tbody></table></div></div><div class=\"panel\"><h2>Ultimos 5 eventos</h2><div class=\"table-wrap\">");
    appendEventsTableHtml(html, 5);
    html += F("</div><p class=\"note\">Nesta fase, eventos ficam em RAM e sao perdidos ao reiniciar.</p></div></main></body></html>");
    return html;
}

String logsPage()
{
    const size_t count = readEventCount();
    String html;
    html.reserve(8200);
    appendPageHead(html, "Registro de eventos - ESP32 Mini Firewall Gateway");
    appendHeader(html, "Registro de eventos", "Eventos em memoria para diagnostico do firmware e demonstracao em bancada.");
    html += F("<main><div class=\"toolbar\"><a class=\"btn primary\" href=\"/\">Dashboard</a><a class=\"btn\" href=\"/evidencias\">Evidencias</a><a class=\"btn\" href=\"/api/events\">JSON</a><a class=\"btn\" href=\"/demo/info\">Gerar INFO</a><a class=\"btn warn\" href=\"/demo/warn\">Gerar WARN</a><a class=\"btn security\" href=\"/demo/security\">Gerar SECURITY</a></div>");
    html += F("<div class=\"panel tight\"><div class=\"grid summary\"><div class=\"metric\"><strong>Eventos em memoria</strong><span>");
    html += count;
    html += F("/");
    html += EVENT_CAPACITY;
    html += F("</span></div><div class=\"metric\"><strong>Persistencia</strong><span>RAM</span></div><div class=\"metric\"><strong>Uso</strong><span>diagnostico</span></div></div><p class=\"note\">Eventos demo sao simulacoes controladas para apresentacao.</p></div>");
    html += F("<div class=\"panel\"><h2>Eventos recentes</h2><div class=\"table-wrap\">");
    appendEventsTableHtml(html, EVENT_CAPACITY);
    html += F("</div></div></main></body></html>");
    return html;
}

String htmlPage()
{
    String html;
    html.reserve(9200);
    appendPageHead(html, "ESP32 Mini Firewall Gateway");
    appendHeader(html, PROJECT_NAME, "Monitor ciberfisico didatico em ESP32 para TDE academico.");
    html += F("<main><div class=\"toplinks\"><a class=\"linkbtn primary\" href=\"/evidencias\">Evidencias</a><a class=\"linkbtn\" href=\"/logs\">Logs</a><a class=\"linkbtn\" href=\"/api/status\">API status</a><a class=\"linkbtn\" href=\"/api/events\">API eventos</a></div>");
    html += F("<div class=\"panel\"><h2>Resumo</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Status</strong><span id=\"status\">n/d</span></div><div class=\"metric\"><strong>IP AP</strong><span id=\"apIp\">n/d</span></div><div class=\"metric\"><strong>Uptime</strong><span id=\"uptime\">n/d</span></div><div class=\"metric\"><strong>Eventos</strong><span id=\"eventCount\">n/d</span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Firewall didatico</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Status</strong><span id=\"fwStatus\">n/d</span></div><div class=\"metric\"><strong>Requisicoes HTTP</strong><span id=\"fwRequests\">n/d</span></div><div class=\"metric\"><strong>Eventos SECURITY</strong><span id=\"fwSecurity\">n/d</span></div><div class=\"metric\"><strong>Ultima rota</strong><span id=\"fwRoute\">n/d</span></div><div class=\"metric\"><strong>Ultimo IP</strong><span id=\"fwIp\">n/d</span></div><div class=\"metric\"><strong>Regra de flood</strong><span id=\"fwRule\">n/d</span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Metricas do sistema</h2><div class=\"grid\"><div class=\"metric\"><strong>Heap livre</strong><span id=\"freeHeap\">n/d</span></div><div class=\"metric\"><strong>Heap minimo</strong><span id=\"minFreeHeap\">n/d</span></div><div class=\"metric\"><strong>Flash</strong><span id=\"flashSize\">n/d</span></div><div class=\"metric\"><strong>Sketch</strong><span id=\"sketchSize\">n/d</span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Energia</h2><div class=\"grid\"><div class=\"metric\"><strong>INA219</strong><span id=\"energyStatus\">n/d</span></div><div class=\"metric\"><strong>Tensao</strong><span id=\"energyVoltage\">n/d</span></div><div class=\"metric\"><strong>Corrente</strong><span id=\"energyCurrent\">n/d</span></div><div class=\"metric\"><strong>Potencia</strong><span id=\"energyPower\">n/d</span></div><div class=\"metric\"><strong>Ultimo update</strong><span id=\"energyUpdated\">n/d</span></div><div class=\"metric\"><strong>Alertas</strong><span id=\"energyAlert\">n/d</span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Modulos</h2><div class=\"table-wrap\"><table><thead><tr><th>Modulo</th><th>Status</th></tr></thead><tbody id=\"modulesTable\"><tr><td colspan=\"2\">n/d</td></tr></tbody></table></div></div>");
    html += F("<div class=\"cols\"><div class=\"panel\"><h2>Tasks FreeRTOS</h2><div class=\"table-wrap\"><table><thead><tr><th>Nome</th><th>Core</th><th>Status</th><th>Stack</th></tr></thead><tbody id=\"tasksTable\"><tr><td colspan=\"4\">n/d</td></tr></tbody></table></div></div>");
    html += F("<div class=\"panel\"><h2>Tempos de execucao</h2><div class=\"table-wrap\"><table><thead><tr><th>Funcao</th><th>Ultima medicao</th><th>Status</th></tr></thead><tbody id=\"timingsTable\"><tr><td colspan=\"3\">n/d</td></tr></tbody></table></div></div></div>");
    html += F("<div class=\"panel tight\"><h2>Registro de eventos</h2><p class=\"note\"><a href=\"/logs\">Abrir pagina de logs</a>. Eventos demo: <a href=\"/demo/info\">INFO</a>, <a href=\"/demo/warn\">WARN</a>, <a href=\"/demo/security\">SECURITY</a>.</p></div>");
    html += F("<script>function nz(v){return v===undefined||v===null?'n/d':v}function formatBytes(v){return typeof v==='number'&&v>0?v+' bytes':'n/d'}function fixed(v,d,u){return typeof v==='number'?v.toFixed(d)+' '+u:'n/d'}function badge(s){return '<span class=\"badge '+(s==='ativo'||s==='ativa'||s==='ok'||s==='detectado'||s==='normal'?'ok':'planned')+'\">'+s+'</span>'}function renderModules(items){const b=document.getElementById('modulesTable');b.innerHTML='';if(!Array.isArray(items)||!items.length){b.innerHTML='<tr><td colspan=\"2\">n/d</td></tr>';return}items.forEach(m=>{const r=document.createElement('tr');r.innerHTML='<td>'+m.name+'</td><td>'+badge(m.status)+'</td>';b.appendChild(r)})}function renderTasks(items){const b=document.getElementById('tasksTable');b.innerHTML='';if(!Array.isArray(items)||!items.length){b.innerHTML='<tr><td colspan=\"4\">n/d</td></tr>';return}items.forEach(t=>{const r=document.createElement('tr');r.innerHTML='<td>'+t.name+'</td><td>'+t.core+'</td><td>'+badge(t.status)+'</td><td>'+t.stackHighWatermark+'</td>';b.appendChild(r)})}function renderTimings(items){const b=document.getElementById('timingsTable');b.innerHTML='';if(!Array.isArray(items)||!items.length){b.innerHTML='<tr><td colspan=\"3\">n/d</td></tr>';return}items.forEach(t=>{const r=document.createElement('tr');r.innerHTML='<td>'+t.name+'</td><td>'+(t.measured?t.lastMicros+' us':'n/d')+'</td><td>'+badge(t.measured?'medida':'pendente')+'</td>';b.appendChild(r)})}function renderFirewall(f){f=f||{};document.getElementById('fwStatus').innerHTML=badge(f.enabled?'ativo':'indisponivel');document.getElementById('fwRequests').textContent=nz(f.total_requests);document.getElementById('fwSecurity').textContent=nz(f.security_events);document.getElementById('fwRoute').textContent=f.last_route||'n/d';document.getElementById('fwIp').textContent=f.last_client_ip||'n/d';document.getElementById('fwRule').textContent=nz(f.flood_threshold)+' req / '+nz(f.flood_window_ms)+' ms'}function renderEnergy(e){e=e||{};document.getElementById('energyStatus').innerHTML=badge(e.available?'detectado':'indisponivel');document.getElementById('energyVoltage').textContent=e.available?fixed(e.bus_voltage_v,2,'V'):'n/d';document.getElementById('energyCurrent').textContent=e.available?fixed(e.current_ma,1,'mA'):'n/d';document.getElementById('energyPower').textContent=e.available?fixed(e.power_mw,1,'mW'):'n/d';document.getElementById('energyUpdated').textContent=e.available?nz(e.last_update_ms)+' ms':'n/d';document.getElementById('energyAlert').innerHTML=badge(e.alert_status||'sensor indisponivel')}async function refreshStatus(){try{const res=await fetch('/api/status');const d=await res.json();const ev=nz(d.eventCount)+'/'+nz(d.eventCapacity);document.getElementById('status').innerHTML=badge(d.status||'n/d');document.getElementById('apIp').textContent=d.apIp||d.ip||'n/d';document.getElementById('uptime').textContent=nz(d.uptimeSeconds)+'s';document.getElementById('eventCount').textContent=ev;document.getElementById('freeHeap').textContent=formatBytes(d.freeHeap);document.getElementById('minFreeHeap').textContent=formatBytes(d.minFreeHeap);document.getElementById('flashSize').textContent=formatBytes(d.flashSize);document.getElementById('sketchSize').textContent=formatBytes(d.sketchSize);renderFirewall(d.firewall);renderEnergy(d.energy);renderModules(d.modules);renderTasks(d.tasks);renderTimings(d.functionTimings)}catch(e){document.getElementById('status').textContent='erro'}}refreshStatus();</script>");
    html += F("</main></body></html>");
    return html;
}

String buildStatusJson()
{
    const MetricsSnapshot snapshot = readMetricsSnapshot();
    String json;
    json.reserve(1280);
    json += "{";
    json += "\"project_name\":\"";
    json += PROJECT_NAME;
    json += "\",\"firmware_version\":\"";
    json += PROJECT_VERSION;
    json += "\",\"wifi_connected\":";
    json += WiFi.getMode() == WIFI_AP ? "true" : "false";
    json += ",\"ip\":\"";
    json += snapshot.apIp;
    json += "\",\"uptime_ms\":";
    json += millis();
    json += ",\"free_heap\":";
    json += snapshot.freeHeap;
    json += ",\"modules\":";
    appendModulesJson(json);
    json += ",";
    json += "\"project\":\"";
    json += PROJECT_NAME;
    json += "\",\"version\":\"";
    json += PROJECT_VERSION;
    json += "\",\"phase\":\"";
    json += PROJECT_PHASE;
    json += "\",\"uptimeSeconds\":";
    json += snapshot.uptimeSeconds;
    json += ",\"freeHeap\":";
    json += snapshot.freeHeap;
    json += ",\"minFreeHeap\":";
    json += snapshot.minFreeHeap;
    json += ",\"flashSize\":";
    json += snapshot.flashSize;
    json += ",\"sketchSize\":";
    json += snapshot.sketchSize;
    json += ",\"apSsid\":\"";
    json += snapshot.apSsid;
    json += "\",\"apIp\":\"";
    json += snapshot.apIp;
    json += "\",\"tasks\":[";

    for (size_t index = 0; index < sizeof(TASKS) / sizeof(TASKS[0]); ++index) {
        if (index > 0) {
            json += ",";
        }
        json += "{\"name\":\"";
        json += TASKS[index].name;
        json += "\",\"core\":";
        json += TASKS[index].core;
        json += ",\"status\":\"";
        json += TASKS[index].status;
        json += "\",\"stackHighWatermark\":\"pendente\"}";
    }

    json += "],\"functionTimings\":[";
    const FunctionTiming timings[] = {
        {"buildStatusJson", snapshot.buildStatusJsonMicros, snapshot.buildStatusJsonMeasured},
        {"handleRoot", snapshot.handleRootMicros, snapshot.handleRootMeasured},
        {"handleEvidences", snapshot.handleEvidencesMicros, snapshot.handleEvidencesMeasured},
        {"taskMetrics", 0, false},
        {"taskWebServer", 0, false},
    };

    for (size_t index = 0; index < sizeof(timings) / sizeof(timings[0]); ++index) {
        if (index > 0) {
            json += ",";
        }
        json += "{\"name\":\"";
        json += timings[index].name;
        json += "\",\"lastMicros\":";
        json += timings[index].lastMicros;
        json += ",\"measured\":";
        json += timings[index].measured ? "true" : "false";
        json += "}";
    }

    json += "],\"energy\":{";
    json += "\"available\":";
    json += snapshot.energy.available ? "true" : "false";
    json += ",\"bus_voltage_v\":";
    json += formattedFloat(snapshot.energy.busVoltageV, 3);
    json += ",\"shunt_voltage_mv\":";
    json += formattedFloat(snapshot.energy.shuntVoltageMv, 3);
    json += ",\"current_ma\":";
    json += formattedFloat(snapshot.energy.currentMa, 3);
    json += ",\"power_mw\":";
    json += formattedFloat(snapshot.energy.powerMw, 3);
    json += ",\"last_update_ms\":";
    json += snapshot.energy.lastUpdateMs;
    json += ",\"alert_status\":\"";
    appendJsonEscaped(json, snapshot.energy.alertStatus);
    json += "\"}";
    const FirewallSnapshot firewall = readFirewallSnapshot();
    json += ",\"firewall\":{";
    json += "\"enabled\":";
    json += firewall.enabled ? "true" : "false";
    json += ",\"total_requests\":";
    json += firewall.totalRequests;
    json += ",\"security_events\":";
    json += firewall.securityEvents;
    json += ",\"last_client_ip\":\"";
    appendJsonEscaped(json, firewall.lastClientIp);
    json += "\",\"last_route\":\"";
    appendJsonEscaped(json, firewall.lastRoute);
    json += "\",\"last_request_ms\":";
    json += firewall.lastRequestMs;
    json += ",\"flood_window_ms\":";
    json += firewall.floodWindowMs;
    json += ",\"flood_threshold\":";
    json += firewall.floodThreshold;
    json += "}";
    json += ",\"eventCount\":";
    json += readEventCount();
    json += ",\"eventCapacity\":";
    json += EVENT_CAPACITY;
    json += ",\"status\":\"ok\"";
    json += "}";

    return json;
}

void handleRoot()
{
    const uint32_t startMicros = micros();
    registerHttpAccess("/");
    server.send(200, "text/html; charset=utf-8", htmlPage());
    updateFunctionTiming("handleRoot", micros() - startMicros);
}

void handleStatus()
{
    const uint32_t startMicros = micros();
    registerHttpAccess("/api/status");
    const String json = buildStatusJson();
    updateFunctionTiming("buildStatusJson", micros() - startMicros);
    server.send(200, "application/json", json);
}

void handleEventsApi()
{
    registerHttpAccess("/api/events");
    server.send(200, "application/json", buildEventsJson());
}

void handleEvidences()
{
    const uint32_t startMicros = micros();
    registerHttpAccess("/evidencias");
    server.send(200, "text/html; charset=utf-8", evidencePage());
    updateFunctionTiming("handleEvidences", micros() - startMicros);
}

void handleLogs()
{
    registerHttpAccess(server.uri().c_str());
    server.send(200, "text/html; charset=utf-8", logsPage());
}

void redirectToLogs()
{
    server.sendHeader("Location", "/logs", true);
    server.send(303, "text/plain; charset=utf-8", "Evento registrado. Consulte /logs");
}

void handleDemoInfo()
{
    registerHttpAccess("/demo/info");
    addEvent("INFO", "DEMO", "Evento demonstrativo informativo");
    redirectToLogs();
}

void handleDemoWarn()
{
    registerHttpAccess("/demo/warn");
    addEvent("WARN", "DEMO", "Alerta demonstrativo de condicao anormal");
    redirectToLogs();
}

void handleDemoSecurity()
{
    registerHttpAccess("/demo/security");
    addSecurityDemoEvent("Evento demonstrativo de seguranca");
    redirectToLogs();
}

void handleDemoFlood()
{
    registerHttpAccess("/demo/flood");
    addSecurityDemoEvent("Simulacao controlada de excesso de requisicoes", "flood didatico");
    redirectToLogs();
}

void handleNotFound()
{
    registerHttpAccess("404", false);
    server.send(404, "text/plain; charset=utf-8", "Rota nao encontrada");
}

void setupEnergySensor()
{
    ina219Available = ina219.begin();
    if (ina219Available) {
        ina219.setCalibration_32V_2A();
        addEvent("INFO", "SENSOR", "INA219 iniciado", "I2C 0x40");
        return;
    }

    addEvent("WARN", "SENSOR", "INA219 nao detectado", "I2C 0x40");
}

void setupAccessPoint()
{
    WiFi.mode(WIFI_AP);
    const bool apStarted = WiFi.softAP(AP_SSID, AP_PASSPHRASE);

    Serial.print("Wi-Fi AP SSID: ");
    Serial.println(AP_SSID);
    Serial.print("Wi-Fi AP iniciado: ");
    Serial.println(apStarted ? "sim" : "nao");
    Serial.print("Wi-Fi AP IP: ");
    Serial.println(WiFi.softAPIP());

    addEvent(apStarted ? "INFO" : "ERROR", "WIFI", apStarted ? "Wi-Fi AP iniciado" : "Falha ao iniciar Wi-Fi AP", WiFi.softAPIP().toString().c_str());
}

void setupWebServer()
{
    server.on("/", HTTP_GET, handleRoot);
    server.on("/api/status", HTTP_GET, handleStatus);
    server.on("/api/events", HTTP_GET, handleEventsApi);
    server.on("/evidencias", HTTP_GET, handleEvidences);
    server.on("/logs", HTTP_GET, handleLogs);
    server.on("/eventos", HTTP_GET, handleLogs);
    server.on("/demo/info", HTTP_GET, handleDemoInfo);
    server.on("/demo/warn", HTTP_GET, handleDemoWarn);
    server.on("/demo/security", HTTP_GET, handleDemoSecurity);
    server.on("/demo/flood", HTTP_GET, handleDemoFlood);
    server.onNotFound(handleNotFound);
    server.begin();

    Serial.println("Servidor web iniciado na porta 80.");
    addEvent("INFO", "WEB", "Servidor web iniciado", "porta 80");
}

void taskWebServer(void *parameter)
{
    (void)parameter;

    for (;;) {
        server.handleClient();
        vTaskDelay(pdMS_TO_TICKS(WEB_SERVER_INTERVAL_MS));
    }
}

void taskMetrics(void *parameter)
{
    (void)parameter;

    for (;;) {
        refreshMetricsSnapshot();
        vTaskDelay(pdMS_TO_TICKS(METRICS_INTERVAL_MS));
    }
}

void taskHeartbeat(void *parameter)
{
    (void)parameter;

    for (;;) {
        Serial.print("Heartbeat Fase 2 | uptime=");
        Serial.print(uptimeSeconds());
        Serial.println("s");
        vTaskDelay(pdMS_TO_TICKS(HEARTBEAT_INTERVAL_MS));
    }
}

void createTasks()
{
    xTaskCreatePinnedToCore(taskWebServer, "taskWebServer", 8192, nullptr, 2, &webServerTaskHandle, CORE_WEB);
    xTaskCreatePinnedToCore(taskMetrics, "taskMetrics", 4096, nullptr, 1, &metricsTaskHandle, CORE_BACKGROUND);
    xTaskCreatePinnedToCore(taskHeartbeat, "taskHeartbeat", 3072, nullptr, 1, &heartbeatTaskHandle, CORE_BACKGROUND);
}
} // namespace

void setup()
{
    Serial.begin(115200);

    Serial.println();
    Serial.println(PROJECT_NAME);
    Serial.print("Versao: ");
    Serial.println(PROJECT_VERSION);
    Serial.println(PROJECT_PHASE);
    Serial.println("Projeto didatico/de laboratorio; nao substitui firewall profissional.");

    metricsMutex = xSemaphoreCreateMutex();
    eventsMutex = xSemaphoreCreateMutex();
    firewallMutex = xSemaphoreCreateMutex();
    addEvent("INFO", "SYSTEM", "Boot do sistema", PROJECT_VERSION);
    setupEnergySensor();
    setupAccessPoint();
    setupWebServer();
    refreshMetricsSnapshot();
    createTasks();
}

void loop()
{
    vTaskDelay(pdMS_TO_TICKS(1000));
}
