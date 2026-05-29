#include <Arduino.h>
#include <Adafruit_INA219.h>
#include <LittleFS.h>
#include <WebServer.h>
#include <WiFi.h>
#include <lwip/opt.h>
#if IP_NAPT && IP_FORWARD
#include <lwip/lwip_napt.h>
#endif
#include <cstdio>
#include <cstring>

namespace {
constexpr const char *PROJECT_NAME = "ESP32 Mini Firewall Gateway";
constexpr const char *PROJECT_VERSION = "0.12.0-sprint-nat-experimental";
constexpr const char *PROJECT_PHASE = "Sprint NAT experimental AP+STA";
constexpr const char *AP_SSID = "ESP32-Firewall-Lab";
constexpr const char *AP_PASSPHRASE = "esp32lab123";
constexpr bool NAT_EXPERIMENTAL_ENABLED = true;
constexpr unsigned long UPSTREAM_CONNECT_TIMEOUT_MS = 3000UL;
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
constexpr unsigned long IDS_EVENT_COOLDOWN_MS = 30000UL;
constexpr unsigned long IDS_404_EVENT_COOLDOWN_MS = 30000UL;
constexpr unsigned long IDS_SCAN_WINDOW_MS = 15000UL;
constexpr uint16_t IDS_SCAN_404_THRESHOLD = 5;
constexpr unsigned long IDS_SCAN_COOLDOWN_MS = 30000UL;
constexpr size_t EVENT_CAPACITY = 40;
constexpr const char *PERSISTENT_EVENTS_PATH = "/events.log";
constexpr const char *WIFI_CONFIG_PATH = "/wifi.json";
constexpr size_t PERSISTENT_EVENTS_MAX_SIZE = 16 * 1024;
constexpr size_t WIFI_SSID_MAX_SIZE = 32;
constexpr size_t WIFI_PASSPHRASE_MAX_SIZE = 63;
constexpr size_t WIFI_PASSPHRASE_MIN_SIZE = 8;
constexpr size_t EVENT_MESSAGE_SIZE = 72;
constexpr size_t EVENT_VALUE_SIZE = 24;
constexpr BaseType_t CORE_WEB = 1;
constexpr BaseType_t CORE_BACKGROUND = 0;
const char *WEB_HEADER_KEYS[] = {"User-Agent"};

WebServer server(80);
Adafruit_INA219 ina219;
SemaphoreHandle_t metricsMutex = nullptr;
SemaphoreHandle_t eventsMutex = nullptr;
SemaphoreHandle_t firewallMutex = nullptr;
SemaphoreHandle_t gatewayMutex = nullptr;
SemaphoreHandle_t wifiConfigMutex = nullptr;
SemaphoreHandle_t natMutex = nullptr;
SemaphoreHandle_t trafficMutex = nullptr;
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
    {"Gateway AP+STA", "ativo"},
    {"NAT experimental", "ativo"},
    {"IDS didatico", "ativo"},
    {"Traffic Monitor HTTP", "ativo"},
    {"Sensores", "planejado"},
    {"Atuadores", "planejado"},
    {"Eventos em memoria", "ativo"},
    {"Logs persistentes", "ativo"},
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
    bool idsEnabled;
    uint32_t idsEvents;
    uint32_t suspicious404Count;
    uint32_t sensitivePathHits;
};

struct GatewaySnapshot {
    bool apEnabled;
    char apSsid[33];
    char apIp[16];
    bool staConfigured;
    bool staConnected;
    char upstreamSsid[33];
    char upstreamIp[16];
    int32_t upstreamRssi;
    unsigned long lastConnectAttemptMs;
    unsigned long lastStatusChangeMs;
    uint8_t clientCount;
    char mode[8];
    bool natEnabled;
    bool passphrasePresent;
    char lastStatus[24];
    char lastError[64];
};

struct WifiUpstreamConfig {
    bool saved;
    char ssid[WIFI_SSID_MAX_SIZE + 1];
    char passphrase[WIFI_PASSPHRASE_MAX_SIZE + 1];
    bool passphrasePresent;
};

struct NatSnapshot {
    bool experimentalEnabled;
    bool supported;
    bool enabled;
    bool active;
    unsigned long lastAttemptMs;
    char lastStatus[28];
    char lastError[72];
    char note[96];
};

struct TrafficRouteCounter {
    char route[32];
    uint32_t count;
};

struct TrafficSnapshot {
    uint32_t totalRequests;
    uint32_t notFoundCount;
    uint32_t sensitivePathHits;
    uint32_t suspiciousScanCount;
    uint32_t idsEvents;
    char lastIp[16];
    char lastRoute[32];
    char lastUserAgentShort[64];
    TrafficRouteCounter topRoutes[6];
    unsigned long scanWindowStartMs;
    uint16_t scanWindow404Count;
    unsigned long lastScanEventMs;
    unsigned long scanWindowMs;
    uint16_t scanThreshold;
    unsigned long scanCooldownMs;
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
FirewallSnapshot firewallSnapshot = {true, 0, 0, "n/d", "n/d", 0, FIREWALL_FLOOD_WINDOW_MS, FIREWALL_FLOOD_THRESHOLD, true, 0, 0, 0};
GatewaySnapshot gatewaySnapshot = {true, "ESP32-Firewall-Lab", "0.0.0.0", false, false, "nao configurado", "0.0.0.0", 0, 0, 0, 0, "AP_ONLY", false, false, "nao configurado", ""};
WifiUpstreamConfig wifiConfig = {false, "", "", false};
NatSnapshot natSnapshot = {NAT_EXPERIMENTAL_ENABLED, false, NAT_EXPERIMENTAL_ENABLED, false, 0, "inicializando", "", "NAT experimental depende de suporte NAPT no lwIP"};
TrafficSnapshot trafficSnapshot = {0, 0, 0, 0, 0, "n/d", "n/d", "n/d", {}, 0, 0, 0, IDS_SCAN_WINDOW_MS, IDS_SCAN_404_THRESHOLD, IDS_SCAN_COOLDOWN_MS};
EventRecord events[EVENT_CAPACITY] = {};
bool ina219Available = false;
bool littleFsAvailable = false;
bool persistentLogRotated = false;
uint32_t nextPersistentEventId = 1;
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
unsigned long lastIdsSecurityEventMs = 0;
unsigned long lastIds404EventMs = 0;
bool lastStaConnected = false;
uint8_t lastGatewayClientCount = 255;
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

void addEvent(const char *level, const char *source, const char *message, const char *value);
void refreshGatewaySnapshot(bool logChanges);
void evaluateNatState(bool logChanges);
void attemptUpstreamConnection(const char *reason);
void appendGatewayJson(String &json);
void appendNatJson(String &json);

void appendJsonEscaped(String &json, const char *text)
{
    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        if (*cursor == '"' || *cursor == '\\') {
            json += '\\';
        }
        json += *cursor;
    }
}

void appendHtmlEscaped(String &html, const char *text)
{
    for (const char *cursor = text; *cursor != '\0'; ++cursor) {
        switch (*cursor) {
            case '&':
                html += F("&amp;");
                break;
            case '<':
                html += F("&lt;");
                break;
            case '>':
                html += F("&gt;");
                break;
            case '"':
                html += F("&quot;");
                break;
            default:
                html += *cursor;
                break;
        }
    }
}

String maskedSsid(const char *ssid)
{
    if (ssid == nullptr || ssid[0] == '\0') {
        return "n/d";
    }
    const size_t length = std::strlen(ssid);
    if (length <= 2) {
        return String("*");
    }
    String value;
    value.reserve(length + 2);
    value += ssid[0];
    value += "***";
    value += ssid[length - 1];
    return value;
}

bool isImportantPersistentEvent(const char *level, const char *source, const char *message)
{
    if (std::strcmp(level, "WARN") == 0 || std::strcmp(level, "ERROR") == 0 || std::strcmp(level, "SECURITY") == 0) {
        return true;
    }

    if (std::strcmp(source, "SYSTEM") == 0 || std::strcmp(source, "STORAGE") == 0 ||
        std::strcmp(source, "SENSOR") == 0 || std::strcmp(source, "ENERGY") == 0 ||
        std::strcmp(source, "WIFI") == 0 || std::strcmp(source, "NAT") == 0) {
        return true;
    }

    if (std::strcmp(source, "FIREWALL") == 0 && std::strstr(message, "flood") != nullptr) {
        return true;
    }

    return false;
}

size_t persistentLogSize()
{
    if (!littleFsAvailable || !LittleFS.exists(PERSISTENT_EVENTS_PATH)) {
        return 0;
    }

    File file = LittleFS.open(PERSISTENT_EVENTS_PATH, "r");
    if (!file) {
        return 0;
    }
    const size_t size = file.size();
    file.close();
    return size;
}

void appendPersistentEventLine(String &line, const EventRecord &event)
{
    line += "{\"persisted_id\":";
    line += nextPersistentEventId++;
    line += ",\"id\":";
    line += event.id;
    line += ",\"uptime_ms\":";
    line += event.uptimeMs;
    line += ",\"level\":\"";
    appendJsonEscaped(line, event.level);
    line += "\",\"source\":\"";
    appendJsonEscaped(line, event.source);
    line += "\",\"message\":\"";
    appendJsonEscaped(line, event.message);
    line += "\"";
    if (event.hasValue) {
        line += ",\"value\":\"";
        appendJsonEscaped(line, event.value);
        line += "\"";
    }
    line += "}\n";
}

void persistEventIfRelevant(const EventRecord &event)
{
    if (!littleFsAvailable || !isImportantPersistentEvent(event.level, event.source, event.message)) {
        return;
    }

    String line;
    line.reserve(180);
    appendPersistentEventLine(line, event);

    const size_t currentSize = persistentLogSize();
    if (currentSize + line.length() > PERSISTENT_EVENTS_MAX_SIZE) {
        LittleFS.remove(PERSISTENT_EVENTS_PATH);
        persistentLogRotated = true;
    }

    File file = LittleFS.open(PERSISTENT_EVENTS_PATH, "a");
    if (!file) {
        return;
    }
    file.print(line);
    file.close();
}

void appendStorageJson(String &json)
{
    json += "{\"available\":";
    json += littleFsAvailable ? "true" : "false";
    json += ",\"file_size\":";
    json += persistentLogSize();
    json += ",\"max_size\":";
    json += PERSISTENT_EVENTS_MAX_SIZE;
    json += ",\"path\":\"";
    json += PERSISTENT_EVENTS_PATH;
    json += "\",\"policy\":\"WARN ERROR SECURITY e eventos importantes de sistema firewall sensores e energia\"";
    json += ",\"rotated\":";
    json += persistentLogRotated ? "true" : "false";
    json += "}";
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
    FirewallSnapshot snapshot = {true, 0, 0, "n/d", "n/d", 0, FIREWALL_FLOOD_WINDOW_MS, FIREWALL_FLOOD_THRESHOLD, true, 0, 0, 0};
    if (firewallMutex != nullptr && xSemaphoreTake(firewallMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        snapshot = firewallSnapshot;
        xSemaphoreGive(firewallMutex);
    }
    return snapshot;
}

TrafficSnapshot readTrafficSnapshot()
{
    TrafficSnapshot snapshot = {0, 0, 0, 0, 0, "n/d", "n/d", "n/d", {}, 0, 0, 0, IDS_SCAN_WINDOW_MS, IDS_SCAN_404_THRESHOLD, IDS_SCAN_COOLDOWN_MS};
    if (trafficMutex != nullptr && xSemaphoreTake(trafficMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        snapshot = trafficSnapshot;
        xSemaphoreGive(trafficMutex);
    }
    return snapshot;
}

void noteTrafficIdsEvent()
{
    if (trafficMutex != nullptr && xSemaphoreTake(trafficMutex, pdMS_TO_TICKS(20)) == pdTRUE) {
        if (trafficSnapshot.idsEvents < UINT32_MAX) {
            ++trafficSnapshot.idsEvents;
        }
        xSemaphoreGive(trafficMutex);
    }
}

void shortenText(char *target, size_t targetSize, const char *source)
{
    copyText(target, targetSize, source != nullptr && source[0] != '\0' ? source : "n/d");
}

void updateTrafficTopRoutes(TrafficSnapshot &snapshot, const char *route)
{
    size_t emptyIndex = sizeof(snapshot.topRoutes) / sizeof(snapshot.topRoutes[0]);
    for (size_t index = 0; index < sizeof(snapshot.topRoutes) / sizeof(snapshot.topRoutes[0]); ++index) {
        if (snapshot.topRoutes[index].route[0] == '\0') {
            if (emptyIndex == sizeof(snapshot.topRoutes) / sizeof(snapshot.topRoutes[0])) {
                emptyIndex = index;
            }
            continue;
        }
        if (std::strcmp(snapshot.topRoutes[index].route, route) == 0) {
            if (snapshot.topRoutes[index].count < UINT32_MAX) {
                ++snapshot.topRoutes[index].count;
            }
            return;
        }
    }

    if (emptyIndex < sizeof(snapshot.topRoutes) / sizeof(snapshot.topRoutes[0])) {
        copyText(snapshot.topRoutes[emptyIndex].route, sizeof(snapshot.topRoutes[emptyIndex].route), route);
        snapshot.topRoutes[emptyIndex].count = 1;
        return;
    }

    size_t minIndex = 0;
    for (size_t index = 1; index < sizeof(snapshot.topRoutes) / sizeof(snapshot.topRoutes[0]); ++index) {
        if (snapshot.topRoutes[index].count < snapshot.topRoutes[minIndex].count) {
            minIndex = index;
        }
    }
    copyText(snapshot.topRoutes[minIndex].route, sizeof(snapshot.topRoutes[minIndex].route), route);
    snapshot.topRoutes[minIndex].count = 1;
}

bool recordTrafficSample(const char *route, const char *clientIp, const char *userAgent, bool notFound, bool sensitive)
{
    bool shouldLogScan = false;
    const unsigned long now = millis();
    if (trafficMutex != nullptr && xSemaphoreTake(trafficMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        if (trafficSnapshot.totalRequests < UINT32_MAX) {
            ++trafficSnapshot.totalRequests;
        }
        if (notFound && trafficSnapshot.notFoundCount < UINT32_MAX) {
            ++trafficSnapshot.notFoundCount;
        }
        if (sensitive && trafficSnapshot.sensitivePathHits < UINT32_MAX) {
            ++trafficSnapshot.sensitivePathHits;
        }
        copyText(trafficSnapshot.lastIp, sizeof(trafficSnapshot.lastIp), clientIp);
        copyText(trafficSnapshot.lastRoute, sizeof(trafficSnapshot.lastRoute), route);
        shortenText(trafficSnapshot.lastUserAgentShort, sizeof(trafficSnapshot.lastUserAgentShort), userAgent);
        updateTrafficTopRoutes(trafficSnapshot, route);

        if (notFound) {
            if (trafficSnapshot.scanWindowStartMs == 0 || now - trafficSnapshot.scanWindowStartMs > IDS_SCAN_WINDOW_MS) {
                trafficSnapshot.scanWindowStartMs = now;
                trafficSnapshot.scanWindow404Count = 1;
            } else if (trafficSnapshot.scanWindow404Count < UINT16_MAX) {
                ++trafficSnapshot.scanWindow404Count;
            }
            if (trafficSnapshot.scanWindow404Count >= IDS_SCAN_404_THRESHOLD &&
                (trafficSnapshot.lastScanEventMs == 0 || now - trafficSnapshot.lastScanEventMs >= IDS_SCAN_COOLDOWN_MS)) {
                shouldLogScan = true;
                trafficSnapshot.lastScanEventMs = now;
                if (trafficSnapshot.suspiciousScanCount < UINT32_MAX) {
                    ++trafficSnapshot.suspiciousScanCount;
                }
            }
        }
        xSemaphoreGive(trafficMutex);
    }
    return shouldLogScan;
}

void registerTrafficAccess(const char *route, bool notFound = false, bool sensitive = false)
{
    char clientIp[16];
    copyText(clientIp, sizeof(clientIp), server.client().remoteIP().toString().c_str());
    const String userAgent = server.header("User-Agent");
    if (recordTrafficSample(route, clientIp, userAgent.c_str(), notFound, sensitive)) {
        noteTrafficIdsEvent();
        addEvent("SECURITY", "IDS", "Possivel scan HTTP detectado", route);
    }
}

GatewaySnapshot readGatewaySnapshot()
{
    GatewaySnapshot snapshot = {true, "ESP32-Firewall-Lab", "0.0.0.0", false, false, "nao configurado", "0.0.0.0", 0, 0, 0, 0, "AP_ONLY", false, false, "nao configurado", ""};
    if (gatewayMutex != nullptr && xSemaphoreTake(gatewayMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        snapshot = gatewaySnapshot;
        xSemaphoreGive(gatewayMutex);
    }
    return snapshot;
}

NatSnapshot readNatSnapshot()
{
    NatSnapshot snapshot = {NAT_EXPERIMENTAL_ENABLED, false, NAT_EXPERIMENTAL_ENABLED, false, 0, "indisponivel", "", "NAT experimental depende de suporte NAPT no lwIP"};
    if (natMutex != nullptr && xSemaphoreTake(natMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        snapshot = natSnapshot;
        xSemaphoreGive(natMutex);
    }
    return snapshot;
}

bool natCompileTimeSupported()
{
#if IP_NAPT && IP_FORWARD
    return true;
#else
    return false;
#endif
}

void updateNatSnapshot(bool active, unsigned long attemptMs, const char *status, const char *error, const char *note)
{
    if (natMutex != nullptr && xSemaphoreTake(natMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        natSnapshot.experimentalEnabled = NAT_EXPERIMENTAL_ENABLED;
        natSnapshot.supported = natCompileTimeSupported();
        natSnapshot.enabled = NAT_EXPERIMENTAL_ENABLED;
        natSnapshot.active = active;
        if (attemptMs > 0) {
            natSnapshot.lastAttemptMs = attemptMs;
        }
        copyText(natSnapshot.lastStatus, sizeof(natSnapshot.lastStatus), status);
        copyText(natSnapshot.lastError, sizeof(natSnapshot.lastError), error);
        copyText(natSnapshot.note, sizeof(natSnapshot.note), note);
        xSemaphoreGive(natMutex);
    }
}

void setGatewayNatActive(bool active)
{
    if (gatewayMutex != nullptr && xSemaphoreTake(gatewayMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        gatewaySnapshot.natEnabled = active;
        xSemaphoreGive(gatewayMutex);
    }
}

bool natStatusChanged(const NatSnapshot &snapshot, bool active, const char *status, const char *error)
{
    return snapshot.active != active || std::strcmp(snapshot.lastStatus, status) != 0 || std::strcmp(snapshot.lastError, error) != 0;
}

void evaluateNatState(bool logChanges)
{
    const GatewaySnapshot gateway = readGatewaySnapshot();
    const NatSnapshot before = readNatSnapshot();
    const unsigned long now = millis();
    const char *experimentalNote = "NAT experimental; desempenho e estabilidade dependem do core/lwIP e do upstream";

    if (!NAT_EXPERIMENTAL_ENABLED) {
#if IP_NAPT && IP_FORWARD
        if (before.active) {
            ip_napt_enable(static_cast<uint32_t>(WiFi.softAPIP()), 0);
        }
#endif
        updateNatSnapshot(false, now, "desabilitado", "", "Feature flag NAT_EXPERIMENTAL_ENABLED=false");
        setGatewayNatActive(false);
        if (logChanges && natStatusChanged(before, false, "desabilitado", "")) {
            addEvent("INFO", "NAT", "NAT experimental desabilitado", "feature flag");
        }
        return;
    }

    if (!gateway.apEnabled || gateway.apIp[0] == '\0' || std::strcmp(gateway.apIp, "0.0.0.0") == 0) {
        updateNatSnapshot(false, now, "aguardando AP", "AP indisponivel", experimentalNote);
        setGatewayNatActive(false);
        if (logChanges && natStatusChanged(before, false, "aguardando AP", "AP indisponivel")) {
            addEvent("WARN", "NAT", "NAT aguardando AP", "AP indisponivel");
        }
        return;
    }

    if (!gateway.staConnected || std::strcmp(gateway.upstreamIp, "0.0.0.0") == 0) {
#if IP_NAPT && IP_FORWARD
        if (before.active) {
            ip_napt_enable(static_cast<uint32_t>(WiFi.softAPIP()), 0);
        }
#endif
        updateNatSnapshot(false, now, "aguardando upstream", "upstream desconectado", experimentalNote);
        setGatewayNatActive(false);
        if (logChanges && natStatusChanged(before, false, "aguardando upstream", "upstream desconectado")) {
            addEvent("INFO", "NAT", "NAT desativado por falta de upstream", "STA desconectada");
        }
        return;
    }

    if (!natCompileTimeSupported()) {
        updateNatSnapshot(false, now, "nao suportado", "lwIP sem IP_NAPT/IP_FORWARD linkavel", "Core atual nao exporta NAPT; AP e painel seguem operando");
        setGatewayNatActive(false);
        if (logChanges && natStatusChanged(before, false, "nao suportado", "lwIP sem IP_NAPT/IP_FORWARD linkavel")) {
            addEvent("WARN", "NAT", "NAT indisponivel no core atual", "lwIP sem NAPT");
        }
        return;
    }

#if IP_NAPT && IP_FORWARD
    if (logChanges && !before.active) {
        addEvent("INFO", "NAT", "Tentativa de habilitar NAT", gateway.apIp);
    }
    ip_napt_enable(static_cast<uint32_t>(WiFi.softAPIP()), 1);
    updateNatSnapshot(true, now, "ativo", "", experimentalNote);
    setGatewayNatActive(true);
    if (logChanges && natStatusChanged(before, true, "ativo", "")) {
        addEvent("INFO", "NAT", "NAT experimental ativo", gateway.apIp);
    }
#else
    updateNatSnapshot(false, now, "nao suportado", "lwIP sem IP_NAPT/IP_FORWARD linkavel", "Core atual nao exporta NAPT; AP e painel seguem operando");
    setGatewayNatActive(false);
#endif
}

WifiUpstreamConfig readWifiConfig()
{
    WifiUpstreamConfig config = {false, "", "", false};
    if (wifiConfigMutex != nullptr && xSemaphoreTake(wifiConfigMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        config = wifiConfig;
        xSemaphoreGive(wifiConfigMutex);
    }
    return config;
}

bool upstreamWifiConfigured()
{
    const WifiUpstreamConfig config = readWifiConfig();
    return config.saved && config.ssid[0] != '\0';
}

bool upstreamWifiConnectable()
{
    const WifiUpstreamConfig config = readWifiConfig();
    return config.saved && config.ssid[0] != '\0' && config.passphrasePresent;
}

void updateGatewayAttemptStatus(unsigned long attemptMs, const char *status, const char *error)
{
    if (gatewayMutex != nullptr && xSemaphoreTake(gatewayMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        if (attemptMs > 0) {
            gatewaySnapshot.lastConnectAttemptMs = attemptMs;
        }
        copyText(gatewaySnapshot.lastStatus, sizeof(gatewaySnapshot.lastStatus), status);
        copyText(gatewaySnapshot.lastError, sizeof(gatewaySnapshot.lastError), error);
        xSemaphoreGive(gatewayMutex);
    }
}

void resetWifiConfigInMemory()
{
    if (wifiConfigMutex != nullptr && xSemaphoreTake(wifiConfigMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        wifiConfig.saved = false;
        copyText(wifiConfig.ssid, sizeof(wifiConfig.ssid), "");
        copyText(wifiConfig.passphrase, sizeof(wifiConfig.passphrase), "");
        wifiConfig.passphrasePresent = false;
        xSemaphoreGive(wifiConfigMutex);
    }
}

void setWifiConfigInMemory(const char *ssid, const char *passphrase)
{
    if (wifiConfigMutex != nullptr && xSemaphoreTake(wifiConfigMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        wifiConfig.saved = ssid != nullptr && ssid[0] != '\0';
        copyText(wifiConfig.ssid, sizeof(wifiConfig.ssid), ssid != nullptr ? ssid : "");
        copyText(wifiConfig.passphrase, sizeof(wifiConfig.passphrase), passphrase != nullptr ? passphrase : "");
        wifiConfig.passphrasePresent = passphrase != nullptr && passphrase[0] != '\0';
        xSemaphoreGive(wifiConfigMutex);
    }
}

void appendJsonStringValue(String &json, const char *key, const char *value, bool comma)
{
    if (comma) {
        json += ",";
    }
    json += "\"";
    json += key;
    json += "\":\"";
    appendJsonEscaped(json, value);
    json += "\"";
}

bool saveWifiConfigFile(const char *ssid, const char *passphrase)
{
    if (!littleFsAvailable) {
        updateGatewayAttemptStatus(0, "erro", "LittleFS indisponivel");
        addEvent("ERROR", "WIFI", "Falha ao salvar upstream", "LittleFS indisponivel");
        return false;
    }

    File file = LittleFS.open(WIFI_CONFIG_PATH, "w");
    if (!file) {
        updateGatewayAttemptStatus(0, "erro", "falha ao abrir arquivo");
        addEvent("ERROR", "WIFI", "Falha ao salvar upstream", WIFI_CONFIG_PATH);
        return false;
    }

    String json;
    json.reserve(140);
    json += "{";
    appendJsonStringValue(json, "ssid", ssid, false);
    appendJsonStringValue(json, "passphrase", passphrase, true);
    json += "}\n";
    file.print(json);
    file.close();
    setWifiConfigInMemory(ssid, passphrase);
    updateGatewayAttemptStatus(0, "salvo", "");
    addEvent("INFO", "WIFI", "Configuracao upstream salva", ssid);
    return true;
}

void clearWifiConfigFile()
{
    if (littleFsAvailable && LittleFS.exists(WIFI_CONFIG_PATH)) {
        LittleFS.remove(WIFI_CONFIG_PATH);
    }
    resetWifiConfigInMemory();
    WiFi.disconnect(false, false);
    WiFi.mode(WIFI_AP_STA);
    updateGatewayAttemptStatus(0, "limpo", "");
    refreshGatewaySnapshot(false);
    addEvent("WARN", "WIFI", "Configuracao upstream limpa", "AP recovery ativo");
}

bool extractJsonStringValue(const String &json, const char *key, char *target, size_t targetSize)
{
    if (targetSize == 0) {
        return false;
    }
    target[0] = '\0';
    String pattern = "\"";
    pattern += key;
    pattern += "\"";
    int keyIndex = json.indexOf(pattern);
    if (keyIndex < 0) {
        return false;
    }
    int colonIndex = json.indexOf(':', keyIndex + pattern.length());
    if (colonIndex < 0) {
        return false;
    }
    int startIndex = json.indexOf('"', colonIndex + 1);
    if (startIndex < 0) {
        return false;
    }
    ++startIndex;
    size_t outIndex = 0;
    bool escaped = false;
    for (int index = startIndex; index < json.length(); ++index) {
        const char c = json[index];
        if (escaped) {
            if (outIndex + 1 < targetSize) {
                target[outIndex++] = c;
            }
            escaped = false;
            continue;
        }
        if (c == '\\') {
            escaped = true;
            continue;
        }
        if (c == '"') {
            target[outIndex] = '\0';
            return true;
        }
        if (outIndex + 1 < targetSize) {
            target[outIndex++] = c;
        }
    }
    target[outIndex] = '\0';
    return false;
}

bool isValidSsidLength(const String &ssid)
{
    return ssid.length() >= 1 && ssid.length() <= WIFI_SSID_MAX_SIZE;
}

bool isValidPassphraseLength(const String &passphrase)
{
    return passphrase.length() == 0 || (passphrase.length() >= WIFI_PASSPHRASE_MIN_SIZE && passphrase.length() <= WIFI_PASSPHRASE_MAX_SIZE);
}

void loadWifiConfigFile()
{
    resetWifiConfigInMemory();
    updateGatewayAttemptStatus(0, "nao configurado", "");
    if (!littleFsAvailable) {
        updateGatewayAttemptStatus(0, "erro", "LittleFS indisponivel");
        addEvent("WARN", "WIFI", "Configuracao upstream indisponivel", WIFI_CONFIG_PATH);
        return;
    }
    if (!LittleFS.exists(WIFI_CONFIG_PATH)) {
        addEvent("INFO", "WIFI", "Upstream Wi-Fi nao configurado", "AP_ONLY");
        return;
    }

    File file = LittleFS.open(WIFI_CONFIG_PATH, "r");
    if (!file) {
        updateGatewayAttemptStatus(0, "erro", "falha ao ler arquivo");
        addEvent("WARN", "WIFI", "Falha ao ler configuracao upstream", WIFI_CONFIG_PATH);
        return;
    }
    const String json = file.readString();
    file.close();

    char ssid[WIFI_SSID_MAX_SIZE + 1] = "";
    char passphrase[WIFI_PASSPHRASE_MAX_SIZE + 1] = "";
    extractJsonStringValue(json, "ssid", ssid, sizeof(ssid));
    extractJsonStringValue(json, "passphrase", passphrase, sizeof(passphrase));

    const String ssidValue(ssid);
    const String passphraseValue(passphrase);
    if (!isValidSsidLength(ssidValue) || !isValidPassphraseLength(passphraseValue)) {
        resetWifiConfigInMemory();
        updateGatewayAttemptStatus(0, "erro", "configuracao invalida");
        addEvent("WARN", "WIFI", "Configuracao upstream invalida", WIFI_CONFIG_PATH);
        return;
    }

    setWifiConfigInMemory(ssid, passphrase);
    updateGatewayAttemptStatus(0, "carregado", "");
    addEvent("INFO", "WIFI", "Configuracao upstream carregada", ssid);
}

void noteIdsFinding(bool securityEvent, bool sensitivePath)
{
    if (firewallMutex != nullptr && xSemaphoreTake(firewallMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        firewallSnapshot.idsEnabled = true;
        if (securityEvent && firewallSnapshot.idsEvents < UINT32_MAX) {
            ++firewallSnapshot.idsEvents;
        }
        if (sensitivePath && firewallSnapshot.sensitivePathHits < UINT32_MAX) {
            ++firewallSnapshot.sensitivePathHits;
        } else if (!sensitivePath && firewallSnapshot.suspicious404Count < UINT32_MAX) {
            ++firewallSnapshot.suspicious404Count;
        }
        xSemaphoreGive(firewallMutex);
    }
}

void refreshGatewaySnapshot(bool logChanges)
{
    const WifiUpstreamConfig config = readWifiConfig();
    const bool configured = config.saved && config.ssid[0] != '\0';
    const bool connected = configured && WiFi.status() == WL_CONNECTED;
    const uint8_t clients = WiFi.softAPgetStationNum();
    const unsigned long now = millis();
    const bool statusChanged = connected != lastStaConnected;
    const bool clientChanged = clients != lastGatewayClientCount;

    if (gatewayMutex != nullptr && xSemaphoreTake(gatewayMutex, pdMS_TO_TICKS(50)) == pdTRUE) {
        gatewaySnapshot.apEnabled = true;
        copyText(gatewaySnapshot.apSsid, sizeof(gatewaySnapshot.apSsid), AP_SSID);
        copyText(gatewaySnapshot.apIp, sizeof(gatewaySnapshot.apIp), WiFi.softAPIP().toString().c_str());
        gatewaySnapshot.staConfigured = configured;
        gatewaySnapshot.staConnected = connected;
        gatewaySnapshot.passphrasePresent = config.passphrasePresent;
        copyText(gatewaySnapshot.upstreamSsid, sizeof(gatewaySnapshot.upstreamSsid), configured ? config.ssid : "nao configurado");
        copyText(gatewaySnapshot.upstreamIp, sizeof(gatewaySnapshot.upstreamIp), connected ? WiFi.localIP().toString().c_str() : "0.0.0.0");
        gatewaySnapshot.upstreamRssi = connected ? WiFi.RSSI() : 0;
        gatewaySnapshot.clientCount = clients;
        copyText(gatewaySnapshot.mode, sizeof(gatewaySnapshot.mode), configured ? "AP_STA" : "AP_ONLY");
        gatewaySnapshot.natEnabled = false;
        if (connected) {
            copyText(gatewaySnapshot.lastStatus, sizeof(gatewaySnapshot.lastStatus), "conectado");
            copyText(gatewaySnapshot.lastError, sizeof(gatewaySnapshot.lastError), "");
        } else if (configured && gatewaySnapshot.lastStatus[0] == '\0') {
            copyText(gatewaySnapshot.lastStatus, sizeof(gatewaySnapshot.lastStatus), "desconectado");
        } else if (!configured) {
            copyText(gatewaySnapshot.lastStatus, sizeof(gatewaySnapshot.lastStatus), "nao configurado");
            copyText(gatewaySnapshot.lastError, sizeof(gatewaySnapshot.lastError), "");
        }
        if (statusChanged || gatewaySnapshot.lastStatusChangeMs == 0) {
            gatewaySnapshot.lastStatusChangeMs = now;
        }
        xSemaphoreGive(gatewayMutex);
    }

    if (logChanges && configured && statusChanged) {
        addEvent(connected ? "INFO" : "WARN", "WIFI", connected ? "Upstream Wi-Fi conectado" : "Upstream Wi-Fi desconectado", connected ? WiFi.localIP().toString().c_str() : config.ssid);
    }
    if (logChanges && clientChanged && lastGatewayClientCount != 255) {
        char value[EVENT_VALUE_SIZE];
        std::snprintf(value, sizeof(value), "%u clientes", clients);
        addEvent("INFO", "WIFI", "Clientes conectados ao AP", value);
    }

    lastStaConnected = connected;
    lastGatewayClientCount = clients;
    evaluateNatState(logChanges);
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

    EventRecord persistedEvent = event;
    xSemaphoreGive(eventsMutex);
    persistEventIfRelevant(persistedEvent);
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
    if (std::strcmp(module.name, "Logs persistentes") == 0) {
        return littleFsAvailable ? "ativo" : "indisponivel";
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

const char *const SENSITIVE_PATHS[] = {
    "/admin",
    "/login",
    "/wp-admin",
    "/xmlrpc.php",
    "/etc/passwd",
    "/.env",
    "/config",
    "/phpmyadmin",
};

bool isSensitivePath(const char *route)
{
    for (size_t index = 0; index < sizeof(SENSITIVE_PATHS) / sizeof(SENSITIVE_PATHS[0]); ++index) {
        if (std::strstr(route, SENSITIVE_PATHS[index]) != nullptr) {
            return true;
        }
    }
    return false;
}

void addIdsDemoEvent(const char *message, const char *value = nullptr)
{
    noteIdsFinding(true, true);
    noteTrafficIdsEvent();
    addEvent("SECURITY", "IDS", message, value);
}

void registerIdsNotFound(const char *route)
{
    const bool sensitive = isSensitivePath(route);
    const unsigned long now = millis();
    bool shouldLog = false;
    const char *level = sensitive ? "SECURITY" : "WARN";
    const char *message = sensitive ? "Tentativa de acesso a rota sensivel" : "Rota inexistente acessada";

    if (sensitive) {
        if (lastIdsSecurityEventMs == 0 || now - lastIdsSecurityEventMs >= IDS_EVENT_COOLDOWN_MS) {
            shouldLog = true;
            lastIdsSecurityEventMs = now;
        }
    } else if (lastIds404EventMs == 0 || now - lastIds404EventMs >= IDS_404_EVENT_COOLDOWN_MS) {
        shouldLog = true;
        lastIds404EventMs = now;
    }

    noteIdsFinding(sensitive, sensitive);
    if (shouldLog) {
        if (std::strcmp(level, "SECURITY") == 0) {
            noteTrafficIdsEvent();
        }
        addEvent(level, "IDS", message, route);
    }
}

void registerHttpAccess(const char *route, bool logAccessEvent = true, bool trackTraffic = true)
{
    if (trackTraffic) {
        registerTrafficAccess(route);
    }
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
    refreshGatewaySnapshot(true);

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

void appendTrafficJsonObject(String &json, const TrafficSnapshot &traffic)
{
    json += "{\"total_requests\":";
    json += traffic.totalRequests;
    json += ",\"not_found_count\":";
    json += traffic.notFoundCount;
    json += ",\"sensitive_path_hits\":";
    json += traffic.sensitivePathHits;
    json += ",\"suspicious_scan_count\":";
    json += traffic.suspiciousScanCount;
    json += ",\"ids_events\":";
    json += traffic.idsEvents;
    json += ",\"last_ip\":\"";
    appendJsonEscaped(json, traffic.lastIp);
    json += "\",\"last_route\":\"";
    appendJsonEscaped(json, traffic.lastRoute);
    json += "\",\"last_user_agent_short\":\"";
    appendJsonEscaped(json, traffic.lastUserAgentShort);
    json += "\",\"window_ms\":";
    json += traffic.scanWindowMs;
    json += ",\"scan_window_ms\":";
    json += traffic.scanWindowMs;
    json += ",\"scan_window_404_count\":";
    json += traffic.scanWindow404Count;
    json += ",\"scan_threshold\":";
    json += traffic.scanThreshold;
    json += ",\"scan_cooldown_ms\":";
    json += traffic.scanCooldownMs;
    json += ",\"last_scan_event_ms\":";
    json += traffic.lastScanEventMs;
    json += ",\"top_route\":\"";
    if (traffic.topRoutes[0].route[0] != '\0') {
        appendJsonEscaped(json, traffic.topRoutes[0].route);
    } else {
        appendJsonEscaped(json, "n/d");
    }
    json += "\",\"top_routes\":[";
    bool first = true;
    for (size_t index = 0; index < sizeof(traffic.topRoutes) / sizeof(traffic.topRoutes[0]); ++index) {
        if (traffic.topRoutes[index].route[0] == '\0') {
            continue;
        }
        if (!first) {
            json += ",";
        }
        json += "{\"route\":\"";
        appendJsonEscaped(json, traffic.topRoutes[index].route);
        json += "\",\"count\":";
        json += traffic.topRoutes[index].count;
        json += "}";
        first = false;
    }
    json += "]}";
}

String buildTrafficJson()
{
    String json;
    json.reserve(900);
    appendTrafficJsonObject(json, readTrafficSnapshot());
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
    css += F("table{width:100%;border-collapse:collapse;margin-top:8px;background:#fff}th,td{border:1px solid var(--line);padding:7px 8px;text-align:left;vertical-align:top}th{background:#f1f5f9;color:#445160;font-size:12px;font-weight:700}td{font-size:14px}.table-wrap{overflow-x:auto}.cols{display:grid;grid-template-columns:1fr 1fr;gap:14px}code{background:#eef2f6;border:1px solid var(--line);padding:2px 4px;border-radius:3px}label{display:block;font-size:13px;font-weight:700;color:var(--muted);margin:0 0 5px}input{width:100%;border:1px solid var(--line);border-radius:4px;padding:9px;font:inherit;background:#fff}.actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}form.inline{display:inline}");
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

void appendRecentEventsSummaryJson(String &json)
{
    json += "{\"count\":";
    if (eventsMutex == nullptr || xSemaphoreTake(eventsMutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        json += "0,\"capacity\":";
        json += EVENT_CAPACITY;
        json += ",\"recent\":[]}";
        return;
    }

    json += eventCount;
    json += ",\"capacity\":";
    json += EVENT_CAPACITY;
    json += ",\"recent\":[";
    const size_t rows = eventCount < 5 ? eventCount : 5;
    for (size_t offset = 0; offset < rows; ++offset) {
        if (offset > 0) {
            json += ",";
        }
        const size_t newestOffset = eventCount - 1 - offset;
        const size_t index = (eventStart + newestOffset) % EVENT_CAPACITY;
        appendEventJsonObject(json, events[index]);
    }
    json += "]}";
    xSemaphoreGive(eventsMutex);
}

String buildReportJson()
{
    const MetricsSnapshot metrics = readMetricsSnapshot();
    const FirewallSnapshot firewall = readFirewallSnapshot();
    const GatewaySnapshot gateway = readGatewaySnapshot();
    const NatSnapshot nat = readNatSnapshot();
    const TrafficSnapshot traffic = readTrafficSnapshot();
    String json;
    json.reserve(2400);
    json += "{\"project\":\"";
    appendJsonEscaped(json, PROJECT_NAME);
    json += "\",\"version\":\"";
    appendJsonEscaped(json, PROJECT_VERSION);
    json += "\",\"uptime_ms\":";
    json += millis();
    json += ",\"system\":{\"free_heap\":";
    json += metrics.freeHeap;
    json += ",\"min_free_heap\":";
    json += metrics.minFreeHeap;
    json += ",\"flash_size\":";
    json += metrics.flashSize;
    json += ",\"sketch_size\":";
    json += metrics.sketchSize;
    json += ",\"ap_ssid\":\"";
    appendJsonEscaped(json, metrics.apSsid);
    json += "\",\"ap_ip\":\"";
    appendJsonEscaped(json, metrics.apIp);
    json += "\"}";
    json += ",\"gateway\":";
    appendGatewayJson(json);
    json += ",\"nat\":";
    appendNatJson(json);
    json += ",\"firewall\":{\"enabled\":";
    json += firewall.enabled ? "true" : "false";
    json += ",\"total_requests\":";
    json += firewall.totalRequests;
    json += ",\"security_events\":";
    json += firewall.securityEvents;
    json += ",\"last_client_ip\":\"";
    appendJsonEscaped(json, firewall.lastClientIp);
    json += "\",\"last_route\":\"";
    appendJsonEscaped(json, firewall.lastRoute);
    json += "\"}";
    json += ",\"ids\":{\"enabled\":";
    json += firewall.idsEnabled ? "true" : "false";
    json += ",\"events\":";
    json += firewall.idsEvents;
    json += ",\"suspicious_404_count\":";
    json += firewall.suspicious404Count;
    json += ",\"sensitive_path_hits\":";
    json += firewall.sensitivePathHits;
    json += "}";
    json += ",\"traffic\":";
    appendTrafficJsonObject(json, traffic);
    json += ",\"storage\":";
    appendStorageJson(json);
    json += ",\"recent_events_summary\":";
    appendRecentEventsSummaryJson(json);
    json += ",\"limitations\":[";
    json += "\"Monitoramento HTTP didatico limitado ao painel embarcado\",";
    json += "\"Nao faz sniffing de pacotes nem inspecao HTTPS\",";
    json += "\"Nao substitui firewall ou IDS profissional\",";
    json += "\"PoC de NAT real fica em branch experimental ESP-IDF separada\"";
    json += "]}";
    return json;
}

String reportPage()
{
    const MetricsSnapshot metrics = readMetricsSnapshot();
    const FirewallSnapshot firewall = readFirewallSnapshot();
    const GatewaySnapshot gateway = readGatewaySnapshot();
    const NatSnapshot nat = readNatSnapshot();
    const TrafficSnapshot traffic = readTrafficSnapshot();
    const size_t events = readEventCount();
    const size_t logSize = persistentLogSize();
    const char *topRoute = traffic.topRoutes[0].route[0] != '\0' ? traffic.topRoutes[0].route : "n/d";

    String html;
    html.reserve(9800);
    appendPageHead(html, "Relatorio de evidencia - ESP32 Mini Firewall Gateway");
    appendHeader(html, "Relatorio de evidencia", "Este relatorio resume o estado atual do prototipo.");
    html += F("<main><div class=\"toolbar\"><a class=\"btn primary\" href=\"/\">Dashboard</a><a class=\"btn\" href=\"/evidencias\">Evidencias</a><a class=\"btn\" href=\"/traffic\">Traffic</a><a class=\"btn\" href=\"/logs\">Logs</a><a class=\"btn\" href=\"/api/report\">/api/report</a></div>");
    html += F("<div class=\"panel\"><h2>Identificacao do projeto</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Projeto</strong><span>");
    appendHtmlEscaped(html, PROJECT_NAME);
    html += F("</span></div><div class=\"metric\"><strong>Firmware</strong><span>");
    appendHtmlEscaped(html, PROJECT_VERSION);
    html += F("</span></div><div class=\"metric\"><strong>Fase</strong><span>");
    appendHtmlEscaped(html, PROJECT_PHASE);
    html += F("</span></div></div><p class=\"note\">Relatorio tecnico embarcado para apresentacao, auditoria simples e documentacao final.</p></div>");

    html += F("<div class=\"panel\"><h2>Status geral</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Uptime</strong><span>");
    html += metrics.uptimeSeconds;
    html += F("s</span></div><div class=\"metric\"><strong>Heap livre</strong><span>");
    html += metrics.freeHeap;
    html += F(" bytes</span></div><div class=\"metric\"><strong>Eventos RAM</strong><span>");
    html += events;
    html += F("/");
    html += EVENT_CAPACITY;
    html += F("</span></div><div class=\"metric\"><strong>Eventos SECURITY</strong><span>");
    html += firewall.securityEvents;
    html += F("</span></div></div></div>");

    html += F("<div class=\"panel\"><h2>Rede e gateway</h2><div class=\"grid summary\"><div class=\"metric\"><strong>AP SSID</strong><span>");
    appendHtmlEscaped(html, gateway.apSsid);
    html += F("</span></div><div class=\"metric\"><strong>AP IP</strong><span>");
    appendHtmlEscaped(html, gateway.apIp);
    html += F("</span></div><div class=\"metric\"><strong>Clientes conectados</strong><span>");
    html += gateway.clientCount;
    html += F("</span></div><div class=\"metric\"><strong>Upstream</strong><span>");
    html += gateway.staConfigured ? (gateway.staConnected ? "conectado" : "configurado/desconectado") : "nao configurado";
    html += F("</span></div><div class=\"metric\"><strong>IP upstream</strong><span>");
    appendHtmlEscaped(html, gateway.staConnected ? gateway.upstreamIp : "n/d");
    html += F("</span></div><div class=\"metric\"><strong>NAT status</strong><span>");
    appendHtmlEscaped(html, nat.lastStatus);
    html += F("</span></div></div><p class=\"note\">A PoC de NAT real fica em branch experimental ESP-IDF. Na main, NAT e experimental com fallback e telemetria clara.</p></div>");

    html += F("<div class=\"panel\"><h2>Firewall/IDS didatico</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Requests firewall</strong><span>");
    html += firewall.totalRequests;
    html += F("</span></div><div class=\"metric\"><strong>Eventos IDS</strong><span>");
    html += firewall.idsEvents;
    html += F("</span></div><div class=\"metric\"><strong>404 suspeitos</strong><span>");
    html += firewall.suspicious404Count;
    html += F("</span></div><div class=\"metric\"><strong>Rotas sensiveis</strong><span>");
    html += firewall.sensitivePathHits;
    html += F("</span></div></div><p class=\"note\">Este prototipo nao substitui firewall/IDS profissional.</p></div>");

    html += F("<div class=\"panel\"><h2>Traffic Monitor</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Total HTTP</strong><span>");
    html += traffic.totalRequests;
    html += F("</span></div><div class=\"metric\"><strong>404 count</strong><span>");
    html += traffic.notFoundCount;
    html += F("</span></div><div class=\"metric\"><strong>Rotas sensiveis</strong><span>");
    html += traffic.sensitivePathHits;
    html += F("</span></div><div class=\"metric\"><strong>Scans suspeitos</strong><span>");
    html += traffic.suspiciousScanCount;
    html += F("</span></div><div class=\"metric\"><strong>Ultima rota</strong><span>");
    appendHtmlEscaped(html, traffic.lastRoute);
    html += F("</span></div><div class=\"metric\"><strong>Ultimo IP</strong><span>");
    appendHtmlEscaped(html, traffic.lastIp);
    html += F("</span></div><div class=\"metric\"><strong>Top rota</strong><span>");
    appendHtmlEscaped(html, topRoute);
    html += F("</span></div></div><p class=\"note\">O monitoramento HTTP e didatico e limitado ao painel embarcado.</p></div>");

    html += F("<div class=\"panel\"><h2>Logs e persistencia</h2><div class=\"grid summary\"><div class=\"metric\"><strong>LittleFS</strong><span>");
    html += littleFsAvailable ? "ativo" : "indisponivel";
    html += F("</span></div><div class=\"metric\"><strong>Arquivo persistente</strong><span>");
    html += logSize;
    html += F(" bytes</span></div><div class=\"metric\"><strong>Limite</strong><span>");
    html += PERSISTENT_EVENTS_MAX_SIZE;
    html += F(" bytes</span></div></div><p class=\"note\">Persistencia seletiva para WARN, ERROR, SECURITY e eventos importantes.</p></div>");

    html += F("<div class=\"panel\"><h2>Eventos recentes</h2><div class=\"table-wrap\">");
    appendEventsTableHtml(html, 8);
    html += F("</div></div>");
    html += F("<div class=\"panel\"><h2>Limitacoes tecnicas</h2><ul><li>Monitoramento HTTP didatico limitado ao painel embarcado.</li><li>Nao faz sniffing de pacotes nem inspecao HTTPS.</li><li>Este prototipo nao substitui firewall/IDS profissional.</li><li>A PoC de NAT real fica em branch experimental ESP-IDF separada.</li></ul></div>");
    html += F("<div class=\"panel\"><h2>Como validar</h2><ul><li>Abrir <code>/api/report</code> e conferir o resumo JSON.</li><li>Executar <code>python3 tools/smoke_test_http.py --base-url http://192.168.4.1</code> quando conectado ao AP.</li><li>Gerar <code>/demo/scan</code> e verificar eventos SECURITY/IDS em <code>/logs</code>.</li><li>Comparar <code>/report</code>, <code>/api/status</code> e <code>/api/traffic</code>.</li></ul></div>");
    html += F("</main></body></html>");
    return html;
}

String evidencePage()
{
    const MetricsSnapshot snapshot = readMetricsSnapshot();
    const size_t count = readEventCount();
    String html;
    html.reserve(7600);
    appendPageHead(html, "Evidencia de execucao - ESP32 Mini Firewall Gateway");
    appendHeader(html, "Evidencia de execucao", "Resumo tecnico para print do firmware em execucao no ESP32.");
    html += F("<main><div class=\"toolbar\"><a class=\"btn primary\" href=\"/\">Dashboard</a><a class=\"btn\" href=\"/logs\">Logs</a><a class=\"btn\" href=\"/report\">Relatorio</a><a class=\"btn\" href=\"/api/status\">/api/status</a><a class=\"btn\" href=\"/api/events\">/api/events</a></div>");
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
    html += F("<div class=\"panel\"><h2>Persistencia de logs</h2><div class=\"grid summary\"><div class=\"metric\"><strong>LittleFS</strong><span><span class=\"badge ");
    html += littleFsAvailable ? "ok" : "planned";
    html += F("\">");
    html += littleFsAvailable ? "ativo" : "indisponivel";
    html += F("</span></span></div><div class=\"metric\"><strong>Arquivo</strong><span>");
    html += persistentLogSize();
    html += F(" bytes</span></div><div class=\"metric\"><strong>Limite</strong><span>");
    html += PERSISTENT_EVENTS_MAX_SIZE;
    html += F(" bytes</span></div><div class=\"metric\"><strong>Politica</strong><span>eventos relevantes</span></div></div><p class=\"note\">Persistem WARN, ERROR, SECURITY e eventos importantes de sistema, firewall, sensores e energia. Acessos comuns de API nao sao gravados em flash.</p><p class=\"note\"><a href=\"/api/events/persistent\">Abrir JSON persistente</a></p></div>");
    const FirewallSnapshot firewall = readFirewallSnapshot();
    const GatewaySnapshot gateway = readGatewaySnapshot();
    html += F("<div class=\"panel\"><h2>Seguranca de rede</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Firewall didatico</strong><span><span class=\"badge ok\">ativo</span></span></div><div class=\"metric\"><strong>Requisicoes HTTP</strong><span>");
    html += firewall.totalRequests;
    html += F("</span></div><div class=\"metric\"><strong>Eventos SECURITY</strong><span>");
    html += firewall.securityEvents;
    html += F("</span></div><div class=\"metric\"><strong>Ultima rota</strong><span>");
    html += firewall.lastRoute;
    html += F("</span></div></div><p class=\"note\">Deteccao didatica baseada em acessos HTTP ao painel; nao substitui firewall profissional.</p></div>");
    html += F("<div class=\"panel\"><h2>Wi-Fi upstream</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Configurado</strong><span>");
    html += gateway.staConfigured ? "sim" : "nao";
    html += F("</span></div><div class=\"metric\"><strong>Conectado</strong><span>");
    html += gateway.staConnected ? "sim" : "nao";
    html += F("</span></div><div class=\"metric\"><strong>IP upstream</strong><span>");
    html += gateway.staConnected ? gateway.upstreamIp : "n/d";
    html += F("</span></div><div class=\"metric\"><strong>RSSI</strong><span>");
    html += gateway.staConnected ? String(gateway.upstreamRssi) + " dBm" : "n/d";
    html += F("</span></div></div><p class=\"note\">A passphrase do upstream nunca e exibida nesta pagina, nas APIs ou nos logs.</p></div>");
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
    html += F("<main><div class=\"toolbar\"><a class=\"btn primary\" href=\"/\">Dashboard</a><a class=\"btn\" href=\"/gateway\">Gateway</a><a class=\"btn\" href=\"/evidencias\">Evidencias</a><a class=\"btn\" href=\"/report\">Relatorio</a><a class=\"btn\" href=\"/api/events\">JSON</a><a class=\"btn\" href=\"/demo/info\">Gerar INFO</a><a class=\"btn warn\" href=\"/demo/warn\">Gerar WARN</a><a class=\"btn security\" href=\"/demo/security\">Gerar SECURITY</a><a class=\"btn security\" href=\"/demo/flood\">Gerar flood</a><a class=\"btn security\" href=\"/demo/ids\">Gerar IDS</a></div>");
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

String trafficPage()
{
    const TrafficSnapshot traffic = readTrafficSnapshot();
    String html;
    html.reserve(6200);
    appendPageHead(html, "Traffic Monitor - ESP32 Mini Firewall Gateway");
    appendHeader(html, "Traffic Monitor HTTP", "Monitoramento didatico do trafego HTTP recebido pelo painel embarcado.");
    html += F("<main><div class=\"toolbar\"><a class=\"btn primary\" href=\"/\">Dashboard</a><a class=\"btn\" href=\"/logs\">Logs</a><a class=\"btn\" href=\"/gateway\">Gateway</a><a class=\"btn\" href=\"/report\">Relatorio</a><a class=\"btn\" href=\"/api/traffic\">/api/traffic</a><a class=\"btn security\" href=\"/demo/scan\">Simular scan</a></div>");
    html += F("<div class=\"panel\"><h2>Resumo de trafego</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Total requests</strong><span>");
    html += traffic.totalRequests;
    html += F("</span></div><div class=\"metric\"><strong>404 suspeitos</strong><span>");
    html += traffic.notFoundCount;
    html += F("</span></div><div class=\"metric\"><strong>Rotas sensiveis</strong><span>");
    html += traffic.sensitivePathHits;
    html += F("</span></div><div class=\"metric\"><strong>Scans detectados</strong><span>");
    html += traffic.suspiciousScanCount;
    html += F("</span></div><div class=\"metric\"><strong>Eventos IDS</strong><span>");
    html += traffic.idsEvents;
    html += F("</span></div><div class=\"metric\"><strong>Janela IDS</strong><span>");
    html += traffic.scanWindow404Count;
    html += F("/");
    html += traffic.scanThreshold;
    html += F(" 404</span></div></div>");
    if (traffic.suspiciousScanCount > 0) {
        html += F("<p class=\"note\"><span class=\"badge security\">alerta</span> Scan HTTP didatico ja foi detectado nesta execucao.</p>");
    } else {
        html += F("<p class=\"note\">Nenhum scan didatico detectado nesta execucao.</p>");
    }
    html += F("</div>");
    html += F("<div class=\"panel\"><h2>Ultimo acesso</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Ultimo IP</strong><span>");
    appendHtmlEscaped(html, traffic.lastIp);
    html += F("</span></div><div class=\"metric\"><strong>Ultima rota</strong><span>");
    appendHtmlEscaped(html, traffic.lastRoute);
    html += F("</span></div><div class=\"metric\"><strong>User-Agent resumido</strong><span>");
    appendHtmlEscaped(html, traffic.lastUserAgentShort);
    html += F("</span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Top rotas acessadas</h2><div class=\"table-wrap\"><table><thead><tr><th>Rota</th><th>Requests</th></tr></thead><tbody>");
    bool hasRoutes = false;
    for (size_t index = 0; index < sizeof(traffic.topRoutes) / sizeof(traffic.topRoutes[0]); ++index) {
        if (traffic.topRoutes[index].route[0] == '\0') {
            continue;
        }
        hasRoutes = true;
        html += F("<tr><td>");
        appendHtmlEscaped(html, traffic.topRoutes[index].route);
        html += F("</td><td>");
        html += traffic.topRoutes[index].count;
        html += F("</td></tr>");
    }
    if (!hasRoutes) {
        html += F("<tr><td colspan=\"2\">n/d</td></tr>");
    }
    html += F("</tbody></table></div></div>");
    html += F("<div class=\"panel tight\"><h2>Escopo</h2><p class=\"note\">Monitoramento didatico baseado no trafego HTTP do painel embarcado. Nao faz sniffing de pacotes, nao inspeciona HTTPS e nao substitui IDS/IPS profissional.</p></div>");
    html += F("</main></body></html>");
    return html;
}

String htmlPage()
{
    String html;
    html.reserve(9200);
    appendPageHead(html, "ESP32 Mini Firewall Gateway");
    appendHeader(html, PROJECT_NAME, "Mini IDS portatil, Mini Firewall Gateway e monitor ciberfisico em ESP32 para laboratorio didatico de seguranca.");
    html += F("<main><div class=\"toplinks\"><a class=\"linkbtn primary\" href=\"/evidencias\">Evidencias</a><a class=\"linkbtn\" href=\"/gateway\">Gateway</a><a class=\"linkbtn\" href=\"/wifi\">Wi-Fi</a><a class=\"linkbtn\" href=\"/logs\">Logs</a><a class=\"linkbtn\" href=\"/report\">Relatorio</a><a class=\"linkbtn\" href=\"/api/status\">API status</a><a class=\"linkbtn\" href=\"/api/events\">API eventos</a></div>");
    html += F("<div class=\"panel\"><h2>Resumo</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Status</strong><span id=\"status\">n/d</span></div><div class=\"metric\"><strong>IP AP</strong><span id=\"apIp\">n/d</span></div><div class=\"metric\"><strong>Uptime</strong><span id=\"uptime\">n/d</span></div><div class=\"metric\"><strong>Eventos</strong><span id=\"eventCount\">n/d</span></div></div></div>");
    html += F("<div class=\"panel tight\"><h2>Traffic Monitor HTTP</h2><p class=\"note\"><a href=\"/traffic\">Abrir /traffic</a> para ver total de requests, top rotas, 404 suspeitos, rotas sensiveis e eventos IDS. Monitoramento didatico do HTTP do painel, sem sniffing de HTTPS.</p></div>");
    html += F("<div class=\"panel\"><h2>Firewall didatico</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Status</strong><span id=\"fwStatus\">n/d</span></div><div class=\"metric\"><strong>Requisicoes HTTP</strong><span id=\"fwRequests\">n/d</span></div><div class=\"metric\"><strong>Eventos SECURITY</strong><span id=\"fwSecurity\">n/d</span></div><div class=\"metric\"><strong>Eventos IDS</strong><span id=\"idsEvents\">n/d</span></div><div class=\"metric\"><strong>Ultima rota</strong><span id=\"fwRoute\">n/d</span></div><div class=\"metric\"><strong>Ultimo IP</strong><span id=\"fwIp\">n/d</span></div><div class=\"metric\"><strong>Regra de flood</strong><span id=\"fwRule\">n/d</span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Gateway</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Modo</strong><span id=\"gwMode\">n/d</span></div><div class=\"metric\"><strong>Upstream</strong><span id=\"gwUpstream\">n/d</span></div><div class=\"metric\"><strong>Config upstream</strong><span id=\"gwConfigured\">n/d</span></div><div class=\"metric\"><strong>AP IP</strong><span id=\"gwApIp\">n/d</span></div><div class=\"metric\"><strong>IP upstream</strong><span id=\"gwUpIp\">n/d</span></div><div class=\"metric\"><strong>RSSI</strong><span id=\"gwRssi\">n/d</span></div><div class=\"metric\"><strong>Clientes AP</strong><span id=\"gwClients\">n/d</span></div><div class=\"metric\"><strong>Configurar</strong><span><a href=\"/wifi\">/wifi</a></span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Metricas do sistema</h2><div class=\"grid\"><div class=\"metric\"><strong>Heap livre</strong><span id=\"freeHeap\">n/d</span></div><div class=\"metric\"><strong>Heap minimo</strong><span id=\"minFreeHeap\">n/d</span></div><div class=\"metric\"><strong>Flash</strong><span id=\"flashSize\">n/d</span></div><div class=\"metric\"><strong>Sketch</strong><span id=\"sketchSize\">n/d</span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Energia</h2><div class=\"grid\"><div class=\"metric\"><strong>INA219</strong><span id=\"energyStatus\">n/d</span></div><div class=\"metric\"><strong>Tensao</strong><span id=\"energyVoltage\">n/d</span></div><div class=\"metric\"><strong>Corrente</strong><span id=\"energyCurrent\">n/d</span></div><div class=\"metric\"><strong>Potencia</strong><span id=\"energyPower\">n/d</span></div><div class=\"metric\"><strong>Ultimo update</strong><span id=\"energyUpdated\">n/d</span></div><div class=\"metric\"><strong>Alertas</strong><span id=\"energyAlert\">n/d</span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Modulos</h2><div class=\"table-wrap\"><table><thead><tr><th>Modulo</th><th>Status</th></tr></thead><tbody id=\"modulesTable\"><tr><td colspan=\"2\">n/d</td></tr></tbody></table></div></div>");
    html += F("<div class=\"cols\"><div class=\"panel\"><h2>Tasks FreeRTOS</h2><div class=\"table-wrap\"><table><thead><tr><th>Nome</th><th>Core</th><th>Status</th><th>Stack</th></tr></thead><tbody id=\"tasksTable\"><tr><td colspan=\"4\">n/d</td></tr></tbody></table></div></div>");
    html += F("<div class=\"panel\"><h2>Tempos de execucao</h2><div class=\"table-wrap\"><table><thead><tr><th>Funcao</th><th>Ultima medicao</th><th>Status</th></tr></thead><tbody id=\"timingsTable\"><tr><td colspan=\"3\">n/d</td></tr></tbody></table></div></div></div>");
    html += F("<div class=\"panel tight\"><h2>Registro de eventos</h2><p class=\"note\"><a href=\"/logs\">Abrir pagina de logs</a>. Eventos demo: <a href=\"/demo/info\">INFO</a>, <a href=\"/demo/warn\">WARN</a>, <a href=\"/demo/security\">SECURITY</a>, <a href=\"/demo/flood\">flood</a>, <a href=\"/demo/ids\">IDS</a>.</p></div>");
    html += F("<script>function nz(v){return v===undefined||v===null?'n/d':v}function formatBytes(v){return typeof v==='number'&&v>0?v+' bytes':'n/d'}function fixed(v,d,u){return typeof v==='number'?v.toFixed(d)+' '+u:'n/d'}function badge(s){return '<span class=\"badge '+(s==='ativo'||s==='ativa'||s==='ok'||s==='detectado'||s==='normal'?'ok':'planned')+'\">'+s+'</span>'}function renderModules(items){const b=document.getElementById('modulesTable');b.innerHTML='';if(!Array.isArray(items)||!items.length){b.innerHTML='<tr><td colspan=\"2\">n/d</td></tr>';return}items.forEach(m=>{const r=document.createElement('tr');r.innerHTML='<td>'+m.name+'</td><td>'+badge(m.status)+'</td>';b.appendChild(r)})}function renderTasks(items){const b=document.getElementById('tasksTable');b.innerHTML='';if(!Array.isArray(items)||!items.length){b.innerHTML='<tr><td colspan=\"4\">n/d</td></tr>';return}items.forEach(t=>{const r=document.createElement('tr');r.innerHTML='<td>'+t.name+'</td><td>'+t.core+'</td><td>'+badge(t.status)+'</td><td>'+t.stackHighWatermark+'</td>';b.appendChild(r)})}function renderTimings(items){const b=document.getElementById('timingsTable');b.innerHTML='';if(!Array.isArray(items)||!items.length){b.innerHTML='<tr><td colspan=\"3\">n/d</td></tr>';return}items.forEach(t=>{const r=document.createElement('tr');r.innerHTML='<td>'+t.name+'</td><td>'+(t.measured?t.lastMicros+' us':'n/d')+'</td><td>'+badge(t.measured?'medida':'pendente')+'</td>';b.appendChild(r)})}function renderFirewall(f){f=f||{};document.getElementById('fwStatus').innerHTML=badge(f.enabled?'ativo':'indisponivel');document.getElementById('fwRequests').textContent=nz(f.total_requests);document.getElementById('fwSecurity').textContent=nz(f.security_events);document.getElementById('idsEvents').textContent=nz(f.ids_events);document.getElementById('fwRoute').textContent=f.last_route||'n/d';document.getElementById('fwIp').textContent=f.last_client_ip||'n/d';document.getElementById('fwRule').textContent=nz(f.flood_threshold)+' req / '+nz(f.flood_window_ms)+' ms'}function renderStorage(s){const el=document.getElementById('storageStatus');if(!el)return;s=s||{};el.innerHTML=badge(s.available?'ativo':'indisponivel');document.getElementById('storageSize').textContent=formatBytes(s.file_size);document.getElementById('storageMax').textContent=formatBytes(s.max_size);document.getElementById('storagePolicy').textContent=s.policy||'n/d'}function renderGateway(g){g=g||{};document.getElementById('gwMode').textContent=g.mode||'n/d';document.getElementById('gwUpstream').innerHTML=badge(g.sta_connected?'conectado':(g.sta_configured?'desconectado':'nao configurado'));document.getElementById('gwConfigured').textContent=g.sta_configured?'sim':'nao';document.getElementById('gwApIp').textContent=g.ap_ip||'n/d';document.getElementById('gwUpIp').textContent=g.sta_connected?(g.upstream_ip||'n/d'):'n/d';document.getElementById('gwRssi').textContent=g.sta_connected?nz(g.upstream_rssi)+' dBm':'n/d';document.getElementById('gwClients').textContent=nz(g.client_count);const n=document.getElementById('gwNat');if(n)n.innerHTML=badge(g.nat_active?'ativo':(g.nat_enabled?'fallback':'inativo'))}function renderTraffic(t){t=t||{};const set=(id,v)=>{const e=document.getElementById(id);if(e)e.textContent=v};set('trTotal',nz(t.total_requests));set('tr404',nz(t.not_found_count));set('trSensitive',nz(t.sensitive_path_hits));set('trScan',nz(t.suspicious_scan_count));set('trTop',t.top_route||'n/d');set('trLast',t.last_route||'n/d')}function renderEnergy(e){e=e||{};document.getElementById('energyStatus').innerHTML=badge(e.available?'detectado':'indisponivel');document.getElementById('energyVoltage').textContent=e.available?fixed(e.bus_voltage_v,2,'V'):'n/d';document.getElementById('energyCurrent').textContent=e.available?fixed(e.current_ma,1,'mA'):'n/d';document.getElementById('energyPower').textContent=e.available?fixed(e.power_mw,1,'mW'):'n/d';document.getElementById('energyUpdated').textContent=e.available?nz(e.last_update_ms)+' ms':'n/d';document.getElementById('energyAlert').innerHTML=badge(e.alert_status||'sensor indisponivel')}async function refreshStatus(){try{const res=await fetch('/api/status');const d=await res.json();const ev=nz(d.eventCount)+'/'+nz(d.eventCapacity);document.getElementById('status').innerHTML=badge(d.status||'n/d');document.getElementById('apIp').textContent=d.apIp||d.ip||'n/d';document.getElementById('uptime').textContent=nz(d.uptimeSeconds)+'s';document.getElementById('eventCount').textContent=ev;document.getElementById('freeHeap').textContent=formatBytes(d.freeHeap);document.getElementById('minFreeHeap').textContent=formatBytes(d.minFreeHeap);document.getElementById('flashSize').textContent=formatBytes(d.flashSize);document.getElementById('sketchSize').textContent=formatBytes(d.sketchSize);renderFirewall(d.firewall);renderGateway(d.gateway);renderTraffic(d.traffic);renderStorage(d.storage||d.persistence);renderEnergy(d.energy);renderModules(d.modules);renderTasks(d.tasks);renderTimings(d.functionTimings)}catch(e){document.getElementById('status').textContent='erro'}}refreshStatus();</script>");
    html += F("</main></body></html>");
    return html;
}

String demoPage()
{
    const MetricsSnapshot snapshot = readMetricsSnapshot();
    const FirewallSnapshot firewall = readFirewallSnapshot();
    const GatewaySnapshot gateway = readGatewaySnapshot();
    const size_t count = readEventCount();
    String html;
    html.reserve(7600);
    appendPageHead(html, "Demo guiada - ESP32 Mini Firewall Gateway");
    appendHeader(html, "Demo guiada", "Roteiro de apresentacao do TDE no ESP32 em bancada.");
    html += F("<main><div class=\"toolbar\"><a class=\"btn primary\" href=\"/\">Dashboard</a><a class=\"btn\" href=\"/gateway\">Gateway</a><a class=\"btn\" href=\"/evidencias\">Evidencias</a><a class=\"btn\" href=\"/logs\">Logs</a><a class=\"btn\" href=\"/report\">Relatorio</a><a class=\"btn\" href=\"/api/status\">/api/status</a><a class=\"btn\" href=\"/api/events\">/api/events</a><a class=\"btn\" href=\"/api/events/persistent\">/api/events/persistent</a></div>");
    html += F("<div class=\"panel\"><h2>Status resumido</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Firmware</strong><span>");
    html += PROJECT_VERSION;
    html += F("</span></div><div class=\"metric\"><strong>IP AP</strong><span>");
    html += snapshot.apIp[0] != '\0' ? snapshot.apIp : "n/d";
    html += F("</span></div><div class=\"metric\"><strong>Gateway</strong><span>");
    html += gateway.mode;
    html += F("</span></div><div class=\"metric\"><strong>Upstream</strong><span>");
    html += gateway.staConfigured ? (gateway.staConnected ? "conectado" : "desconectado") : "nao configurado";
    html += F("</span></div><div class=\"metric\"><strong>Eventos</strong><span>");
    html += count;
    html += F("/");
    html += EVENT_CAPACITY;
    html += F("</span></div><div class=\"metric\"><strong>SECURITY</strong><span>");
    html += firewall.securityEvents;
    html += F("</span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Roteiro em etapas</h2><div class=\"table-wrap\"><table><thead><tr><th>Etapa</th><th>Objetivo</th><th>Acao</th></tr></thead><tbody>");
    html += F("<tr><td>1</td><td>Verificar status do sistema</td><td><a class=\"btn\" href=\"/\">Abrir dashboard</a></td></tr>");
    html += F("<tr><td>2</td><td>Verificar Gateway AP+STA</td><td><a class=\"btn\" href=\"/gateway\">Abrir gateway</a></td></tr>");
    html += F("<tr><td>3</td><td>Gerar evento informativo</td><td><a class=\"btn\" href=\"/demo/info\">Gerar INFO</a></td></tr>");
    html += F("<tr><td>4</td><td>Gerar alerta WARN</td><td><a class=\"btn warn\" href=\"/demo/warn\">Gerar WARN</a></td></tr>");
    html += F("<tr><td>5</td><td>Gerar evento SECURITY</td><td><a class=\"btn security\" href=\"/demo/security\">Gerar SECURITY</a></td></tr>");
    html += F("<tr><td>6</td><td>Simular flood HTTP</td><td><a class=\"btn security\" href=\"/demo/flood\">Simular flood</a></td></tr>");
    html += F("<tr><td>7</td><td>Simular IDS</td><td><a class=\"btn security\" href=\"/demo/ids\">Simular IDS</a></td></tr>");
    html += F("<tr><td>8</td><td>Simular scan basico</td><td><a class=\"btn security\" href=\"/demo/scan\">Simular scan</a></td></tr>");
    html += F("<tr><td>9</td><td>Abrir Traffic Monitor</td><td><a class=\"btn\" href=\"/traffic\">Abrir /traffic</a></td></tr>");
    html += F("<tr><td>10</td><td>Ver logs em RAM</td><td><a class=\"btn\" href=\"/logs\">Abrir logs</a></td></tr>");
    html += F("<tr><td>11</td><td>Ver logs persistentes</td><td><a class=\"btn\" href=\"/api/events/persistent\">Abrir JSON persistente</a></td></tr>");
    html += F("<tr><td>12</td><td>Validar com smoke tester externo</td><td><code>python3 tools/smoke_test_http.py --base-url http://192.168.4.1</code></td></tr>");
    html += F("</tbody></table></div></div>");
    html += F("<div class=\"cols\"><div class=\"panel\"><h2>Como apresentar</h2><ul><li>Primeiro mostro o painel local do ESP32.</li><li>Depois mostro o gateway didatico e o AP.</li><li>Em seguida simulo eventos de seguranca.</li><li>Os eventos aparecem em RAM e nos logs persistentes.</li><li>Por fim, executo o smoke test para validar as rotas.</li></ul></div>");
    html += F("<div class=\"panel\"><h2>Limitacoes</h2><ul><li>NAT/roteamento real nao implementado nesta fase.</li><li>IDS e didatico e baseado em HTTP do painel.</li><li>Nao inspeciona HTTPS.</li><li>Sensores fisicos ficam para fase final.</li><li>INA219 esta preparado no firmware, mas teste fisico depende de montagem/solda.</li></ul></div></div>");
    html += F("<div class=\"panel tight\"><h2>APIs para demonstracao</h2><p class=\"note\"><a href=\"/api/status\">/api/status</a> mostra metricas, gateway e IDS. <a href=\"/api/events\">/api/events</a> mostra o buffer em RAM. <a href=\"/api/events/persistent\">/api/events/persistent</a> mostra eventos relevantes salvos em LittleFS. <a href=\"/report\">/report</a> consolida a evidencia embarcada.</p></div>");
    html += F("</main></body></html>");
    return html;
}

void appendGatewayJson(String &json)
{
    const GatewaySnapshot gateway = readGatewaySnapshot();
    json += "{\"mode\":\"";
    appendJsonEscaped(json, gateway.mode);
    json += "\",\"ap_enabled\":";
    json += gateway.apEnabled ? "true" : "false";
    json += ",\"ap_ssid\":\"";
    appendJsonEscaped(json, gateway.apSsid);
    json += "\",\"ap_ip\":\"";
    appendJsonEscaped(json, gateway.apIp);
    json += "\",\"sta_configured\":";
    json += gateway.staConfigured ? "true" : "false";
    json += ",\"configured\":";
    json += gateway.staConfigured ? "true" : "false";
    json += ",\"sta_connected\":";
    json += gateway.staConnected ? "true" : "false";
    json += ",\"connected\":";
    json += gateway.staConnected ? "true" : "false";
    json += ",\"upstream_ssid\":\"";
    appendJsonEscaped(json, gateway.upstreamSsid);
    json += "\",\"ssid_present\":";
    json += gateway.staConfigured ? "true" : "false";
    json += ",\"ssid_masked\":\"";
    appendJsonEscaped(json, gateway.staConfigured ? maskedSsid(gateway.upstreamSsid).c_str() : "n/d");
    json += "\",\"passphrase_present\":";
    json += gateway.passphrasePresent ? "true" : "false";
    json += ",\"upstream_ip\":\"";
    appendJsonEscaped(json, gateway.upstreamIp);
    json += "\",\"ip\":\"";
    appendJsonEscaped(json, gateway.upstreamIp);
    json += "\",\"upstream_rssi\":";
    json += gateway.upstreamRssi;
    json += ",\"rssi\":";
    json += gateway.upstreamRssi;
    json += ",\"last_connect_attempt_ms\":";
    json += gateway.lastConnectAttemptMs;
    json += ",\"last_attempt_ms\":";
    json += gateway.lastConnectAttemptMs;
    json += ",\"last_status_change_ms\":";
    json += gateway.lastStatusChangeMs;
    json += ",\"last_status\":\"";
    appendJsonEscaped(json, gateway.lastStatus);
    json += "\",\"last_error\":\"";
    appendJsonEscaped(json, gateway.lastError);
    json += "\",\"client_count\":";
    json += gateway.clientCount;
    const NatSnapshot nat = readNatSnapshot();
    json += ",\"nat_enabled\":";
    json += nat.enabled ? "true" : "false";
    json += ",\"nat_active\":";
    json += nat.active ? "true" : "false";
    json += ",\"nat_supported\":";
    json += nat.supported ? "true" : "false";
    json += ",\"nat_status\":\"";
    appendJsonEscaped(json, nat.lastStatus);
    json += "\",\"nat_error\":\"";
    appendJsonEscaped(json, nat.lastError);
    json += "\",\"nat_note\":\"";
    appendJsonEscaped(json, nat.note);
    json += "\"}";
}

void appendWifiUpstreamJson(String &json)
{
    appendGatewayJson(json);
}

void appendNatJson(String &json)
{
    const NatSnapshot nat = readNatSnapshot();
    json += "{\"experimental_enabled\":";
    json += nat.experimentalEnabled ? "true" : "false";
    json += ",\"supported\":";
    json += nat.supported ? "true" : "false";
    json += ",\"enabled\":";
    json += nat.enabled ? "true" : "false";
    json += ",\"active\":";
    json += nat.active ? "true" : "false";
    json += ",\"last_attempt_ms\":";
    json += nat.lastAttemptMs;
    json += ",\"last_status\":\"";
    appendJsonEscaped(json, nat.lastStatus);
    json += "\",\"last_error\":\"";
    appendJsonEscaped(json, nat.lastError);
    json += "\",\"note\":\"";
    appendJsonEscaped(json, nat.note);
    json += "\"}";
}

String gatewayStatusText(const GatewaySnapshot &gateway)
{
    if (!gateway.staConfigured) {
        return "nao configurado";
    }
    return gateway.staConnected ? "conectado" : "desconectado";
}

String buildWifiPage()
{
    const GatewaySnapshot gateway = readGatewaySnapshot();
    String html;
    html.reserve(6200);
    appendPageHead(html, "Wi-Fi upstream - ESP32 Mini Firewall Gateway");
    appendHeader(html, "Wi-Fi upstream", "Configuracao didatica da internet upstream mantendo o AP local de recuperacao.");
    html += F("<main><div class=\"toolbar\"><a class=\"btn primary\" href=\"/\">Dashboard</a><a class=\"btn\" href=\"/gateway\">Gateway</a><a class=\"btn\" href=\"/logs\">Logs</a><a class=\"btn\" href=\"/api/status\">/api/status</a></div>");
    html += F("<div class=\"panel\"><h2>Status atual</h2><div class=\"grid summary\"><div class=\"metric\"><strong>AP local</strong><span><span class=\"badge ok\">ativo</span></span></div><div class=\"metric\"><strong>SSID salvo</strong><span>");
    if (gateway.staConfigured) {
        appendHtmlEscaped(html, gateway.upstreamSsid);
    } else {
        html += F("nao configurado");
    }
    html += F("</span></div><div class=\"metric\"><strong>Passphrase configurada</strong><span>");
    html += gateway.passphrasePresent ? "sim" : "nao";
    html += F("</span></div><div class=\"metric\"><strong>Upstream</strong><span><span class=\"badge ");
    html += gateway.staConnected ? "ok" : "planned";
    html += F("\">");
    html += gatewayStatusText(gateway);
    html += F("</span></span></div><div class=\"metric\"><strong>IP upstream</strong><span>");
    html += gateway.staConnected ? gateway.upstreamIp : "n/d";
    html += F("</span></div><div class=\"metric\"><strong>RSSI</strong><span>");
    html += gateway.staConnected ? String(gateway.upstreamRssi) + " dBm" : "n/d";
    html += F("</span></div><div class=\"metric\"><strong>Ultima tentativa</strong><span>");
    html += gateway.lastConnectAttemptMs;
    html += F(" ms</span></div><div class=\"metric\"><strong>Ultimo status</strong><span>");
    appendHtmlEscaped(html, gateway.lastStatus);
    html += F("</span></div><div class=\"metric\"><strong>Ultimo erro</strong><span>");
    html += gateway.lastError[0] != '\0' ? gateway.lastError : "n/d";
    html += F("</span></div></div><p class=\"note\">O AP local <code>ESP32-Firewall-Lab</code> continua ativo em <code>192.168.4.1</code> para recuperacao mesmo se o upstream falhar. Esta pagina nao possui autenticacao nesta fase; use apenas em laboratorio controlado.</p></div>");
    html += F("<div class=\"panel\"><h2>Configurar upstream</h2><form method=\"post\" action=\"/wifi/save\"><div class=\"grid\"><div><label for=\"ssid\">SSID upstream</label><input id=\"ssid\" name=\"ssid\" maxlength=\"32\" value=\"");
    if (gateway.staConfigured) {
        appendHtmlEscaped(html, gateway.upstreamSsid);
    }
    html += F("\"></div><div><label for=\"passphrase\">Passphrase WPA/WPA2</label><input id=\"passphrase\" type=\"");
    html += F("pass");
    html += F("word\" name=\"passphrase\" minlength=\"8\" maxlength=\"63\" autocomplete=\"off\" placeholder=\"nao exibida apos salvar\"></div></div><div class=\"actions\"><button class=\"btn primary\" type=\"submit\">Conectar e salvar</button><a class=\"btn\" href=\"/wifi/reconnect\">Reconectar</a></div></form><p class=\"note\">A passphrase e gravada apenas localmente em arquivo do LittleFS para permitir a conexao STA. Ela nao aparece em API, logs, Serial ou HTML depois de salvar.</p></div>");
    html += F("<div class=\"panel tight\"><h2>Limpar configuracao</h2><p class=\"note\">Remove o upstream salvo, desconecta a STA e mantem o AP local ativo.</p><form class=\"inline\" method=\"post\" action=\"/wifi/clear\"><button class=\"btn warn\" type=\"submit\">Limpar upstream</button></form></div>");
    html += F("</main></body></html>");
    return html;
}

String buildGatewayPage()
{
    const GatewaySnapshot gateway = readGatewaySnapshot();
    const FirewallSnapshot firewall = readFirewallSnapshot();
    const NatSnapshot nat = readNatSnapshot();
    String html;
    html.reserve(5200);
    appendPageHead(html, "Gateway - ESP32 Mini Firewall Gateway");
    appendHeader(html, "Gateway AP+STA", "Telemetria didatica de rede local e upstream Wi-Fi.");
    html += F("<main><div class=\"toolbar\"><a class=\"btn primary\" href=\"/\">Dashboard</a><a class=\"btn\" href=\"/wifi\">Wi-Fi</a><a class=\"btn\" href=\"/logs\">Logs</a><a class=\"btn\" href=\"/evidencias\">Evidencias</a><a class=\"btn\" href=\"/api/status\">/api/status</a><a class=\"btn\" href=\"/demo/ids\">Gerar IDS</a></div>");
    html += F("<div class=\"panel\"><h2>Modo Wi-Fi</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Modo</strong><span>");
    html += gateway.mode;
    html += F("</span></div><div class=\"metric\"><strong>AP SSID</strong><span>");
    html += gateway.apSsid;
    html += F("</span></div><div class=\"metric\"><strong>AP IP</strong><span>");
    html += gateway.apIp;
    html += F("</span></div><div class=\"metric\"><strong>Clientes AP</strong><span>");
    html += gateway.clientCount;
    html += F("</span></div></div></div>");
    html += F("<div class=\"panel\"><h2>Upstream Wi-Fi</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Configuracao</strong><span><span class=\"badge ");
    html += gateway.staConfigured ? "ok" : "planned";
    html += F("\">");
    html += gateway.staConfigured ? "configurado" : "nao configurado";
    html += F("</span></span></div><div class=\"metric\"><strong>Status</strong><span>");
    html += gatewayStatusText(gateway);
    html += F("</span></div><div class=\"metric\"><strong>SSID upstream</strong><span>");
    html += gateway.upstreamSsid;
    html += F("</span></div><div class=\"metric\"><strong>IP upstream</strong><span>");
    html += gateway.upstreamIp;
    html += F("</span></div><div class=\"metric\"><strong>RSSI</strong><span>");
    html += gateway.staConnected ? String(gateway.upstreamRssi) + " dBm" : "n/d";
    html += F("</span></div><div class=\"metric\"><strong>Ultima tentativa</strong><span>");
    html += gateway.lastConnectAttemptMs;
    html += F(" ms</span></div><div class=\"metric\"><strong>Passphrase salva</strong><span>");
    html += gateway.passphrasePresent ? "sim" : "nao";
    html += F("</span></div><div class=\"metric\"><strong>Ultimo status</strong><span>");
    appendHtmlEscaped(html, gateway.lastStatus);
    html += F("</span></div><div class=\"metric\"><strong>Ultimo erro</strong><span>");
    appendHtmlEscaped(html, gateway.lastError[0] != '\0' ? gateway.lastError : "n/d");
    html += F("</span></div><div class=\"metric\"><strong>Configuracao</strong><span><a href=\"/wifi\">/wifi</a></span></div></div><p class=\"note\">NAT/roteamento real nao faz parte desta sprint; a funcao e telemetria AP+STA, configuracao upstream e demonstracao didatica de IDS.</p></div>");
    html += F("<div class=\"panel\"><h2>IDS didatico</h2><div class=\"grid summary\"><div class=\"metric\"><strong>Status</strong><span><span class=\"badge ok\">ativo</span></span></div><div class=\"metric\"><strong>Eventos IDS</strong><span>");
    html += firewall.idsEvents;
    html += F("</span></div><div class=\"metric\"><strong>404 suspeitos</strong><span>");
    html += firewall.suspicious404Count;
    html += F("</span></div><div class=\"metric\"><strong>Rotas sensiveis</strong><span>");
    html += firewall.sensitivePathHits;
    html += F("</span></div></div><p class=\"note\">Deteccao baseada em HTTP do painel: flood, rotas inexistentes e caminhos sensiveis simulados. Nao inspeciona HTTPS e nao substitui IDS/IPS real.</p></div></main></body></html>");
    return html;
}

String buildStatusJson()
{
    const MetricsSnapshot snapshot = readMetricsSnapshot();
    String json;
    json.reserve(1700);
    json += "{";
    json += "\"project_name\":\"";
    json += PROJECT_NAME;
    json += "\",\"firmware_version\":\"";
    json += PROJECT_VERSION;
    json += "\",\"wifi_connected\":";
    json += (WiFi.getMode() == WIFI_AP || WiFi.getMode() == WIFI_AP_STA) ? "true" : "false";
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
    json += ",\"ids_enabled\":";
    json += firewall.idsEnabled ? "true" : "false";
    json += ",\"ids_events\":";
    json += firewall.idsEvents;
    json += ",\"suspicious_404_count\":";
    json += firewall.suspicious404Count;
    json += ",\"sensitive_path_hits\":";
    json += firewall.sensitivePathHits;
    json += "}";
    json += ",\"ids\":{\"enabled\":";
    json += firewall.idsEnabled ? "true" : "false";
    json += ",\"events\":";
    json += firewall.idsEvents;
    json += ",\"suspicious_404_count\":";
    json += firewall.suspicious404Count;
    json += ",\"sensitive_path_hits\":";
    json += firewall.sensitivePathHits;
    json += "}";
    json += ",\"gateway\":";
    appendGatewayJson(json);
    json += ",\"nat\":";
    appendNatJson(json);
    json += ",\"traffic\":";
    appendTrafficJsonObject(json, readTrafficSnapshot());
    json += ",\"wifi_upstream\":";
    appendWifiUpstreamJson(json);
    json += ",\"storage\":";
    appendStorageJson(json);
    json += ",\"persistence\":";
    appendStorageJson(json);
    json += ",\"eventCount\":";
    json += readEventCount();
    json += ",\"eventCapacity\":";
    json += EVENT_CAPACITY;
    json += ",\"status\":\"ok\"";
    json += "}";

    return json;
}

String buildPersistentEventsJson()
{
    String json;
    json.reserve(PERSISTENT_EVENTS_MAX_SIZE + 220);
    json += "{\"available\":";
    json += littleFsAvailable ? "true" : "false";
    json += ",\"file_size\":";
    json += persistentLogSize();
    json += ",\"max_size\":";
    json += PERSISTENT_EVENTS_MAX_SIZE;
    json += ",\"path\":\"";
    json += PERSISTENT_EVENTS_PATH;
    json += "\",\"policy\":\"WARN ERROR SECURITY e eventos importantes de sistema firewall sensores e energia\"";
    json += ",\"rotated\":";
    json += persistentLogRotated ? "true" : "false";
    json += ",\"lines\":[";

    if (littleFsAvailable && LittleFS.exists(PERSISTENT_EVENTS_PATH)) {
        File file = LittleFS.open(PERSISTENT_EVENTS_PATH, "r");
        bool first = true;
        while (file && file.available()) {
            String line = file.readStringUntil('\n');
            line.trim();
            if (line.length() == 0) {
                continue;
            }
            if (!first) {
                json += ",";
            }
            json += "\"";
            appendJsonEscaped(json, line.c_str());
            json += "\"";
            first = false;
        }
        if (file) {
            file.close();
        }
    }

    json += "]}";
    return json;
}

void handlePersistentEventsApi()
{
    registerHttpAccess("/api/events/persistent", false);
    server.send(200, "application/json", buildPersistentEventsJson());
}

void handleClearPersistentLogs()
{
    registerHttpAccess("/logs/clear-persistent", false);
    if (littleFsAvailable) {
        LittleFS.remove(PERSISTENT_EVENTS_PATH);
        persistentLogRotated = false;
        addEvent("WARN", "STORAGE", "Limpeza manual dos logs persistentes", PERSISTENT_EVENTS_PATH);
    } else {
        addEvent("ERROR", "STORAGE", "Limpeza solicitada sem LittleFS disponivel", PERSISTENT_EVENTS_PATH);
    }
    server.sendHeader("Location", "/logs", true);
    server.send(303, "text/plain; charset=utf-8", "Logs persistentes limpos. Consulte /logs");
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

void handleTrafficApi()
{
    registerHttpAccess("/api/traffic");
    server.send(200, "application/json", buildTrafficJson());
}

void handleReportApi()
{
    registerHttpAccess("/api/report");
    server.send(200, "application/json", buildReportJson());
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

void handleTraffic()
{
    registerHttpAccess("/traffic");
    server.send(200, "text/html; charset=utf-8", trafficPage());
}

void handleReport()
{
    registerHttpAccess("/report");
    server.send(200, "text/html; charset=utf-8", reportPage());
}

void redirectToLogs()
{
    server.sendHeader("Location", "/logs", true);
    server.send(303, "text/plain; charset=utf-8", "Evento registrado. Consulte /logs");
}

void handleDemoPage()
{
    registerHttpAccess("/demo");
    server.send(200, "text/html; charset=utf-8", demoPage());
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

void handleDemoIds()
{
    registerHttpAccess("/demo/ids");
    addIdsDemoEvent("Simulacao controlada de assinatura IDS", "assinatura didatica");
    redirectToLogs();
}

void handleDemoScan()
{
    registerHttpAccess("/demo/scan");
    const char *paths[] = {"/admin", "/login", "/wp-admin", "/xmlrpc.php", "/etc/passwd", "/phpmyadmin"};
    char clientIp[16];
    copyText(clientIp, sizeof(clientIp), server.client().remoteIP().toString().c_str());
    bool scanLogged = false;
    for (size_t index = 0; index < sizeof(paths) / sizeof(paths[0]); ++index) {
        const bool sensitive = isSensitivePath(paths[index]);
        if (recordTrafficSample(paths[index], clientIp, "demo-scan/1.0", true, sensitive)) {
            scanLogged = true;
        }
        noteIdsFinding(true, sensitive);
    }
    noteTrafficIdsEvent();
    addEvent("SECURITY", "IDS", scanLogged ? "Possivel scan HTTP detectado" : "Simulacao controlada de scan HTTP", "demo scan");
    redirectToLogs();
}

void handleGateway()
{
    registerHttpAccess("/gateway");
    server.send(200, "text/html; charset=utf-8", buildGatewayPage());
}

void handleWifiPage()
{
    registerHttpAccess("/wifi");
    server.send(200, "text/html; charset=utf-8", buildWifiPage());
}

void redirectToWifi()
{
    server.sendHeader("Location", "/wifi", true);
    server.send(303, "text/plain; charset=utf-8", "Consulte /wifi");
}

void handleWifiSave()
{
    registerHttpAccess("/wifi/save", false);
    if (!server.hasArg("ssid") || !server.hasArg("passphrase")) {
        updateGatewayAttemptStatus(0, "erro", "formulario incompleto");
        addEvent("WARN", "WIFI", "Configuracao upstream rejeitada", "formulario incompleto");
        redirectToWifi();
        return;
    }

    String ssid = server.arg("ssid");
    String passphrase = server.arg("passphrase");
    ssid.trim();
    passphrase.trim();

    if (!isValidSsidLength(ssid)) {
        updateGatewayAttemptStatus(0, "erro", "SSID invalido");
        addEvent("WARN", "WIFI", "Configuracao upstream rejeitada", "SSID invalido");
        redirectToWifi();
        return;
    }
    if (passphrase.length() == 0 || !isValidPassphraseLength(passphrase)) {
        updateGatewayAttemptStatus(0, "erro", "passphrase invalida");
        addEvent("WARN", "WIFI", "Configuracao upstream rejeitada", "passphrase invalida");
        redirectToWifi();
        return;
    }

    if (saveWifiConfigFile(ssid.c_str(), passphrase.c_str())) {
        attemptUpstreamConnection("Tentativa de conexao upstream");
    }
    redirectToWifi();
}

void handleWifiClear()
{
    registerHttpAccess("/wifi/clear", false);
    clearWifiConfigFile();
    redirectToWifi();
}

void handleWifiReconnect()
{
    registerHttpAccess("/wifi/reconnect", false);
    attemptUpstreamConnection("Tentativa manual de reconexao upstream");
    redirectToWifi();
}

void handleNotFound()
{
    const String route = server.uri();
    const bool sensitive = isSensitivePath(route.c_str());
    registerTrafficAccess(route.c_str(), true, sensitive);
    registerHttpAccess(route.c_str(), false, false);
    registerIdsNotFound(route.c_str());
    server.send(404, "text/plain; charset=utf-8", "Rota nao encontrada");
}

void setupPersistentStorage()
{
    littleFsAvailable = LittleFS.begin(true);
    if (littleFsAvailable) {
        addEvent("INFO", "STORAGE", "LittleFS iniciado", PERSISTENT_EVENTS_PATH);
        return;
    }

    addEvent("ERROR", "STORAGE", "Falha ao iniciar LittleFS", PERSISTENT_EVENTS_PATH);
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

void attemptUpstreamConnection(const char *reason)
{
    const WifiUpstreamConfig config = readWifiConfig();
    if (!config.saved || config.ssid[0] == '\0') {
        updateGatewayAttemptStatus(0, "nao configurado", "");
        refreshGatewaySnapshot(false);
        return;
    }
    if (!config.passphrasePresent) {
        updateGatewayAttemptStatus(0, "sem passphrase", "passphrase ausente");
        addEvent("WARN", "WIFI", "Tentativa upstream ignorada", config.ssid);
        refreshGatewaySnapshot(false);
        return;
    }

    const unsigned long attemptMs = millis();
    updateGatewayAttemptStatus(attemptMs, "tentando", "");
    addEvent("INFO", "WIFI", reason, config.ssid);

    WiFi.disconnect(false, false);
    WiFi.mode(WIFI_AP_STA);
    WiFi.begin(config.ssid, config.passphrase);

    const unsigned long startMs = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - startMs < UPSTREAM_CONNECT_TIMEOUT_MS) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    refreshGatewaySnapshot(false);
    if (WiFi.status() == WL_CONNECTED) {
        updateGatewayAttemptStatus(attemptMs, "conectado", "");
        addEvent("INFO", "WIFI", "Upstream Wi-Fi conectado", WiFi.localIP().toString().c_str());
    } else {
        WiFi.disconnect(false, false);
        WiFi.mode(WIFI_AP_STA);
        updateGatewayAttemptStatus(attemptMs, "falhou", "timeout ou credenciais invalidas");
        addEvent("WARN", "WIFI", "Upstream Wi-Fi falhou", config.ssid);
    }
    refreshGatewaySnapshot(false);
}

void setupAccessPoint()
{
    WiFi.mode(WIFI_AP_STA);
    const bool apStarted = WiFi.softAP(AP_SSID, AP_PASSPHRASE);

    Serial.print("Wi-Fi AP SSID: ");
    Serial.println(AP_SSID);
    Serial.print("Wi-Fi AP iniciado: ");
    Serial.println(apStarted ? "sim" : "nao");
    Serial.print("Wi-Fi AP IP: ");
    Serial.println(WiFi.softAPIP());

    addEvent(apStarted ? "INFO" : "ERROR", "WIFI", apStarted ? "Wi-Fi AP iniciado" : "Falha ao iniciar Wi-Fi AP", WiFi.softAPIP().toString().c_str());

    if (!upstreamWifiConfigured()) {
        refreshGatewaySnapshot(false);
        return;
    }

    attemptUpstreamConnection("Tentativa de conexao upstream");
}

void setupWebServer()
{
    server.collectHeaders(WEB_HEADER_KEYS, sizeof(WEB_HEADER_KEYS) / sizeof(WEB_HEADER_KEYS[0]));
    server.on("/", HTTP_GET, handleRoot);
    server.on("/api/status", HTTP_GET, handleStatus);
    server.on("/api/events", HTTP_GET, handleEventsApi);
    server.on("/api/traffic", HTTP_GET, handleTrafficApi);
    server.on("/api/report", HTTP_GET, handleReportApi);
    server.on("/api/events/persistent", HTTP_GET, handlePersistentEventsApi);
    server.on("/evidencias", HTTP_GET, handleEvidences);
    server.on("/gateway", HTTP_GET, handleGateway);
    server.on("/traffic", HTTP_GET, handleTraffic);
    server.on("/report", HTTP_GET, handleReport);
    server.on("/wifi", HTTP_GET, handleWifiPage);
    server.on("/wifi/save", HTTP_POST, handleWifiSave);
    server.on("/wifi/clear", HTTP_GET, handleWifiClear);
    server.on("/wifi/clear", HTTP_POST, handleWifiClear);
    server.on("/wifi/reconnect", HTTP_GET, handleWifiReconnect);
    server.on("/logs", HTTP_GET, handleLogs);
    server.on("/eventos", HTTP_GET, handleLogs);
    server.on("/logs/clear-persistent", HTTP_GET, handleClearPersistentLogs);
    server.on("/demo", HTTP_GET, handleDemoPage);
    server.on("/demo/info", HTTP_GET, handleDemoInfo);
    server.on("/demo/warn", HTTP_GET, handleDemoWarn);
    server.on("/demo/security", HTTP_GET, handleDemoSecurity);
    server.on("/demo/flood", HTTP_GET, handleDemoFlood);
    server.on("/demo/ids", HTTP_GET, handleDemoIds);
    server.on("/demo/scan", HTTP_GET, handleDemoScan);
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
    gatewayMutex = xSemaphoreCreateMutex();
    wifiConfigMutex = xSemaphoreCreateMutex();
    natMutex = xSemaphoreCreateMutex();
    trafficMutex = xSemaphoreCreateMutex();
    updateNatSnapshot(false, 0, "inicializando", "", "NAT experimental depende de suporte NAPT no lwIP");
    setupPersistentStorage();
    loadWifiConfigFile();
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
