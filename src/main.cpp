#include <Arduino.h>
#include <WebServer.h>
#include <WiFi.h>
#include <cstring>

namespace {
constexpr const char *PROJECT_NAME = "ESP32 Mini Firewall Gateway";
constexpr const char *PROJECT_VERSION = "0.4.0-sprint-evidencias";
constexpr const char *PROJECT_PHASE = "Sprint evidencias - base demonstravel";
constexpr const char *AP_SSID = "ESP32-Firewall-Lab";
constexpr const char *AP_PASSWORD = "esp32lab123";
constexpr unsigned long HEARTBEAT_INTERVAL_MS = 5000UL;
constexpr uint32_t WEB_SERVER_INTERVAL_MS = 10UL;
constexpr uint32_t METRICS_INTERVAL_MS = 1000UL;
constexpr BaseType_t CORE_WEB = 1;
constexpr BaseType_t CORE_BACKGROUND = 0;

WebServer server(80);
SemaphoreHandle_t metricsMutex = nullptr;
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
    {"Firewall didatico", "planejado"},
    {"Sensores", "planejado"},
    {"Atuadores", "planejado"},
    {"Logs e persistencia", "planejado"},
    {"Energia", "planejado"},
};

struct MetricsSnapshot {
    unsigned long uptimeSeconds;
    uint32_t freeHeap;
    uint32_t minFreeHeap;
    uint32_t flashSize;
    uint32_t sketchSize;
    char apIp[16];
    char apSsid[33];
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
    if (metricsMutex == nullptr || xSemaphoreTake(metricsMutex, pdMS_TO_TICKS(50)) != pdTRUE) {
        return;
    }

    metricsSnapshot.uptimeSeconds = uptimeSeconds();
    metricsSnapshot.freeHeap = ESP.getFreeHeap();
    metricsSnapshot.minFreeHeap = ESP.getMinFreeHeap();
    metricsSnapshot.flashSize = ESP.getFlashChipSize();
    metricsSnapshot.sketchSize = ESP.getSketchSize();
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
        json += MODULES[index].status;
        json += "\"}";
    }
    json += "]";
}

String evidencePage()
{
    const MetricsSnapshot snapshot = readMetricsSnapshot();
    String html;
    html.reserve(5200);
    html += F("<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">");
    html += F("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">");
    html += F("<title>Evidencias - ESP32 Mini Firewall Gateway</title>");
    html += F("<style>");
    html += F(":root{--bg:#f6f7f9;--panel:#fff;--text:#1f2933;--muted:#52616f;--line:#d7dde5;--ok:#0f766e;--wait:#8a5a00}");
    html += F("*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:Arial,Helvetica,sans-serif}");
    html += F("header{padding:18px 22px;background:#102a43;color:#fff}h1{margin:0 0 6px;font-size:24px}header p{margin:0;color:#d9e2ec}");
    html += F("main{width:min(1050px,100%);margin:0 auto;padding:16px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}");
    html += F(".metric,section{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px}.metric strong{display:block;color:var(--muted);font-size:13px;margin-bottom:6px}.metric span{font-size:18px;word-break:break-word}");
    html += F("section{margin-top:14px}h2{font-size:18px;margin:0 0 10px}table{width:100%;border-collapse:collapse;background:#fbfdff}th,td{border:1px solid var(--line);padding:8px;text-align:left}th{color:var(--muted);font-size:13px}");
    html += F(".ok{color:var(--ok);font-weight:700}.wait{color:var(--wait);font-weight:700}.note{color:var(--muted);line-height:1.45}a{color:#0f5f9c}</style></head><body>");
    html += F("<header><h1>");
    html += PROJECT_NAME;
    html += F("</h1><p>Pagina leve para prints de evidencia do TDE academico.</p></header><main>");
    html += F("<div class=\"grid\">");
    html += F("<div class=\"metric\"><strong>Versao do firmware</strong><span>");
    html += PROJECT_VERSION;
    html += F("</span></div><div class=\"metric\"><strong>IP local</strong><span>");
    html += snapshot.apIp[0] != '\0' ? snapshot.apIp : "n/d";
    html += F("</span></div><div class=\"metric\"><strong>Status do Wi-Fi</strong><span>");
    html += WiFi.getMode() == WIFI_AP ? "AP ativo" : "n/d";
    html += F("</span></div><div class=\"metric\"><strong>Uptime</strong><span>");
    html += snapshot.uptimeSeconds;
    html += F("s</span></div><div class=\"metric\"><strong>Heap livre</strong><span>");
    html += snapshot.freeHeap;
    html += F(" bytes</span></div><div class=\"metric\"><strong>SSID AP</strong><span>");
    html += snapshot.apSsid[0] != '\0' ? snapshot.apSsid : "n/d";
    html += F("</span></div></div>");
    html += F("<section><h2>Status dos modulos principais</h2><table><thead><tr><th>Modulo</th><th>Status</th></tr></thead><tbody>");
    for (size_t index = 0; index < sizeof(MODULES) / sizeof(MODULES[0]); ++index) {
        const bool active = std::strcmp(MODULES[index].status, "ativo") == 0;
        html += F("<tr><td>");
        html += MODULES[index].name;
        html += F("</td><td class=\"");
        html += active ? "ok" : "wait";
        html += F("\">");
        html += MODULES[index].status;
        html += F("</td></tr>");
    }
    html += F("</tbody></table></section>");
    html += F("<section><h2>Ultimos eventos</h2><p class=\"note\">Placeholder: sistema de logs persistente ainda nao foi implementado. Eventos esperados nesta sprint: boot, Wi-Fi AP iniciado, servidor web iniciado e consulta de status.</p></section>");
    html += F("<section><h2>Links de verificacao</h2><p><a href=\"/\">Dashboard</a> | <a href=\"/api/status\">API de status</a></p></section>");
    html += F("</main></body></html>");
    return html;
}

String htmlPage()
{
    return R"rawliteral(
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ESP32 Mini Firewall Gateway</title>
  <style>
    :root {
      color-scheme: light;
      --bg: #f4f6f8;
      --panel: #ffffff;
      --text: #1f2933;
      --muted: #5c6f82;
      --line: #d8e0e8;
      --accent: #0f766e;
      --accent-strong: #115e59;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Arial, Helvetica, sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    header {
      background: #102a43;
      color: #ffffff;
      padding: 20px;
    }
    header h1 {
      margin: 0 0 6px;
      font-size: 24px;
      line-height: 1.2;
    }
    header p {
      margin: 0;
      color: #d9e2ec;
      line-height: 1.4;
    }
    main {
      width: min(1100px, 100%);
      margin: 0 auto;
      padding: 16px;
    }
    nav {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }
    button.tab {
      border: 1px solid var(--line);
      background: var(--panel);
      color: var(--text);
      padding: 10px 12px;
      border-radius: 6px;
      cursor: pointer;
      min-height: 40px;
    }
    button.tab.active {
      background: var(--accent);
      border-color: var(--accent-strong);
      color: #ffffff;
    }
    section {
      display: none;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      padding: 16px;
    }
    section.active { display: block; }
    h2, h3 { margin: 0 0 12px; }
    h2 { font-size: 20px; }
    h3 { font-size: 16px; margin-top: 18px; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }
    .metric {
      border: 1px solid var(--line);
      border-radius: 6px;
      padding: 12px;
      background: #fbfdff;
    }
    .metric strong {
      display: block;
      font-size: 13px;
      color: var(--muted);
      margin-bottom: 6px;
    }
    .metric span {
      font-size: 18px;
      word-break: break-word;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      background: #fbfdff;
    }
    th, td {
      border: 1px solid var(--line);
      padding: 8px;
      text-align: left;
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
    }
    .note {
      color: var(--muted);
      line-height: 1.5;
    }
    code {
      background: #eef2f6;
      padding: 2px 4px;
      border-radius: 4px;
    }
  </style>
</head>
<body>
  <header>
    <h1>ESP32 Mini Firewall Gateway</h1>
    <p>Projeto didatico/de laboratorio. Nao substitui firewall profissional.</p>
  </header>
  <main>
    <nav aria-label="Abas principais">
      <button class="tab active" data-tab="performance">Performance</button>
      <button class="tab" data-tab="firewall">Firewall</button>
      <button class="tab" data-tab="clientes">Clientes</button>
      <button class="tab" data-tab="logs">Logs</button>
      <button class="tab" data-tab="configuracao">Configuracao</button>
      <button class="tab" data-tab="sobre">Sobre</button>
      <button class="tab" data-tab="changelog">Changelog</button>
    </nav>

    <section id="performance" class="active">
      <h2>Performance</h2>
      <div class="grid">
        <div class="metric"><strong>Status</strong><span id="status">n/d</span></div>
        <div class="metric"><strong>Uptime</strong><span id="uptime">n/d</span></div>
        <div class="metric"><strong>Heap livre</strong><span id="freeHeap">n/d</span></div>
        <div class="metric"><strong>Heap minimo</strong><span id="minFreeHeap">n/d</span></div>
        <div class="metric"><strong>Flash</strong><span id="flashSize">n/d</span></div>
        <div class="metric"><strong>Sketch</strong><span id="sketchSize">n/d</span></div>
        <div class="metric"><strong>SSID AP</strong><span id="apSsid">n/d</span></div>
        <div class="metric"><strong>IP AP</strong><span id="apIp">n/d</span></div>
      </div>

      <h3>Tasks FreeRTOS</h3>
      <table aria-label="Tasks FreeRTOS">
        <thead>
          <tr><th>Nome</th><th>Core planejado</th><th>Status</th><th>Stack high watermark</th></tr>
        </thead>
        <tbody id="tasksTable">
          <tr><td colspan="4">n/d</td></tr>
        </tbody>
      </table>

      <h3>Tempos de execucao</h3>
      <table aria-label="Tempos de execucao">
        <thead>
          <tr><th>Funcao</th><th>Ultima medicao</th><th>Status</th></tr>
        </thead>
        <tbody id="timingsTable">
          <tr><td colspan="3">n/d</td></tr>
        </tbody>
      </table>
      <p class="note">Stack high watermark por task, graficos, series temporais e tempos de pelo menos cinco funcoes serao refinados nas proximas fases.</p>
    </section>

    <section id="firewall">
      <h2>Firewall</h2>
      <p class="note">Firewall didatico sera implementado na Fase 4. Esta interface nao inspeciona HTTPS e nao substitui firewall profissional.</p>
    </section>

    <section id="clientes">
      <h2>Clientes</h2>
      <p class="note">Lista e contadores de clientes conectados ao AP serao detalhados em fase posterior.</p>
    </section>

    <section id="logs">
      <h2>Logs</h2>
      <p class="note">Logs INFO, WARN, ERROR, SECURITY e exportacao serao implementados na Fase 3.</p>
    </section>

    <section id="configuracao">
      <h2>Configuracao</h2>
      <p class="note">Configuracao dinamica e persistencia em NVS serao implementadas em fase posterior.</p>
    </section>

    <section id="sobre">
      <h2>Sobre</h2>
      <p>PUCPR</p>
      <p>Engenharia de Software</p>
      <p>Performance de Sistemas Ciberfisicos</p>
      <p>ESP32 Mini Firewall Gateway</p>
      <p>Projeto didatico/de laboratorio. Nao substitui firewall profissional.</p>
    </section>

    <section id="changelog">
      <h2>Changelog</h2>
      <p class="note">Versao 0.3.0-fase2: FreeRTOS com tasks minimas e metricas de performance.</p>
      <p class="note">Versao 0.2.0-fase1: Wi-Fi AP minimo e dashboard web base.</p>
    </section>
  </main>

  <script>
    const tabs = document.querySelectorAll('button.tab');
    const sections = document.querySelectorAll('main section');

    tabs.forEach((tab) => {
      tab.addEventListener('click', () => {
        const target = tab.dataset.tab;
        tabs.forEach((item) => item.classList.toggle('active', item === tab));
        sections.forEach((section) => section.classList.toggle('active', section.id === target));
      });
    });

    function formatBytes(value) {
      if (typeof value !== 'number' || value <= 0) {
        return 'n/d';
      }
      return `${value} bytes`;
    }

    function renderTasks(tasks) {
      const body = document.getElementById('tasksTable');
      body.innerHTML = '';
      if (!Array.isArray(tasks) || tasks.length === 0) {
        body.innerHTML = '<tr><td colspan="4">n/d</td></tr>';
        return;
      }
      tasks.forEach((task) => {
        const row = document.createElement('tr');
        row.innerHTML = `<td>${task.name}</td><td>${task.core}</td><td>${task.status}</td><td>${task.stackHighWatermark}</td>`;
        body.appendChild(row);
      });
    }

    function renderTimings(timings) {
      const body = document.getElementById('timingsTable');
      body.innerHTML = '';
      if (!Array.isArray(timings) || timings.length === 0) {
        body.innerHTML = '<tr><td colspan="3">n/d</td></tr>';
        return;
      }
      timings.forEach((timing) => {
        const row = document.createElement('tr');
        row.innerHTML = `<td>${timing.name}</td><td>${timing.measured ? timing.lastMicros + ' us' : 'n/d'}</td><td>${timing.measured ? 'medida' : 'pendente'}</td>`;
        body.appendChild(row);
      });
    }

    async function refreshStatus() {
      try {
        const response = await fetch('/api/status');
        const data = await response.json();
        document.getElementById('status').textContent = data.status;
        document.getElementById('uptime').textContent = `${data.uptimeSeconds}s`;
        document.getElementById('freeHeap').textContent = formatBytes(data.freeHeap);
        document.getElementById('minFreeHeap').textContent = formatBytes(data.minFreeHeap);
        document.getElementById('flashSize').textContent = formatBytes(data.flashSize);
        document.getElementById('sketchSize').textContent = formatBytes(data.sketchSize);
        document.getElementById('apSsid').textContent = data.apSsid || 'n/d';
        document.getElementById('apIp').textContent = data.apIp || 'n/d';
        renderTasks(data.tasks);
        renderTimings(data.functionTimings);
      } catch (error) {
        document.getElementById('status').textContent = 'erro ao consultar status';
      }
    }

    refreshStatus();
    setInterval(refreshStatus, 5000);
  </script>
</body>
</html>
)rawliteral";
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

    json += "],\"status\":\"ok\"";
    json += "}";

    return json;
}

void handleRoot()
{
    const uint32_t startMicros = micros();
    server.send(200, "text/html; charset=utf-8", htmlPage());
    updateFunctionTiming("handleRoot", micros() - startMicros);
}

void handleStatus()
{
    const uint32_t startMicros = micros();
    const String json = buildStatusJson();
    updateFunctionTiming("buildStatusJson", micros() - startMicros);
    server.send(200, "application/json", json);
}

void handleEvidences()
{
    const uint32_t startMicros = micros();
    server.send(200, "text/html; charset=utf-8", evidencePage());
    updateFunctionTiming("handleEvidences", micros() - startMicros);
}

void handleNotFound()
{
    server.send(404, "text/plain; charset=utf-8", "Rota nao encontrada");
}

void setupAccessPoint()
{
    WiFi.mode(WIFI_AP);
    const bool apStarted = WiFi.softAP(AP_SSID, AP_PASSWORD);

    Serial.print("Wi-Fi AP SSID: ");
    Serial.println(AP_SSID);
    Serial.print("Wi-Fi AP iniciado: ");
    Serial.println(apStarted ? "sim" : "nao");
    Serial.print("Wi-Fi AP IP: ");
    Serial.println(WiFi.softAPIP());
}

void setupWebServer()
{
    server.on("/", HTTP_GET, handleRoot);
    server.on("/api/status", HTTP_GET, handleStatus);
    server.on("/evidencias", HTTP_GET, handleEvidences);
    server.onNotFound(handleNotFound);
    server.begin();

    Serial.println("Servidor web iniciado na porta 80.");
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
    setupAccessPoint();
    setupWebServer();
    refreshMetricsSnapshot();
    createTasks();
}

void loop()
{
    vTaskDelay(pdMS_TO_TICKS(1000));
}
