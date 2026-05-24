#include <Arduino.h>
#include <WebServer.h>
#include <WiFi.h>

namespace {
constexpr const char *PROJECT_NAME = "ESP32 Mini Firewall Gateway";
constexpr const char *PROJECT_VERSION = "0.2.0-fase1";
constexpr const char *PROJECT_PHASE = "Fase 1 - Wi-Fi AP minimo e dashboard base";
constexpr const char *AP_SSID = "ESP32-Firewall-Lab";
constexpr const char *AP_PASSWORD = "esp32lab123";
constexpr unsigned long HEARTBEAT_INTERVAL_MS = 5000UL;

WebServer server(80);
unsigned long lastHeartbeatMs = 0;

unsigned long uptimeSeconds()
{
    return millis() / 1000UL;
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
    h2 {
      margin: 0 0 12px;
      font-size: 20px;
    }
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
        <div class="metric"><strong>SSID AP</strong><span id="apSsid">n/d</span></div>
        <div class="metric"><strong>IP AP</strong><span id="apIp">n/d</span></div>
      </div>
      <p class="note">Metricas completas, tasks, tempos de execucao e series temporais serao implementados na Fase 2.</p>
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

    async function refreshStatus() {
      try {
        const response = await fetch('/api/status');
        const data = await response.json();
        document.getElementById('status').textContent = data.status;
        document.getElementById('uptime').textContent = `${data.uptimeSeconds}s`;
        document.getElementById('freeHeap').textContent = `${data.freeHeap} bytes`;
        document.getElementById('minFreeHeap').textContent = `${data.minFreeHeap} bytes`;
        document.getElementById('apSsid').textContent = data.apSsid;
        document.getElementById('apIp').textContent = data.apIp;
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

void handleRoot()
{
    server.send(200, "text/html; charset=utf-8", htmlPage());
}

void handleStatus()
{
    String json;
    json.reserve(256);
    json += "{";
    json += "\"project\":\"";
    json += PROJECT_NAME;
    json += "\",\"version\":\"";
    json += PROJECT_VERSION;
    json += "\",\"phase\":\"";
    json += PROJECT_PHASE;
    json += "\",\"uptimeSeconds\":";
    json += uptimeSeconds();
    json += ",\"freeHeap\":";
    json += ESP.getFreeHeap();
    json += ",\"minFreeHeap\":";
    json += ESP.getMinFreeHeap();
    json += ",\"apSsid\":\"";
    json += AP_SSID;
    json += "\",\"apIp\":\"";
    json += WiFi.softAPIP().toString();
    json += "\",\"status\":\"ok\"";
    json += "}";

    server.send(200, "application/json", json);
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
    server.onNotFound(handleNotFound);
    server.begin();

    Serial.println("Servidor web iniciado na porta 80.");
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

    setupAccessPoint();
    setupWebServer();

    lastHeartbeatMs = millis();
}

void loop()
{
    server.handleClient();

    const unsigned long nowMs = millis();

    if (nowMs - lastHeartbeatMs >= HEARTBEAT_INTERVAL_MS) {
        lastHeartbeatMs = nowMs;
        Serial.print("Heartbeat Fase 1 | uptime=");
        Serial.print(uptimeSeconds());
        Serial.println("s");
    }

    vTaskDelay(pdMS_TO_TICKS(10));
}
