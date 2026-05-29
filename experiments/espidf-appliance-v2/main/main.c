#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "lwip/inet.h"
#include "lwip/lwip_napt.h"
#include "lwip/opt.h"
#include "nvs_flash.h"
#include "dhcpserver/dhcpserver.h"

#define AP_IP_A 192
#define AP_IP_B 168
#define AP_IP_C 4
#define AP_IP_D 1
#define DNS_PRIMARY_A 1
#define DNS_PRIMARY_B 1
#define DNS_PRIMARY_C 1
#define DNS_PRIMARY_D 1
#define DNS_BACKUP_A 8
#define DNS_BACKUP_B 8
#define DNS_BACKUP_C 8
#define DNS_BACKUP_D 8
#define STA_MAXIMUM_RETRY 8
#define EVENT_CAPACITY 32
#define EVENT_MESSAGE_LEN 128

typedef struct {
    uint32_t id;
    uint64_t uptime_ms;
    char time_label[16];
    char level[12];
    char source[16];
    char message[EVENT_MESSAGE_LEN];
} app_event_t;

typedef struct {
    uint64_t total;
    uint64_t root;
    uint64_t status;
    uint64_t api_status;
    uint64_t logs;
    uint64_t api_events;
    uint64_t traffic;
    uint64_t report;
    uint64_t not_found;
} traffic_counters_t;

static const char *TAG = "appliance_v2";
static esp_netif_t *ap_netif = NULL;
static esp_netif_t *sta_netif = NULL;
static httpd_handle_t http_server = NULL;
static SemaphoreHandle_t state_mutex = NULL;
static app_event_t events[EVENT_CAPACITY];
static uint32_t event_next_id = 1;
static uint32_t event_count = 0;
static uint32_t event_write_index = 0;
static traffic_counters_t traffic = {0};
static bool upstream_configured = false;
static bool upstream_connecting = false;
static bool upstream_connected = false;
static bool nat_attempted = false;
static bool nat_active = false;
static uint8_t last_disconnect_reason = 0;
static char upstream_ip[16] = "0.0.0.0";
static char upstream_gw[16] = "0.0.0.0";
static char upstream_netmask[16] = "0.0.0.0";

static uint64_t uptime_ms(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000ULL);
}

static void format_uptime_label(uint64_t ms, char *out, size_t out_len)
{
    uint64_t seconds = ms / 1000ULL;
    uint64_t hours = seconds / 3600ULL;
    uint64_t minutes = (seconds % 3600ULL) / 60ULL;
    uint64_t secs = seconds % 60ULL;
    snprintf(out, out_len, "%02llu:%02llu:%02llu",
             (unsigned long long)(hours % 100ULL),
             (unsigned long long)minutes,
             (unsigned long long)secs);
}

static void add_event(const char *level, const char *source, const char *fmt, ...)
{
    char message[EVENT_MESSAGE_LEN];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    if (state_mutex != NULL) {
        xSemaphoreTake(state_mutex, portMAX_DELAY);
    }

    app_event_t *slot = &events[event_write_index];
    slot->id = event_next_id++;
    slot->uptime_ms = uptime_ms();
    format_uptime_label(slot->uptime_ms, slot->time_label, sizeof(slot->time_label));
    strlcpy(slot->level, level, sizeof(slot->level));
    strlcpy(slot->source, source, sizeof(slot->source));
    strlcpy(slot->message, message, sizeof(slot->message));

    event_write_index = (event_write_index + 1U) % EVENT_CAPACITY;
    if (event_count < EVENT_CAPACITY) {
        event_count++;
    }

    if (state_mutex != NULL) {
        xSemaphoreGive(state_mutex);
    }

    ESP_LOGI(TAG, "[%s] %s: %s", level, source, message);
}

static bool is_upstream_configured(void)
{
    return strlen(APPLIANCE_V2_UPSTREAM_SSID) > 0 &&
           strcmp(APPLIANCE_V2_UPSTREAM_SSID, "YOUR_UPSTREAM_WIFI") != 0;
}

static const char *wifi_reason_description(uint8_t reason)
{
    switch (reason) {
    case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT:
        return "4-way handshake timeout";
    case WIFI_REASON_BEACON_TIMEOUT:
        return "beacon timeout";
    case WIFI_REASON_NO_AP_FOUND:
        return "no ap found";
    case WIFI_REASON_AUTH_FAIL:
        return "auth fail";
    case WIFI_REASON_ASSOC_FAIL:
        return "assoc fail";
    case WIFI_REASON_HANDSHAKE_TIMEOUT:
        return "handshake timeout";
    default:
        return "other";
    }
}

static void configure_ap_ip_and_dns(void)
{
    esp_netif_ip_info_t ip_info;
    IP4_ADDR(&ip_info.ip, AP_IP_A, AP_IP_B, AP_IP_C, AP_IP_D);
    IP4_ADDR(&ip_info.gw, AP_IP_A, AP_IP_B, AP_IP_C, AP_IP_D);
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);

    esp_netif_dns_info_t dns_primary = {
        .ip = ESP_IP4ADDR_INIT(DNS_PRIMARY_A, DNS_PRIMARY_B, DNS_PRIMARY_C, DNS_PRIMARY_D)
    };
    esp_netif_dns_info_t dns_backup = {
        .ip = ESP_IP4ADDR_INIT(DNS_BACKUP_A, DNS_BACKUP_B, DNS_BACKUP_C, DNS_BACKUP_D)
    };
    dhcps_offer_t dhcps_dns_offer = OFFER_DNS;

    ESP_ERROR_CHECK(esp_netif_dhcps_stop(ap_netif));
    ESP_ERROR_CHECK(esp_netif_set_ip_info(ap_netif, &ip_info));
    ESP_ERROR_CHECK(esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns_primary));
    ESP_ERROR_CHECK(esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_BACKUP, &dns_backup));
    ESP_ERROR_CHECK(esp_netif_dhcps_option(
        ap_netif,
        ESP_NETIF_OP_SET,
        ESP_NETIF_DOMAIN_NAME_SERVER,
        &dhcps_dns_offer,
        sizeof(dhcps_dns_offer)));
    ESP_ERROR_CHECK(esp_netif_dhcps_start(ap_netif));
}

static bool enable_napt_on_ap(void)
{
    nat_attempted = true;
#if IP_NAPT && IP_FORWARD
    esp_netif_ip_info_t ap_ip;
    ESP_ERROR_CHECK(esp_netif_get_ip_info(ap_netif, &ap_ip));
    ip_napt_enable(ap_ip.ip.addr, 1);
    nat_active = true;
    add_event("INFO", "nat", "NAPT enabled on AP %d.%d.%d.%d", AP_IP_A, AP_IP_B, AP_IP_C, AP_IP_D);
    return true;
#else
    nat_active = false;
    add_event("ERROR", "nat", "NAPT unavailable: IP_NAPT=%d IP_FORWARD=%d", IP_NAPT, IP_FORWARD);
    return false;
#endif
}

static uint16_t get_client_count(void)
{
    wifi_sta_list_t clients;
    if (esp_wifi_ap_get_sta_list(&clients) == ESP_OK) {
        return clients.num;
    }
    return 0;
}

static void increment_route_counter(const char *route)
{
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    traffic.total++;
    if (strcmp(route, "/") == 0) {
        traffic.root++;
    } else if (strcmp(route, "/status") == 0) {
        traffic.status++;
    } else if (strcmp(route, "/api/status") == 0) {
        traffic.api_status++;
    } else if (strcmp(route, "/logs") == 0) {
        traffic.logs++;
    } else if (strcmp(route, "/api/events") == 0) {
        traffic.api_events++;
    } else if (strcmp(route, "/traffic") == 0) {
        traffic.traffic++;
    } else if (strcmp(route, "/report") == 0) {
        traffic.report++;
    } else {
        traffic.not_found++;
    }
    xSemaphoreGive(state_mutex);
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)arg;
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        if (upstream_configured) {
            upstream_connecting = true;
            add_event("INFO", "wifi", "STA connecting to configured upstream SSID");
            esp_wifi_connect();
        } else {
            upstream_connecting = false;
            add_event("WARN", "wifi", "Upstream not configured; AP and dashboard remain available");
        }
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        upstream_connecting = true;
        add_event("INFO", "wifi", "STA associated with upstream");
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *event = (wifi_event_sta_disconnected_t *)event_data;
        last_disconnect_reason = event->reason;
        upstream_connected = false;
        upstream_connecting = false;
        nat_active = false;
        strlcpy(upstream_ip, "0.0.0.0", sizeof(upstream_ip));
        strlcpy(upstream_gw, "0.0.0.0", sizeof(upstream_gw));
        strlcpy(upstream_netmask, "0.0.0.0", sizeof(upstream_netmask));
        add_event("WARN", "wifi", "STA disconnected: reason=%u (%s)", event->reason, wifi_reason_description(event->reason));

        static uint8_t retry_count = 0;
        if (upstream_configured && retry_count < STA_MAXIMUM_RETRY) {
            retry_count++;
            upstream_connecting = true;
            add_event("INFO", "wifi", "STA reconnect attempt %u/%u", retry_count, STA_MAXIMUM_RETRY);
            esp_wifi_connect();
        }
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
        add_event("INFO", "ap", "Client connected: aid=%d", event->aid);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
        add_event("INFO", "ap", "Client disconnected: aid=%d", event->aid);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        upstream_connecting = false;
        upstream_connected = true;
        snprintf(upstream_ip, sizeof(upstream_ip), IPSTR, IP2STR(&event->ip_info.ip));
        snprintf(upstream_gw, sizeof(upstream_gw), IPSTR, IP2STR(&event->ip_info.gw));
        snprintf(upstream_netmask, sizeof(upstream_netmask), IPSTR, IP2STR(&event->ip_info.netmask));
        add_event("INFO", "wifi", "STA got IP %s", upstream_ip);
        enable_napt_on_ap();
    }
}

static void start_wifi_ap_sta(void)
{
    upstream_configured = is_upstream_configured();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    sta_netif = esp_netif_create_default_wifi_sta();
    ap_netif = esp_netif_create_default_wifi_ap();
    configure_ap_ip_and_dns();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t sta_config = {0};
    strlcpy((char *)sta_config.sta.ssid, APPLIANCE_V2_UPSTREAM_SSID, sizeof(sta_config.sta.ssid));
    strlcpy((char *)sta_config.sta.password, APPLIANCE_V2_UPSTREAM_PASSWORD, sizeof(sta_config.sta.password));
    sta_config.sta.threshold.authmode = WIFI_AUTH_OPEN;
    sta_config.sta.pmf_cfg.capable = true;
    sta_config.sta.pmf_cfg.required = false;

    wifi_config_t ap_config = {0};
    strlcpy((char *)ap_config.ap.ssid, APPLIANCE_V2_AP_SSID, sizeof(ap_config.ap.ssid));
    strlcpy((char *)ap_config.ap.password, APPLIANCE_V2_AP_PASSWORD, sizeof(ap_config.ap.password));
    ap_config.ap.ssid_len = strlen(APPLIANCE_V2_AP_SSID);
    ap_config.ap.channel = APPLIANCE_V2_AP_CHANNEL;
    ap_config.ap.max_connection = APPLIANCE_V2_AP_MAX_CLIENTS;
    ap_config.ap.authmode = strlen(APPLIANCE_V2_AP_PASSWORD) == 0 ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA_WPA2_PSK;
    ap_config.ap.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    add_event("INFO", "ap", "AP started: ssid=%s ip=%d.%d.%d.%d", APPLIANCE_V2_AP_SSID, AP_IP_A, AP_IP_B, AP_IP_C, AP_IP_D);
}

static esp_err_t send_text(httpd_req_t *req, const char *route, const char *text)
{
    increment_route_counter(route);
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    return httpd_resp_sendstr(req, text);
}

static esp_err_t root_handler(httpd_req_t *req)
{
    increment_route_counter("/");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_sendstr(req,
        "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>ESP-IDF Appliance v2</title><style>"
        "body{font-family:Arial,sans-serif;margin:0;background:#f6f7f9;color:#1f2933}"
        "header,main{max-width:1040px;margin:0 auto;padding:18px}"
        "header{border-bottom:1px solid #d8dee8;background:#fff}"
        "h1{font-size:24px;margin:0 0 6px}h2{font-size:18px;margin:0 0 12px}"
        ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}"
        ".card{background:#fff;border:1px solid #d8dee8;border-radius:6px;padding:14px}"
        ".value{font-size:22px;font-weight:700}.label{font-size:12px;color:#52606d;text-transform:uppercase}"
        "table{width:100%;border-collapse:collapse;background:#fff}td,th{padding:8px;border-bottom:1px solid #e4e7eb;text-align:left}"
        "code{background:#e4e7eb;padding:2px 4px;border-radius:4px}</style></head><body>"
        "<header><h1>ESP-IDF Appliance v2</h1><div>PoC isolada: AP+STA, NAPT real e dashboard mínimo.</div></header>"
        "<main><section class=\"grid\" id=\"cards\"></section><section class=\"card\"><h2>Eventos</h2><table><thead><tr><th>ID</th><th>Tempo</th><th>Nível</th><th>Origem</th><th>Mensagem</th></tr></thead><tbody id=\"events\"></tbody></table></section></main>"
        "<script>"
        "async function load(){const s=await fetch('/api/status').then(r=>r.json());"
        "document.getElementById('cards').innerHTML=["
        "['AP',s.ap.ssid+' / '+s.ap.ip],['Upstream',s.upstream.connected?s.upstream.ip:(s.upstream.configured?'conectando':'n/d')],"
        "['NAT',s.nat.active?'ativo':(s.nat.attempted?'falhou':'inativo')],['Clientes',s.clients.count],"
        "['Requests',s.traffic.total],['Eventos',s.event_count]"
        "].map(c=>'<div class=\"card\"><div class=\"label\">'+c[0]+'</div><div class=\"value\">'+c[1]+'</div></div>').join('');"
        "const e=await fetch('/api/events').then(r=>r.json());"
        "document.getElementById('events').innerHTML=e.events.map(x=>'<tr><td>'+x.id+'</td><td>'+x.time_label+'</td><td>'+x.level+'</td><td>'+x.source+'</td><td>'+x.message+'</td></tr>').join('');}"
        "load();setInterval(load,5000);</script></body></html>");
}

static esp_err_t status_handler(httpd_req_t *req)
{
    return send_text(req, "/status",
        "ESP-IDF Appliance v2\n"
        "Dashboard: /\n"
        "JSON: /api/status\n"
        "Eventos: /api/events\n");
}

static esp_err_t api_status_handler(httpd_req_t *req)
{
    increment_route_counter("/api/status");
    char *json = calloc(1, 4096);
    if (json == NULL) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no memory");
        return ESP_FAIL;
    }

    uint16_t clients = get_client_count();
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    traffic_counters_t traffic_snapshot = traffic;
    uint32_t event_count_snapshot = event_count;
    bool upstream_configured_snapshot = upstream_configured;
    bool upstream_connecting_snapshot = upstream_connecting;
    bool upstream_connected_snapshot = upstream_connected;
    bool nat_attempted_snapshot = nat_attempted;
    bool nat_active_snapshot = nat_active;
    uint8_t disconnect_snapshot = last_disconnect_reason;
    char ip_snapshot[16];
    char gw_snapshot[16];
    char netmask_snapshot[16];
    strlcpy(ip_snapshot, upstream_ip, sizeof(ip_snapshot));
    strlcpy(gw_snapshot, upstream_gw, sizeof(gw_snapshot));
    strlcpy(netmask_snapshot, upstream_netmask, sizeof(netmask_snapshot));
    xSemaphoreGive(state_mutex);

    snprintf(json, 4096,
        "{"
        "\"project\":\"%s\","
        "\"version\":\"%s\","
        "\"uptime_ms\":%llu,"
        "\"heap_free\":%lu,"
        "\"ap\":{\"ssid\":\"%s\",\"ip\":\"%d.%d.%d.%d\",\"channel\":%d,\"max_clients\":%d},"
        "\"upstream\":{\"configured\":%s,\"connecting\":%s,\"connected\":%s,\"ip\":\"%s\",\"gateway\":\"%s\",\"netmask\":\"%s\",\"last_disconnect_reason\":%u},"
        "\"nat\":{\"compiled\":%s,\"attempted\":%s,\"active\":%s},"
        "\"clients\":{\"count\":%u},"
        "\"traffic\":{\"total\":%llu,\"root\":%llu,\"status\":%llu,\"api_status\":%llu,\"logs\":%llu,\"api_events\":%llu,\"traffic\":%llu,\"report\":%llu,\"not_found\":%llu},"
        "\"event_count\":%lu,"
        "\"limitations\":[\"events_only_in_ram\",\"no_firewall_professional\",\"no_https_inspection\",\"nat_requires_sta_ip\"]"
        "}",
        APPLIANCE_V2_PROJECT,
        APPLIANCE_V2_VERSION,
        (unsigned long long)uptime_ms(),
        (unsigned long)esp_get_free_heap_size(),
        APPLIANCE_V2_AP_SSID,
        AP_IP_A, AP_IP_B, AP_IP_C, AP_IP_D,
        APPLIANCE_V2_AP_CHANNEL,
        APPLIANCE_V2_AP_MAX_CLIENTS,
        upstream_configured_snapshot ? "true" : "false",
        upstream_connecting_snapshot ? "true" : "false",
        upstream_connected_snapshot ? "true" : "false",
        ip_snapshot,
        gw_snapshot,
        netmask_snapshot,
        disconnect_snapshot,
#if IP_NAPT && IP_FORWARD
        "true",
#else
        "false",
#endif
        nat_attempted_snapshot ? "true" : "false",
        nat_active_snapshot ? "true" : "false",
        clients,
        (unsigned long long)traffic_snapshot.total,
        (unsigned long long)traffic_snapshot.root,
        (unsigned long long)traffic_snapshot.status,
        (unsigned long long)traffic_snapshot.api_status,
        (unsigned long long)traffic_snapshot.logs,
        (unsigned long long)traffic_snapshot.api_events,
        (unsigned long long)traffic_snapshot.traffic,
        (unsigned long long)traffic_snapshot.report,
        (unsigned long long)traffic_snapshot.not_found,
        (unsigned long)event_count_snapshot);

    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    free(json);
    return ret;
}

static esp_err_t api_events_handler(httpd_req_t *req)
{
    increment_route_counter("/api/events");
    char *json = calloc(1, 6144);
    if (json == NULL) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no memory");
        return ESP_FAIL;
    }

    size_t used = 0;
    used += snprintf(json + used, 6144 - used, "{\"events\":[");

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    uint32_t available = event_count;
    uint32_t start = (event_write_index + EVENT_CAPACITY - available) % EVENT_CAPACITY;
    for (uint32_t i = 0; i < available && used < 6000; i++) {
        app_event_t *event = &events[(start + i) % EVENT_CAPACITY];
        used += snprintf(json + used, 6144 - used,
            "%s{\"id\":%lu,\"uptime_ms\":%llu,\"time_label\":\"%s\",\"level\":\"%s\",\"source\":\"%s\",\"message\":\"%s\"}",
            i == 0 ? "" : ",",
            (unsigned long)event->id,
            (unsigned long long)event->uptime_ms,
            event->time_label,
            event->level,
            event->source,
            event->message);
    }
    xSemaphoreGive(state_mutex);

    snprintf(json + used, 6144 - used, "]}");
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    free(json);
    return ret;
}

static esp_err_t logs_handler(httpd_req_t *req)
{
    increment_route_counter("/logs");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_sendstr(req,
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Logs</title></head>"
        "<body><h1>Eventos em RAM</h1><pre id=\"out\">carregando...</pre>"
        "<script>fetch('/api/events').then(r=>r.json()).then(j=>out.textContent=JSON.stringify(j,null,2));</script></body></html>");
}

static esp_err_t traffic_handler(httpd_req_t *req)
{
    return send_text(req, "/traffic", "Contadores HTTP disponiveis em /api/status no objeto traffic.\n");
}

static esp_err_t report_handler(httpd_req_t *req)
{
    return send_text(req, "/report",
        "Relatorio minimo da PoC ESP-IDF Appliance v2\n"
        "- AP+STA ativo\n"
        "- NAT/NAPT habilitado somente apos IP do STA\n"
        "- Eventos em RAM\n"
        "- Dashboard minimo sem CDN\n"
        "- Limitacao: nao e firewall profissional\n");
}

static esp_err_t not_found_handler(httpd_req_t *req, httpd_err_code_t err)
{
    (void)err;
    increment_route_counter("not_found");
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
    return ESP_OK;
}

static void start_http_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;

    ESP_ERROR_CHECK(httpd_start(&http_server, &config));

    const httpd_uri_t routes[] = {
        {.uri = "/", .method = HTTP_GET, .handler = root_handler, .user_ctx = NULL},
        {.uri = "/status", .method = HTTP_GET, .handler = status_handler, .user_ctx = NULL},
        {.uri = "/api/status", .method = HTTP_GET, .handler = api_status_handler, .user_ctx = NULL},
        {.uri = "/logs", .method = HTTP_GET, .handler = logs_handler, .user_ctx = NULL},
        {.uri = "/api/events", .method = HTTP_GET, .handler = api_events_handler, .user_ctx = NULL},
        {.uri = "/traffic", .method = HTTP_GET, .handler = traffic_handler, .user_ctx = NULL},
        {.uri = "/report", .method = HTTP_GET, .handler = report_handler, .user_ctx = NULL},
    };

    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        ESP_ERROR_CHECK(httpd_register_uri_handler(http_server, &routes[i]));
    }
    httpd_register_err_handler(http_server, HTTPD_404_NOT_FOUND, not_found_handler);
    add_event("INFO", "http", "HTTP server started on port 80");
}

void app_main(void)
{
    state_mutex = xSemaphoreCreateMutex();
    ESP_ERROR_CHECK(state_mutex == NULL ? ESP_FAIL : ESP_OK);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    add_event("INFO", "boot", "ESP-IDF Appliance v2 starting");
    add_event("INFO", "build", "IP_NAPT=%d IP_FORWARD=%d", IP_NAPT, IP_FORWARD);

    start_wifi_ap_sta();
    start_http_server();

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
