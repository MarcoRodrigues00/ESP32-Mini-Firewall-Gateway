#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>

#include "config.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_sntp.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/inet.h"
#include "lwip/lwip_napt.h"
#include "lwip/opt.h"
#include "lwip/sockets.h"
#include "nvs_flash.h"
#include "dhcpserver/dhcpserver.h"

#define AP_IP_A 192
#define AP_IP_B 168
#define AP_IP_C 4
#define AP_IP_D 1
#define DNS_PRIMARY_A AP_IP_A
#define DNS_PRIMARY_B AP_IP_B
#define DNS_PRIMARY_C AP_IP_C
#define DNS_PRIMARY_D AP_IP_D
#define DNS_BACKUP_A AP_IP_A
#define DNS_BACKUP_B AP_IP_B
#define DNS_BACKUP_C AP_IP_C
#define DNS_BACKUP_D AP_IP_D
#define STA_MAXIMUM_RETRY 8
#define EVENT_CAPACITY 32
#define EVENT_MESSAGE_LEN 128
#define ROUTE_TRACK_CAPACITY 12
#define LAST_ROUTE_LEN 32
#define TIMESTAMP_LEN 32
#define DNS_RECENT_CAPACITY 16
#define DNS_DOMAIN_LEN 64
#define DNS_QUERY_TYPE_LEN 8
#define DNS_CLIENT_LEN 24
#define DNS_PACKET_MAX 512
#define DNS_PROXY_PORT 53

typedef struct {
    uint32_t id;
    uint64_t uptime_ms;
    char time_label[16];
    char timestamp[TIMESTAMP_LEN];
    bool time_synced;
    char level[12];
    char source[16];
    char message[EVENT_MESSAGE_LEN];
} app_event_t;

typedef struct {
    uint64_t total;
    uint64_t root;
    uint64_t status;
    uint64_t api;
    uint64_t api_status;
    uint64_t logs;
    uint64_t api_events;
    uint64_t traffic;
    uint64_t report;
    uint64_t demo;
    uint64_t demo_scan;
    uint64_t demo_security;
    uint64_t demo_info;
    uint64_t favicon;
    uint64_t not_found;
    uint64_t sensitive_path_hits;
    uint64_t suspicious_scan_count;
    uint64_t demo_scan_count;
    char last_route[LAST_ROUTE_LEN];
} traffic_counters_t;

typedef struct {
    char route[LAST_ROUTE_LEN];
    uint64_t count;
} route_stat_t;

typedef struct {
    uint32_t id;
    uint64_t uptime_ms;
    char time_label[16];
    char timestamp[TIMESTAMP_LEN];
    bool time_synced;
    char client[DNS_CLIENT_LEN];
    char domain[DNS_DOMAIN_LEN];
    char query_type[DNS_QUERY_TYPE_LEN];
    bool suspicious;
} dns_query_t;

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
static route_stat_t route_stats[ROUTE_TRACK_CAPACITY] = {0};
static dns_query_t dns_queries[DNS_RECENT_CAPACITY] = {0};
static uint32_t dns_query_count = 0;
static uint32_t dns_write_index = 0;
static uint32_t dns_next_id = 1;
static uint64_t dns_total_queries = 0;
static uint64_t suspicious_dns_count = 0;
static bool dns_monitoring_enabled = false;
static bool dns_first_observed = false;
static char dns_last_domain[DNS_DOMAIN_LEN] = "";
static char dns_last_client[DNS_CLIENT_LEN] = "";
static char dns_last_query_type[DNS_QUERY_TYPE_LEN] = "";
static volatile bool time_synchronized = false;
static bool sntp_started = false;
static char last_timestamp[TIMESTAMP_LEN] = "unsynced";
static const char *TIMEZONE_LABEL = "America/Sao_Paulo";
static bool upstream_configured = false;
static bool upstream_connecting = false;
static bool upstream_connected = false;
static bool nat_attempted = false;
static bool nat_active = false;
static uint8_t last_disconnect_reason = 0;
static char upstream_ip[16] = "0.0.0.0";
static char upstream_gw[16] = "0.0.0.0";
static char upstream_netmask[16] = "0.0.0.0";

static const char *html_style =
    "body{font-family:Arial,sans-serif;margin:0;background:#f5f7fa;color:#17202a}"
    "header,main{max-width:1120px;margin:0 auto;padding:18px}"
    "header{background:#fff;border-bottom:1px solid #d9e2ec}"
    "nav{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}"
    "nav a{color:#0b5cad;text-decoration:none;border:1px solid #bcccdc;border-radius:6px;padding:7px 10px;background:#fff}"
    "h1{font-size:26px;margin:0 0 6px}h2{font-size:18px;margin:0 0 12px}"
    ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;margin:16px 0}"
    ".card{background:#fff;border:1px solid #d9e2ec;border-radius:6px;padding:14px}"
    ".value{font-size:22px;font-weight:700;overflow-wrap:anywhere}.label{font-size:12px;color:#52606d;text-transform:uppercase}"
    ".ok{color:#0b6b3a}.warn{color:#9a6700}.bad{color:#a61b1b}"
    "table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #d9e2ec}"
    "td,th{padding:8px;border-bottom:1px solid #e4e7eb;text-align:left;font-size:14px}"
    "code{background:#e4e7eb;padding:2px 4px;border-radius:4px}pre{white-space:pre-wrap;background:#fff;border:1px solid #d9e2ec;padding:12px}";

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

static bool format_current_timestamp(char *out, size_t out_len)
{
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);
    if (timeinfo.tm_year < (2023 - 1900)) {
        strlcpy(out, "unsynced", out_len);
        return false;
    }
    strftime(out, out_len, "%Y-%m-%d %H:%M:%S %Z", &timeinfo);
    return true;
}

static void snapshot_time(char *timestamp, size_t timestamp_len, bool *synced)
{
    bool ok = time_synchronized && format_current_timestamp(timestamp, timestamp_len);
    if (!ok) {
        strlcpy(timestamp, "unsynced", timestamp_len);
    }
    if (synced != NULL) {
        *synced = ok;
    }
}

static void json_escape_string(const char *in, char *out, size_t out_len)
{
    size_t pos = 0;
    if (out_len == 0) {
        return;
    }
    for (size_t i = 0; in[i] != '\0' && pos + 1 < out_len; i++) {
        unsigned char c = (unsigned char)in[i];
        if ((c == '"' || c == '\\') && pos + 2 < out_len) {
            out[pos++] = '\\';
            out[pos++] = (char)c;
        } else if (c < 0x20) {
            out[pos++] = ' ';
        } else {
            out[pos++] = (char)c;
        }
    }
    out[pos] = '\0';
}

static void add_event(const char *level, const char *source, const char *fmt, ...)
{
    char message[EVENT_MESSAGE_LEN];
    va_list args;
    va_start(args, fmt);
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);
    for (size_t i = 0; message[i] != '\0'; i++) {
        if (message[i] == '"' || message[i] == '\\') {
            message[i] = '\'';
        }
    }

    char timestamp[TIMESTAMP_LEN];
    bool synced = false;
    snapshot_time(timestamp, sizeof(timestamp), &synced);

    if (state_mutex != NULL) {
        xSemaphoreTake(state_mutex, portMAX_DELAY);
    }

    app_event_t *slot = &events[event_write_index];
    slot->id = event_next_id++;
    slot->uptime_ms = uptime_ms();
    format_uptime_label(slot->uptime_ms, slot->time_label, sizeof(slot->time_label));
    strlcpy(slot->timestamp, timestamp, sizeof(slot->timestamp));
    slot->time_synced = synced;
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

static bool is_sensitive_path(const char *route)
{
    return strcmp(route, "/admin") == 0 ||
           strcmp(route, "/login") == 0 ||
           strcmp(route, "/wp-admin") == 0 ||
           strcmp(route, "/etc/passwd") == 0 ||
           strcmp(route, "/api") == 0 ||
           strcmp(route, "/config") == 0 ||
           strcmp(route, "/debug") == 0;
}

static bool is_scan_like_path(const char *route)
{
    return strcmp(route, "/wp-admin") == 0 ||
           strcmp(route, "/etc/passwd") == 0 ||
           strcmp(route, "/config") == 0 ||
           strcmp(route, "/debug") == 0;
}

static void update_top_routes_locked(const char *route)
{
    uint32_t empty_index = ROUTE_TRACK_CAPACITY;
    uint32_t min_index = 0;
    uint64_t min_count = UINT64_MAX;

    for (uint32_t i = 0; i < ROUTE_TRACK_CAPACITY; i++) {
        if (route_stats[i].count > 0 && strcmp(route_stats[i].route, route) == 0) {
            route_stats[i].count++;
            return;
        }
        if (route_stats[i].count == 0 && empty_index == ROUTE_TRACK_CAPACITY) {
            empty_index = i;
        }
        if (route_stats[i].count < min_count) {
            min_count = route_stats[i].count;
            min_index = i;
        }
    }

    uint32_t target = empty_index == ROUTE_TRACK_CAPACITY ? min_index : empty_index;
    strlcpy(route_stats[target].route, route, sizeof(route_stats[target].route));
    route_stats[target].count = 1;
}

static void increment_route_counter(const char *route)
{
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    traffic.total++;
    strlcpy(traffic.last_route, route, sizeof(traffic.last_route));
    update_top_routes_locked(route);

    if (strcmp(route, "/") == 0) {
        traffic.root++;
    } else if (strcmp(route, "/status") == 0) {
        traffic.status++;
    } else if (strcmp(route, "/api") == 0) {
        traffic.api++;
    } else if (strcmp(route, "/api/status") == 0) {
        traffic.api_status++;
    } else if (strcmp(route, "/logs") == 0) {
        traffic.logs++;
    } else if (strcmp(route, "/api/events") == 0) {
        traffic.api_events++;
    } else if (strcmp(route, "/api/dns") == 0 || strcmp(route, "/dns") == 0) {
        traffic.api++;
    } else if (strcmp(route, "/traffic") == 0) {
        traffic.traffic++;
    } else if (strcmp(route, "/report") == 0) {
        traffic.report++;
    } else if (strcmp(route, "/demo") == 0) {
        traffic.demo++;
    } else if (strcmp(route, "/demo/scan") == 0) {
        traffic.demo_scan++;
        traffic.demo_scan_count++;
    } else if (strcmp(route, "/demo/security") == 0) {
        traffic.demo_security++;
    } else if (strcmp(route, "/demo/info") == 0) {
        traffic.demo_info++;
    } else if (strcmp(route, "/favicon.ico") == 0) {
        traffic.favicon++;
    } else {
        traffic.not_found++;
    }
    if (is_sensitive_path(route)) {
        traffic.sensitive_path_hits++;
    }
    if (is_scan_like_path(route)) {
        traffic.suspicious_scan_count++;
    }
    xSemaphoreGive(state_mutex);
}

static void request_client_ip(httpd_req_t *req, char *out, size_t out_len)
{
    strlcpy(out, "n/d", out_len);
    int sockfd = httpd_req_to_sockfd(req);
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    if (sockfd >= 0 && getpeername(sockfd, (struct sockaddr *)&addr, &addr_len) == 0 &&
        addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &s->sin_addr, out, out_len);
    }
}

static void log_http_event(httpd_req_t *req, const char *route, const char *level, const char *note)
{
    char ip[24];
    char agent[64] = "n/d";
    request_client_ip(req, ip, sizeof(ip));
    if (httpd_req_get_hdr_value_str(req, "User-Agent", agent, sizeof(agent)) != ESP_OK) {
        strlcpy(agent, "n/d", sizeof(agent));
    }
    add_event(level, "http", "GET %s from %s ua=%s %s", route, ip, agent, note);
}

static void sntp_sync_callback(struct timeval *tv)
{
    (void)tv;
    time_synchronized = true;
    snapshot_time(last_timestamp, sizeof(last_timestamp), NULL);
    add_event("INFO", "time", "SNTP synchronized: %s", last_timestamp);
}

static void start_sntp_sync(void)
{
    if (sntp_started) {
        return;
    }
    setenv("TZ", "BRT3", 1);
    tzset();
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_setservername(1, "time.google.com");
    esp_sntp_set_time_sync_notification_cb(sntp_sync_callback);
    esp_sntp_init();
    sntp_started = true;
    add_event("INFO", "time", "SNTP started: pool.ntp.org timezone=%s", TIMEZONE_LABEL);
}

static const char *dns_query_type_label(uint16_t qtype)
{
    switch (qtype) {
    case 1:
        return "A";
    case 28:
        return "AAAA";
    default:
        return "OTHER";
    }
}

static bool is_suspicious_domain(const char *domain)
{
    return strcasecmp(domain, "malware.test") == 0 ||
           strcasecmp(domain, "phishing.test") == 0 ||
           strcasecmp(domain, "suspicious.test") == 0 ||
           strcasecmp(domain, "bad.example") == 0;
}

static bool parse_dns_query(const uint8_t *packet, ssize_t len, char *domain, size_t domain_len, uint16_t *qtype)
{
    if (len < 17 || domain_len == 0) {
        return false;
    }
    uint16_t qdcount = ((uint16_t)packet[4] << 8) | packet[5];
    if (qdcount == 0) {
        return false;
    }

    size_t pos = 12;
    size_t out = 0;
    while (pos < (size_t)len) {
        uint8_t label_len = packet[pos++];
        if (label_len == 0) {
            break;
        }
        if ((label_len & 0xC0) != 0 || label_len > 63 || pos + label_len > (size_t)len) {
            return false;
        }
        if (out > 0 && out + 1 < domain_len) {
            domain[out++] = '.';
        }
        for (uint8_t i = 0; i < label_len && out + 1 < domain_len; i++) {
            char c = (char)packet[pos + i];
            domain[out++] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
        }
        pos += label_len;
    }
    domain[out] = '\0';
    if (domain[0] == '\0' || pos + 4 > (size_t)len) {
        return false;
    }
    *qtype = ((uint16_t)packet[pos] << 8) | packet[pos + 1];
    return true;
}

static void record_dns_query(const char *client, const char *domain, const char *query_type)
{
    char timestamp[TIMESTAMP_LEN];
    char label[16];
    bool synced = false;
    bool suspicious = is_suspicious_domain(domain);
    bool first_observed = false;
    uint64_t total_after = 0;
    uint64_t suspicious_after = 0;
    uint64_t now_ms = uptime_ms();
    snapshot_time(timestamp, sizeof(timestamp), &synced);
    format_uptime_label(now_ms, label, sizeof(label));

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    if (!dns_first_observed) {
        dns_first_observed = true;
        first_observed = true;
    }
    dns_total_queries++;
    total_after = dns_total_queries;
    if (suspicious) {
        suspicious_dns_count++;
        suspicious_after = suspicious_dns_count;
    }
    strlcpy(dns_last_domain, domain, sizeof(dns_last_domain));
    strlcpy(dns_last_client, client, sizeof(dns_last_client));
    strlcpy(dns_last_query_type, query_type, sizeof(dns_last_query_type));

    dns_query_t *slot = &dns_queries[dns_write_index];
    slot->id = dns_next_id++;
    slot->uptime_ms = now_ms;
    strlcpy(slot->time_label, label, sizeof(slot->time_label));
    strlcpy(slot->timestamp, timestamp, sizeof(slot->timestamp));
    slot->time_synced = synced;
    strlcpy(slot->client, client, sizeof(slot->client));
    strlcpy(slot->domain, domain, sizeof(slot->domain));
    strlcpy(slot->query_type, query_type, sizeof(slot->query_type));
    slot->suspicious = suspicious;
    dns_write_index = (dns_write_index + 1U) % DNS_RECENT_CAPACITY;
    if (dns_query_count < DNS_RECENT_CAPACITY) {
        dns_query_count++;
    }
    xSemaphoreGive(state_mutex);

    if (first_observed) {
        add_event("INFO", "dns", "First DNS query observed: %s from %s type=%s", domain, client, query_type);
    }
    if (suspicious) {
        add_event("SECURITY", "dns", "Suspicious DNS domain=%s client=%s type=%s total=%llu suspicious=%llu",
                  domain, client, query_type,
                  (unsigned long long)total_after,
                  (unsigned long long)suspicious_after);
    }
}

static int forward_dns_once(const uint8_t *query, ssize_t query_len, uint8_t *response, size_t response_len, const char *server_ip)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        return -1;
    }
    struct timeval timeout = {.tv_sec = 1, .tv_usec = 200000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in upstream = {0};
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons(53);
    inet_pton(AF_INET, server_ip, &upstream.sin_addr);

    int sent = sendto(sock, query, query_len, 0, (struct sockaddr *)&upstream, sizeof(upstream));
    if (sent < 0) {
        close(sock);
        return -1;
    }
    int received = recvfrom(sock, response, response_len, 0, NULL, NULL);
    close(sock);
    return received;
}

static void dns_proxy_task(void *arg)
{
    (void)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        add_event("ERROR", "dns", "DNS proxy socket creation failed");
        vTaskDelete(NULL);
        return;
    }

    struct sockaddr_in listen_addr = {0};
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    listen_addr.sin_port = htons(DNS_PROXY_PORT);
    if (bind(sock, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        add_event("ERROR", "dns", "DNS proxy bind failed on UDP port %d", DNS_PROXY_PORT);
        close(sock);
        vTaskDelete(NULL);
        return;
    }

    dns_monitoring_enabled = true;
    add_event("INFO", "dns", "DNS monitor/proxy started on UDP port %d", DNS_PROXY_PORT);

    while (true) {
        uint8_t query[DNS_PACKET_MAX];
        uint8_t response[DNS_PACKET_MAX];
        struct sockaddr_in client_addr = {0};
        socklen_t client_len = sizeof(client_addr);
        ssize_t len = recvfrom(sock, query, sizeof(query), 0, (struct sockaddr *)&client_addr, &client_len);
        if (len <= 0) {
            continue;
        }

        char client_ip[DNS_CLIENT_LEN] = "n/d";
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        char domain[DNS_DOMAIN_LEN] = "";
        uint16_t qtype = 0;
        if (parse_dns_query(query, len, domain, sizeof(domain), &qtype) && (qtype == 1 || qtype == 28)) {
            record_dns_query(client_ip, domain, dns_query_type_label(qtype));
        }

        int resp_len = forward_dns_once(query, len, response, sizeof(response), "1.1.1.1");
        if (resp_len <= 0) {
            resp_len = forward_dns_once(query, len, response, sizeof(response), "8.8.8.8");
        }
        if (resp_len > 0) {
            sendto(sock, response, resp_len, 0, (struct sockaddr *)&client_addr, client_len);
        }
    }
}

static void start_dns_proxy(void)
{
    xTaskCreatePinnedToCore(dns_proxy_task, "dnsProxy", 4096, NULL, 4, NULL, 0);
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
        start_sntp_sync();
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

static esp_err_t send_html(httpd_req_t *req, const char *route, const char *html)
{
    increment_route_counter(route);
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_sendstr(req, html);
}

static esp_err_t root_handler(httpd_req_t *req)
{
    increment_route_counter("/");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr_chunk(req,
        "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>ESP-IDF Appliance v2</title><style>");
    httpd_resp_sendstr_chunk(req, html_style);
    httpd_resp_sendstr_chunk(req,
        "</style></head><body>"
        "<header><h1>ESP-IDF Appliance v2</h1><div>Mini appliance demonstrável: AP+STA, NAPT, IDS didático e telemetria HTTP.</div>"
        "<nav><a href=\"/\">Dashboard</a><a href=\"/traffic\">Traffic</a><a href=\"/logs\">Logs</a><a href=\"/dns\">DNS</a><a href=\"/report\">Report</a><a href=\"/demo\">Demo</a><a href=\"/api\">API</a></nav></header>"
        "<main><section class=\"grid\" id=\"cards\"></section>"
        "<section class=\"card\"><h2>Rotas mais acessadas</h2><table><thead><tr><th>Rota</th><th>Hits</th></tr></thead><tbody id=\"routes\"></tbody></table></section>"
        "<section class=\"card\"><h2>Eventos recentes</h2><table><thead><tr><th>ID</th><th>Horário</th><th>Uptime</th><th>Nível</th><th>Origem</th><th>Mensagem</th></tr></thead><tbody id=\"events\"></tbody></table></section></main>"
        "<script>"
        "function escapeHtml(v){return String(v==null?'':v).replace(/[&<>\"']/g,function(c){return c==='&'?'&amp;':c==='<'?'&lt;':c==='>'?'&gt;':c==='\"'?'&quot;':'&#39;';});}"
        "function card(label,value){return '<div class=\"card\"><div class=\"label\">'+escapeHtml(label)+'</div><div class=\"value\">'+escapeHtml(value)+'</div></div>'; }"
        "function routeRow(x){return '<tr><td><code>'+escapeHtml(x.route)+'</code></td><td>'+Number(x.count||0)+'</td></tr>'; }"
        "function eventRow(x){return '<tr><td>'+Number(x.id||0)+'</td><td>'+escapeHtml(x.time_synced?x.timestamp:'unsynced')+'</td><td>'+escapeHtml(x.time_label)+'</td><td>'+escapeHtml(x.level)+'</td><td>'+escapeHtml(x.source)+'</td><td>'+escapeHtml(x.message)+'</td></tr>'; }"
        "async function load(){const s=await fetch('/api/status').then(r=>r.json());"
        "document.getElementById('cards').innerHTML=["
        "['AP',s.ap.ssid+' / '+s.ap.ip],['Upstream',s.upstream.connected?s.upstream.ip:(s.upstream.configured?'conectando':'n/d')],"
        "['NAT',s.nat.active?'ativo':(s.nat.attempted?'falhou':'inativo')],['Clientes',s.clients.count],"
        "['Requests',s.traffic.total],['DNS queries',s.dns.total_queries],['Último domínio',s.dns.last_domain||'n/d'],['Horário',s.time.synced?s.time.timestamp:'unsynced'],['404',s.traffic.not_found],['Sensitive',s.traffic.sensitive_path_hits],['Scan',s.traffic.suspicious_scan_count],['Heap',s.heap_free],['Última rota',s.traffic.last_route]"
        "].map(c=>card(c[0],c[1])).join('');"
        "document.getElementById('routes').innerHTML=(s.traffic.top_routes||[]).map(routeRow).join('');"
        "const e=await fetch('/api/events').then(r=>r.json());"
        "document.getElementById('events').innerHTML=(e.events||[]).map(eventRow).join('');}"
        "load();setInterval(load,5000);</script></body></html>");
    return httpd_resp_sendstr_chunk(req, NULL);
}

static esp_err_t status_handler(httpd_req_t *req)
{
    return send_text(req, "/status",
        "ESP-IDF Appliance v2\n"
        "Dashboard: /\n"
        "JSON: /api/status\n"
        "Eventos: /api/events\n"
        "DNS: /dns e /api/dns\n");
}

static esp_err_t api_status_handler(httpd_req_t *req)
{
    increment_route_counter("/api/status");
    char *json = calloc(1, 12288);
    if (json == NULL) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no memory");
        return ESP_FAIL;
    }

    uint16_t clients = get_client_count();
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    traffic_counters_t traffic_snapshot = traffic;
    route_stat_t route_snapshot[ROUTE_TRACK_CAPACITY];
    memcpy(route_snapshot, route_stats, sizeof(route_snapshot));
    uint64_t dns_total_snapshot = dns_total_queries;
    uint64_t suspicious_dns_snapshot = suspicious_dns_count;
    bool dns_enabled_snapshot = dns_monitoring_enabled;
    char dns_domain_snapshot[DNS_DOMAIN_LEN];
    char dns_client_snapshot[DNS_CLIENT_LEN];
    char dns_type_snapshot[DNS_QUERY_TYPE_LEN];
    strlcpy(dns_domain_snapshot, dns_last_domain, sizeof(dns_domain_snapshot));
    strlcpy(dns_client_snapshot, dns_last_client, sizeof(dns_client_snapshot));
    strlcpy(dns_type_snapshot, dns_last_query_type, sizeof(dns_type_snapshot));
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

    char project_json[64];
    char version_json[24];
    char ap_ssid_json[40];
    char last_route_json[LAST_ROUTE_LEN * 2];
    char time_json[TIMESTAMP_LEN * 2];
    char dns_domain_json[DNS_DOMAIN_LEN * 2];
    char dns_client_json[DNS_CLIENT_LEN * 2];
    char dns_type_json[DNS_QUERY_TYPE_LEN * 2];
    char current_timestamp[TIMESTAMP_LEN];
    bool current_time_synced = false;
    snapshot_time(current_timestamp, sizeof(current_timestamp), &current_time_synced);
    json_escape_string(APPLIANCE_V2_PROJECT, project_json, sizeof(project_json));
    json_escape_string(APPLIANCE_V2_VERSION, version_json, sizeof(version_json));
    json_escape_string(APPLIANCE_V2_AP_SSID, ap_ssid_json, sizeof(ap_ssid_json));
    json_escape_string(traffic_snapshot.last_route, last_route_json, sizeof(last_route_json));
    json_escape_string(current_timestamp, time_json, sizeof(time_json));
    json_escape_string(dns_domain_snapshot, dns_domain_json, sizeof(dns_domain_json));
    json_escape_string(dns_client_snapshot, dns_client_json, sizeof(dns_client_json));
    json_escape_string(dns_type_snapshot, dns_type_json, sizeof(dns_type_json));

    size_t used = snprintf(json, 12288,
        "{"
        "\"project\":\"%s\","
        "\"version\":\"%s\","
        "\"uptime_ms\":%llu,"
        "\"time\":{\"synced\":%s,\"timestamp\":\"%s\",\"uptime_ms\":%llu,\"timezone\":\"%s\"},"
        "\"heap_free\":%lu,"
        "\"heap_minimum_free\":%lu,"
        "\"ap\":{\"ssid\":\"%s\",\"ip\":\"%d.%d.%d.%d\",\"channel\":%d,\"max_clients\":%d},"
        "\"upstream\":{\"configured\":%s,\"connecting\":%s,\"connected\":%s,\"ip\":\"%s\",\"gateway\":\"%s\",\"netmask\":\"%s\",\"last_disconnect_reason\":%u},"
        "\"nat\":{\"compiled\":%s,\"attempted\":%s,\"active\":%s},"
        "\"clients\":{\"count\":%u},"
        "\"dns\":{\"monitoring_enabled\":%s,\"total_queries\":%llu,\"suspicious_count\":%llu,\"last_domain\":\"%s\",\"last_client\":\"%s\",\"last_query_type\":\"%s\"},"
        "\"traffic\":{\"total\":%llu,\"root\":%llu,\"status\":%llu,\"api\":%llu,\"api_status\":%llu,\"logs\":%llu,\"api_events\":%llu,\"traffic\":%llu,\"report\":%llu,\"demo\":%llu,\"demo_scan\":%llu,\"demo_security\":%llu,\"demo_info\":%llu,\"favicon\":%llu,\"not_found\":%llu,\"sensitive_path_hits\":%llu,\"suspicious_scan_count\":%llu,\"demo_scan_count\":%llu,\"last_route\":\"%s\",\"top_routes\":[",
        project_json,
        version_json,
        (unsigned long long)uptime_ms(),
        current_time_synced ? "true" : "false",
        time_json,
        (unsigned long long)uptime_ms(),
        TIMEZONE_LABEL,
        (unsigned long)esp_get_free_heap_size(),
        (unsigned long)esp_get_minimum_free_heap_size(),
        ap_ssid_json,
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
        dns_enabled_snapshot ? "true" : "false",
        (unsigned long long)dns_total_snapshot,
        (unsigned long long)suspicious_dns_snapshot,
        dns_domain_json,
        dns_client_json,
        dns_type_json,
        (unsigned long long)traffic_snapshot.total,
        (unsigned long long)traffic_snapshot.root,
        (unsigned long long)traffic_snapshot.status,
        (unsigned long long)traffic_snapshot.api,
        (unsigned long long)traffic_snapshot.api_status,
        (unsigned long long)traffic_snapshot.logs,
        (unsigned long long)traffic_snapshot.api_events,
        (unsigned long long)traffic_snapshot.traffic,
        (unsigned long long)traffic_snapshot.report,
        (unsigned long long)traffic_snapshot.demo,
        (unsigned long long)traffic_snapshot.demo_scan,
        (unsigned long long)traffic_snapshot.demo_security,
        (unsigned long long)traffic_snapshot.demo_info,
        (unsigned long long)traffic_snapshot.favicon,
        (unsigned long long)traffic_snapshot.not_found,
        (unsigned long long)traffic_snapshot.sensitive_path_hits,
        (unsigned long long)traffic_snapshot.suspicious_scan_count,
        (unsigned long long)traffic_snapshot.demo_scan_count,
        last_route_json);

    bool first = true;
    for (uint32_t i = 0; i < ROUTE_TRACK_CAPACITY && used < 11800; i++) {
        if (route_snapshot[i].count == 0) {
            continue;
        }
        char route_json[LAST_ROUTE_LEN * 2];
        json_escape_string(route_snapshot[i].route, route_json, sizeof(route_json));
        used += snprintf(json + used, 12288 - used,
            "%s{\"route\":\"%s\",\"count\":%llu}",
            first ? "" : ",",
            route_json,
            (unsigned long long)route_snapshot[i].count);
        first = false;
    }
    snprintf(json + used, 12288 - used,
        "]},\"event_count\":%lu,"
        "\"limits\":{\"events_capacity\":%d,\"route_track_capacity\":%d},"
        "\"limitations\":[\"events_only_in_ram\",\"no_firewall_professional\",\"no_https_inspection\",\"nat_requires_sta_ip\"]}",
        (unsigned long)event_count_snapshot,
        EVENT_CAPACITY,
        ROUTE_TRACK_CAPACITY);

    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    free(json);
    return ret;
}

static esp_err_t api_events_handler(httpd_req_t *req)
{
    increment_route_counter("/api/events");
    char *json = calloc(1, 8192);
    if (json == NULL) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no memory");
        return ESP_FAIL;
    }

    size_t used = 0;
    used += snprintf(json + used, 8192 - used, "{\"events\":[");

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    uint32_t available = event_count;
    uint32_t start = (event_write_index + EVENT_CAPACITY - available) % EVENT_CAPACITY;
    for (uint32_t i = 0; i < available && used < 8000; i++) {
        app_event_t *event = &events[(start + i) % EVENT_CAPACITY];
        used += snprintf(json + used, 8192 - used,
            "%s{\"id\":%lu,\"uptime_ms\":%llu,\"time_label\":\"%s\",\"timestamp\":\"%s\",\"time_synced\":%s,\"level\":\"%s\",\"source\":\"%s\",\"message\":\"%s\"}",
            i == 0 ? "" : ",",
            (unsigned long)event->id,
            (unsigned long long)event->uptime_ms,
            event->time_label,
            event->timestamp,
            event->time_synced ? "true" : "false",
            event->level,
            event->source,
            event->message);
    }
    xSemaphoreGive(state_mutex);

    snprintf(json + used, 8192 - used, "]}");
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    free(json);
    return ret;
}

static esp_err_t api_dns_handler(httpd_req_t *req)
{
    increment_route_counter("/api/dns");
    char *json = calloc(1, 8192);
    if (json == NULL) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no memory");
        return ESP_FAIL;
    }

    dns_query_t snapshot[DNS_RECENT_CAPACITY];
    uint32_t count_snapshot;
    uint32_t write_snapshot;
    uint64_t total_snapshot;
    uint64_t suspicious_snapshot;
    bool enabled_snapshot;

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    memcpy(snapshot, dns_queries, sizeof(snapshot));
    count_snapshot = dns_query_count;
    write_snapshot = dns_write_index;
    total_snapshot = dns_total_queries;
    suspicious_snapshot = suspicious_dns_count;
    enabled_snapshot = dns_monitoring_enabled;
    xSemaphoreGive(state_mutex);

    size_t used = snprintf(json, 8192,
        "{\"monitoring_enabled\":%s,\"total_queries\":%llu,\"suspicious_count\":%llu,\"recent_queries\":[",
        enabled_snapshot ? "true" : "false",
        (unsigned long long)total_snapshot,
        (unsigned long long)suspicious_snapshot);

    uint32_t start = (write_snapshot + DNS_RECENT_CAPACITY - count_snapshot) % DNS_RECENT_CAPACITY;
    for (uint32_t i = 0; i < count_snapshot && used < 7800; i++) {
        dns_query_t *q = &snapshot[(start + i) % DNS_RECENT_CAPACITY];
        char client_json[DNS_CLIENT_LEN * 2];
        char domain_json[DNS_DOMAIN_LEN * 2];
        char type_json[DNS_QUERY_TYPE_LEN * 2];
        char timestamp_json[TIMESTAMP_LEN * 2];
        json_escape_string(q->client, client_json, sizeof(client_json));
        json_escape_string(q->domain, domain_json, sizeof(domain_json));
        json_escape_string(q->query_type, type_json, sizeof(type_json));
        json_escape_string(q->timestamp, timestamp_json, sizeof(timestamp_json));
        used += snprintf(json + used, 8192 - used,
            "%s{\"id\":%lu,\"uptime_ms\":%llu,\"time_label\":\"%s\",\"timestamp\":\"%s\",\"time_synced\":%s,\"client_ip\":\"%s\",\"domain\":\"%s\",\"query_type\":\"%s\",\"suspicious\":%s}",
            i == 0 ? "" : ",",
            (unsigned long)q->id,
            (unsigned long long)q->uptime_ms,
            q->time_label,
            timestamp_json,
            q->time_synced ? "true" : "false",
            client_json,
            domain_json,
            type_json,
            q->suspicious ? "true" : "false");
    }

    snprintf(json + used, 8192 - used,
        "],\"limitations\":[\"dns_queries_only\",\"no_https_content_inspection\",\"a_aaaa_queries_recorded\",\"best_effort_udp_proxy\",\"ram_only\"]}");
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    free(json);
    return ret;
}

static esp_err_t dns_handler(httpd_req_t *req)
{
    increment_route_counter("/dns");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr_chunk(req, "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>DNS</title><style>");
    httpd_resp_sendstr_chunk(req, html_style);
    httpd_resp_sendstr_chunk(req,
        "</style></head><body><header><h1>DNS</h1><div>Monitor didático de consultas DNS dos clientes do AP.</div>"
        "<nav><a href=\"/\">Dashboard</a><a href=\"/traffic\">Traffic</a><a href=\"/logs\">Logs</a><a href=\"/report\">Report</a><a href=\"/api/dns\">JSON</a></nav></header>"
        "<main><section class=\"grid\" id=\"cards\"></section><section class=\"card\"><h2>Consultas recentes</h2><table><thead><tr><th>Horário</th><th>Uptime</th><th>Cliente</th><th>Domínio</th><th>Tipo</th><th>Status</th></tr></thead><tbody id=\"queries\"></tbody></table></section>"
        "<section class=\"card\"><p>Este monitor mostra consultas DNS. HTTPS continua criptografado e o conteúdo das páginas não é lido.</p></section></main>"
        "<script>function escapeHtml(v){return String(v==null?'':v).replace(/[&<>\"']/g,function(c){return c==='&'?'&amp;':c==='<'?'&lt;':c==='>'?'&gt;':c==='\"'?'&quot;':'&#39;';});}"
        "function card(label,value){return '<div class=\"card\"><div class=\"label\">'+escapeHtml(label)+'</div><div class=\"value\">'+escapeHtml(value)+'</div></div>'; }"
        "function row(x){return '<tr><td>'+escapeHtml(x.time_synced?x.timestamp:'unsynced')+'</td><td>'+escapeHtml(x.time_label)+'</td><td>'+escapeHtml(x.client_ip)+'</td><td><code>'+escapeHtml(x.domain)+'</code></td><td>'+escapeHtml(x.query_type)+'</td><td>'+(x.suspicious?'SECURITY':'ok')+'</td></tr>'; }"
        "async function load(){const d=await fetch('/api/dns').then(r=>r.json());const recent=d.recent_queries||[];const last=recent.length?recent[recent.length-1]:{};cards.innerHTML=[['DNS queries',d.total_queries],['DNS suspeito',d.suspicious_count],['Último domínio',last.domain||'n/d'],['Último cliente',last.client_ip||'n/d']].map(c=>card(c[0],c[1])).join('');queries.innerHTML=recent.map(row).join('');}load();setInterval(load,5000);</script></body></html>");
    return httpd_resp_sendstr_chunk(req, NULL);
}

static esp_err_t logs_handler(httpd_req_t *req)
{
    increment_route_counter("/logs");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr_chunk(req, "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Logs</title><style>");
    httpd_resp_sendstr_chunk(req, html_style);
    httpd_resp_sendstr_chunk(req,
        "</style></head><body><header><h1>Logs</h1><div>Eventos recentes mantidos em RAM.</div>"
        "<nav><a href=\"/\">Dashboard</a><a href=\"/traffic\">Traffic</a><a href=\"/report\">Report</a><a href=\"/api/events\">JSON</a></nav></header>"
        "<main><section class=\"card\"><p>Eventos são filtrados para evitar ruído de polling; requests normais aparecem em /traffic.</p></section>"
        "<table><thead><tr><th>ID</th><th>Horário</th><th>Uptime</th><th>Nível</th><th>Origem</th><th>Mensagem</th></tr></thead><tbody id=\"events\"></tbody></table></main>"
        "<script>function escapeHtml(v){return String(v==null?'':v).replace(/[&<>\"']/g,function(c){return c==='&'?'&amp;':c==='<'?'&lt;':c==='>'?'&gt;':c==='\"'?'&quot;':'&#39;';});}"
        "function eventRow(x){return '<tr><td>'+Number(x.id||0)+'</td><td>'+escapeHtml(x.time_synced?x.timestamp:'unsynced')+'</td><td>'+escapeHtml(x.time_label)+'</td><td>'+escapeHtml(x.level)+'</td><td>'+escapeHtml(x.source)+'</td><td>'+escapeHtml(x.message)+'</td></tr>'; }"
        "fetch('/api/events').then(r=>r.json()).then(j=>events.innerHTML=(j.events||[]).map(eventRow).join(''));</script></body></html>");
    return httpd_resp_sendstr_chunk(req, NULL);
}

static esp_err_t traffic_handler(httpd_req_t *req)
{
    increment_route_counter("/traffic");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr_chunk(req, "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Traffic</title><style>");
    httpd_resp_sendstr_chunk(req, html_style);
    httpd_resp_sendstr_chunk(req,
        "</style></head><body><header><h1>Traffic</h1><div>Contadores HTTP e sinais simples de varredura.</div>"
        "<nav><a href=\"/\">Dashboard</a><a href=\"/logs\">Logs</a><a href=\"/demo/scan\">Demo scan</a><a href=\"/api/status\">JSON</a></nav></header>"
        "<main><section class=\"grid\" id=\"cards\"></section><section class=\"card\"><h2>Top routes</h2><table><thead><tr><th>Rota</th><th>Hits</th></tr></thead><tbody id=\"routes\"></tbody></table></section></main>"
        "<script>function escapeHtml(v){return String(v==null?'':v).replace(/[&<>\"']/g,function(c){return c==='&'?'&amp;':c==='<'?'&lt;':c==='>'?'&gt;':c==='\"'?'&quot;':'&#39;';});}function card(label,value){return '<div class=\"card\"><div class=\"label\">'+escapeHtml(label)+'</div><div class=\"value\">'+escapeHtml(value)+'</div></div>'; }function routeRow(x){return '<tr><td><code>'+escapeHtml(x.route)+'</code></td><td>'+Number(x.count||0)+'</td></tr>'; }async function load(){const s=await fetch('/api/status').then(r=>r.json());cards.innerHTML=[['Total requests',s.traffic.total],['DNS queries',s.dns.total_queries],['Último domínio',s.dns.last_domain||'n/d'],['Último cliente DNS',s.dns.last_client||'n/d'],['DNS suspeito',s.dns.suspicious_count],['404',s.traffic.not_found],['Sensíveis',s.traffic.sensitive_path_hits],['Scan suspeito',s.traffic.suspicious_scan_count],['Demo scan',s.traffic.demo_scan_count],['Última rota',s.traffic.last_route]].map(c=>card(c[0],c[1])).join('');routes.innerHTML=(s.traffic.top_routes||[]).map(routeRow).join('');}load();setInterval(load,5000);</script></body></html>");
    return httpd_resp_sendstr_chunk(req, NULL);
}

static esp_err_t report_handler(httpd_req_t *req)
{
    increment_route_counter("/report");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr_chunk(req, "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Report</title><style>");
    httpd_resp_sendstr_chunk(req, html_style);
    httpd_resp_sendstr_chunk(req,
        "</style></head><body><header><h1>Relatório da PoC</h1><div>Resumo operacional para demonstração em bancada.</div>"
        "<nav><a href=\"/\">Dashboard</a><a href=\"/traffic\">Traffic</a><a href=\"/logs\">Logs</a><a href=\"/dns\">DNS</a><a href=\"/api/status\">JSON</a></nav></header>"
        "<main><section class=\"grid\" id=\"cards\"></section>"
        "<section class=\"card\"><h2>Escopo validado</h2><table><tr><td>AP+STA</td><td>AP fixo em 192.168.4.1 e STA opcional.</td></tr><tr><td>NAPT</td><td>Habilitado somente após IP válido no STA.</td></tr><tr><td>IDS didático</td><td>Contadores HTTP e DNS em RAM para demonstração.</td></tr><tr><td>Limitação</td><td>Não é firewall profissional e não inspeciona HTTPS.</td></tr></table></section>"
        "<section class=\"card\"><h2>DNS/Tráfego observado</h2><table><tr><td>Monitor DNS</td><td>Registra consultas de domínio feitas por clientes do AP via proxy DNS local.</td></tr><tr><td>Privacidade</td><td>HTTPS continua criptografado; o sistema não lê conteúdo das páginas.</td></tr><tr><td>Escopo</td><td>Detecção didática por domínios de teste suspeitos, sem bloqueio nesta sprint.</td></tr></table></section></main>"
        "<script>function escapeHtml(v){return String(v==null?'':v).replace(/[&<>\"']/g,function(c){return c==='&'?'&amp;':c==='<'?'&lt;':c==='>'?'&gt;':c==='\"'?'&quot;':'&#39;';});}"
        "function card(label,value){return '<div class=\"card\"><div class=\"label\">'+escapeHtml(label)+'</div><div class=\"value\">'+escapeHtml(value)+'</div></div>'; }"
        "fetch('/api/status').then(r=>r.json()).then(s=>cards.innerHTML=[['Projeto',s.project],['Versão',s.version],['NAT',s.nat.active?'ativo':'inativo'],['Upstream',s.upstream.connected?s.upstream.ip:'n/d'],['Horário',s.time.synced?s.time.timestamp:'unsynced'],['Heap livre',s.heap_free],['Requests',s.traffic.total],['DNS queries',s.dns.total_queries],['DNS suspeito',s.dns.suspicious_count],['Último domínio',s.dns.last_domain||'n/d']].map(c=>card(c[0],c[1])).join(''));</script></body></html>");
    return httpd_resp_sendstr_chunk(req, NULL);
}

static esp_err_t api_index_handler(httpd_req_t *req)
{
    increment_route_counter("/api");
    log_http_event(req, "/api", "SECURITY", "sensitive_api_index");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_sendstr(req,
        "{\"apis\":["
        "{\"path\":\"/api/status\",\"type\":\"status\"},"
        "{\"path\":\"/api/events\",\"type\":\"events\"},"
        "{\"path\":\"/api/dns\",\"type\":\"dns\"},"
        "{\"path\":\"/traffic\",\"type\":\"html\"},"
        "{\"path\":\"/dns\",\"type\":\"html\"},"
        "{\"path\":\"/logs\",\"type\":\"html\"},"
        "{\"path\":\"/report\",\"type\":\"html\"}"
        "],\"note\":\"/api e tratado tambem como rota sensivel para fins didaticos\"}");
}

static esp_err_t demo_handler(httpd_req_t *req)
{
    return send_html(req, "/demo",
        "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Demo</title><style>"
        "body{font-family:Arial,sans-serif;margin:0;background:#f5f7fa;color:#17202a}header,main{max-width:960px;margin:0 auto;padding:18px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.card{background:#fff;border:1px solid #d9e2ec;border-radius:6px;padding:14px}a{color:#0b5cad}</style></head>"
        "<body><header><h1>Demo</h1><div>Rotas de demonstração para gerar eventos HTTP controlados.</div></header><main><section class=\"grid\"><div class=\"card\"><a href=\"/demo/scan\">Demo scan</a></div><div class=\"card\"><a href=\"/demo/security\">Demo security</a></div><div class=\"card\"><a href=\"/demo/info\">Demo info</a></div></section></main></body></html>");
}

static esp_err_t demo_scan_handler(httpd_req_t *req)
{
    increment_route_counter("/demo/scan");
    log_http_event(req, "/demo/scan", "SECURITY", "demo_scan_signal");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_sendstr(req, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Demo scan</title></head><body><h1>Demo scan</h1><p>Evento SECURITY registrado e contador demo_scan_count incrementado.</p><p><a href=\"/traffic\">Ver traffic</a></p></body></html>");
}

static esp_err_t demo_security_handler(httpd_req_t *req)
{
    increment_route_counter("/demo/security");
    log_http_event(req, "/demo/security", "SECURITY", "containment_test_event");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_sendstr(req, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Demo security</title></head><body><h1>Demo security</h1><p>Evento SECURITY didático registrado sem bloquear tráfego real.</p></body></html>");
}

static esp_err_t demo_info_handler(httpd_req_t *req)
{
    increment_route_counter("/demo/info");
    log_http_event(req, "/demo/info", "INFO", "demo_info");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_sendstr(req, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Demo info</title></head><body><h1>Demo info</h1><p>Use /api/status para ver os contadores expandidos.</p></body></html>");
}

static esp_err_t sensitive_handler(httpd_req_t *req)
{
    const char *route = req->uri;
    increment_route_counter(route);
    log_http_event(req, route, "SECURITY", is_scan_like_path(route) ? "suspicious_scan_path" : "sensitive_path");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    return httpd_resp_sendstr(req, "<!doctype html><html><head><meta charset=\"utf-8\"><title>Rota sensível</title></head><body><h1>Rota sensível</h1><p>Evento SECURITY registrado para demonstração didática.</p><p>Nenhuma configuração sensível foi exibida.</p></body></html>");
}

static esp_err_t favicon_handler(httpd_req_t *req)
{
    increment_route_counter("/favicon.ico");
    httpd_resp_set_type(req, "image/x-icon");
    return httpd_resp_send(req, NULL, 0);
}

static esp_err_t not_found_handler(httpd_req_t *req, httpd_err_code_t err)
{
    (void)err;
    increment_route_counter(req->uri);
    if (strcmp(req->uri, "/favicon.ico") != 0) {
        log_http_event(req, req->uri, "WARN", "not_found");
    }
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
    return ESP_OK;
}

static void start_http_server(void)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_uri_handlers = 28;

    ESP_ERROR_CHECK(httpd_start(&http_server, &config));

    const httpd_uri_t routes[] = {
        {.uri = "/", .method = HTTP_GET, .handler = root_handler, .user_ctx = NULL},
        {.uri = "/status", .method = HTTP_GET, .handler = status_handler, .user_ctx = NULL},
        {.uri = "/api", .method = HTTP_GET, .handler = api_index_handler, .user_ctx = NULL},
        {.uri = "/api/status", .method = HTTP_GET, .handler = api_status_handler, .user_ctx = NULL},
        {.uri = "/logs", .method = HTTP_GET, .handler = logs_handler, .user_ctx = NULL},
        {.uri = "/api/events", .method = HTTP_GET, .handler = api_events_handler, .user_ctx = NULL},
        {.uri = "/api/dns", .method = HTTP_GET, .handler = api_dns_handler, .user_ctx = NULL},
        {.uri = "/dns", .method = HTTP_GET, .handler = dns_handler, .user_ctx = NULL},
        {.uri = "/traffic", .method = HTTP_GET, .handler = traffic_handler, .user_ctx = NULL},
        {.uri = "/report", .method = HTTP_GET, .handler = report_handler, .user_ctx = NULL},
        {.uri = "/demo", .method = HTTP_GET, .handler = demo_handler, .user_ctx = NULL},
        {.uri = "/demo/scan", .method = HTTP_GET, .handler = demo_scan_handler, .user_ctx = NULL},
        {.uri = "/demo/security", .method = HTTP_GET, .handler = demo_security_handler, .user_ctx = NULL},
        {.uri = "/demo/info", .method = HTTP_GET, .handler = demo_info_handler, .user_ctx = NULL},
        {.uri = "/favicon.ico", .method = HTTP_GET, .handler = favicon_handler, .user_ctx = NULL},
        {.uri = "/admin", .method = HTTP_GET, .handler = sensitive_handler, .user_ctx = NULL},
        {.uri = "/login", .method = HTTP_GET, .handler = sensitive_handler, .user_ctx = NULL},
        {.uri = "/wp-admin", .method = HTTP_GET, .handler = sensitive_handler, .user_ctx = NULL},
        {.uri = "/etc/passwd", .method = HTTP_GET, .handler = sensitive_handler, .user_ctx = NULL},
        {.uri = "/config", .method = HTTP_GET, .handler = sensitive_handler, .user_ctx = NULL},
        {.uri = "/debug", .method = HTTP_GET, .handler = sensitive_handler, .user_ctx = NULL},
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
    start_dns_proxy();
    start_http_server();

    while (true) {
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
