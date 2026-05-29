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
#if APPLIANCE_V2_ENABLE_DISPLAY
#include "driver/gpio.h"
#include "driver/spi_master.h"
#endif

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
#define IDS_CLIENT_CAPACITY 8
#define IDS_DOMAIN_HASH_CAPACITY 8
#define IDS_EVENT_LABEL_LEN 32
#define IDS_DNS_BURST_WINDOW_MS 10000ULL
#define IDS_DNS_BURST_THRESHOLD 20U
#define IDS_DNS_BURST_COOLDOWN_MS 60000ULL
#define IDS_UNIQUE_DOMAIN_THRESHOLD 8U
#define IDS_RISK_MAX 100U
#define DISPLAY_SUSPICIOUS_HOLD_MS 300000ULL
#define DISPLAY_ATTACK_HOLD_MS 60000ULL
#define DISPLAY_REFRESH_MIN_MS 1000ULL
#define DISPLAY_DOMAIN_LABEL_LEN 32

typedef enum {
    DISPLAY_STATE_NORMAL = 0,
    DISPLAY_STATE_SUSPICIOUS_DNS,
    DISPLAY_STATE_ATTACK
} display_state_t;

typedef enum {
    DISPLAY_BOX_OFF = 0,
    DISPLAY_BOX_OK,
    DISPLAY_BOX_WARN,
    DISPLAY_BOX_ALERT
} display_box_state_t;

typedef struct {
    display_state_t state;
    display_box_state_t upstream_box;
    display_box_state_t nat_box;
    display_box_state_t ids_box;
    bool upstream_configured;
    bool upstream_connecting;
    bool upstream_connected;
    bool nat_attempted;
    bool nat_active;
    uint16_t client_count;
    uint8_t highest_risk_score;
    char last_suspicious_domain[DISPLAY_DOMAIN_LABEL_LEN];
    char clock_label[8];
} display_snapshot_t;


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
    uint64_t clients;
    uint64_t api_clients;
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

typedef struct {
    bool active;
    char client_ip[DNS_CLIENT_LEN];
    uint64_t first_seen_ms;
    uint64_t last_seen_ms;
    uint64_t dns_query_count;
    uint32_t suspicious_dns_count;
    uint16_t unique_domain_count;
    uint32_t domain_hashes[IDS_DOMAIN_HASH_CAPACITY];
    uint8_t domain_hash_write_index;
    char last_domain[DNS_DOMAIN_LEN];
    uint8_t risk_score;
    char last_event_label[IDS_EVENT_LABEL_LEN];
    uint64_t burst_window_start_ms;
    uint16_t burst_window_count;
    uint64_t last_burst_event_ms;
    bool unique_risk_applied;
} ids_client_t;

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
static ids_client_t ids_clients[IDS_CLIENT_CAPACITY] = {0};
static uint32_t dns_query_count = 0;
static uint32_t dns_write_index = 0;
static uint32_t dns_next_id = 1;
static uint64_t dns_total_queries = 0;
static uint64_t suspicious_dns_count = 0;
static uint32_t total_clients_seen = 0;
static uint64_t dns_burst_count = 0;
static bool dns_monitoring_enabled = false;
static bool dns_first_observed = false;
static char dns_last_domain[DNS_DOMAIN_LEN] = "";
static char dns_last_client[DNS_CLIENT_LEN] = "";
static char dns_last_query_type[DNS_QUERY_TYPE_LEN] = "";
static volatile bool time_synchronized = false;
static bool sntp_started = false;
static volatile bool sntp_sync_event_pending = false;
static bool sta_reconnect_pending = false;
static uint8_t sta_retry_count = 0;
static uint64_t sta_next_reconnect_ms = 0;
static TaskHandle_t dns_task_handle = NULL;
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
static bool display_available = false;
static uint64_t display_last_update_ms = 0;
static uint64_t display_last_suspicious_ms = 0;
static uint64_t display_last_attack_ms = 0;
static char display_last_suspicious_domain[DISPLAY_DOMAIN_LABEL_LEN] = "";
static display_state_t display_current_state = DISPLAY_STATE_NORMAL;
#if APPLIANCE_V2_ENABLE_DISPLAY
static spi_device_handle_t display_spi = NULL;
#endif



static uint64_t uptime_ms(void);
static uint16_t get_client_count(void);
static void ids_summary_locked(uint32_t *active_clients, uint8_t *highest_score, char *highest_client, size_t highest_client_len, char *last_domain, size_t last_domain_len);
static void add_event(const char *level, const char *source, const char *fmt, ...);

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


static const char *display_state_name(display_state_t state)
{
    switch (state) {
    case DISPLAY_STATE_ATTACK:
        return "ATTACK";
    case DISPLAY_STATE_SUSPICIOUS_DNS:
        return "SUSPICIOUS_DNS";
    case DISPLAY_STATE_NORMAL:
    default:
        return "NORMAL";
    }
}

static void display_format_clock(char *out, size_t out_len)
{
    if (out == NULL || out_len == 0) {
        return;
    }
    time_t now;
    struct tm timeinfo;
    time(&now);
    localtime_r(&now, &timeinfo);
    if (!time_synchronized || timeinfo.tm_year < (2023 - 1900)) {
        strlcpy(out, "--:--", out_len);
        return;
    }
    strftime(out, out_len, "%H:%M", &timeinfo);
}

static void display_note_suspicious_dns(const char *domain, uint64_t now_ms)
{
    display_last_suspicious_ms = now_ms;
    if (domain != NULL && domain[0] != '\0') {
        strlcpy(display_last_suspicious_domain, domain, sizeof(display_last_suspicious_domain));
    }
}

static void display_note_attack(uint64_t now_ms)
{
    display_last_attack_ms = now_ms;
}

static void compute_display_state(display_snapshot_t *out)
{
    if (out == NULL) {
        return;
    }
    memset(out, 0, sizeof(*out));
    out->state = DISPLAY_STATE_NORMAL;
    out->upstream_box = DISPLAY_BOX_OFF;
    out->nat_box = DISPLAY_BOX_OFF;
    out->ids_box = DISPLAY_BOX_OK;
    strlcpy(out->last_suspicious_domain, "n/d", sizeof(out->last_suspicious_domain));
    display_format_clock(out->clock_label, sizeof(out->clock_label));

    uint64_t now_ms = uptime_ms();
    out->client_count = get_client_count();

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    uint32_t active_clients = 0;
    char highest_client[DNS_CLIENT_LEN];
    char last_domain[DNS_DOMAIN_LEN];
    ids_summary_locked(&active_clients, &out->highest_risk_score, highest_client, sizeof(highest_client), last_domain, sizeof(last_domain));
    (void)active_clients;
    out->upstream_configured = upstream_configured;
    out->upstream_connecting = upstream_connecting;
    out->upstream_connected = upstream_connected;
    out->nat_attempted = nat_attempted;
    out->nat_active = nat_active;
    uint64_t suspicious_age = display_last_suspicious_ms == 0 ? UINT64_MAX : now_ms - display_last_suspicious_ms;
    uint64_t attack_age = display_last_attack_ms == 0 ? UINT64_MAX : now_ms - display_last_attack_ms;
    strlcpy(out->last_suspicious_domain,
            display_last_suspicious_domain[0] != '\0' ? display_last_suspicious_domain : "n/d",
            sizeof(out->last_suspicious_domain));
    xSemaphoreGive(state_mutex);

    bool attack_recent = attack_age <= DISPLAY_ATTACK_HOLD_MS;
    bool suspicious_recent = suspicious_age <= DISPLAY_SUSPICIOUS_HOLD_MS;
    if (attack_recent || out->highest_risk_score >= 15U) {
        out->state = DISPLAY_STATE_ATTACK;
    } else if (suspicious_recent) {
        out->state = DISPLAY_STATE_SUSPICIOUS_DNS;
    } else {
        out->state = DISPLAY_STATE_NORMAL;
    }
    display_current_state = out->state;

    if (out->upstream_connected) {
        out->upstream_box = DISPLAY_BOX_OK;
    } else if (out->upstream_configured && out->upstream_connecting) {
        out->upstream_box = DISPLAY_BOX_WARN;
    } else if (out->upstream_configured) {
        out->upstream_box = DISPLAY_BOX_ALERT;
    } else {
        out->upstream_box = DISPLAY_BOX_OFF;
    }

    if (out->nat_active) {
        out->nat_box = DISPLAY_BOX_OK;
    } else if (!out->upstream_connected) {
        out->nat_box = DISPLAY_BOX_WARN;
    } else if (out->nat_attempted) {
        out->nat_box = DISPLAY_BOX_ALERT;
    } else {
        out->nat_box = DISPLAY_BOX_OFF;
    }

    if (out->state == DISPLAY_STATE_ATTACK) {
        out->ids_box = DISPLAY_BOX_ALERT;
    } else if (out->state == DISPLAY_STATE_SUSPICIOUS_DNS) {
        out->ids_box = DISPLAY_BOX_WARN;
    } else {
        out->ids_box = DISPLAY_BOX_OK;
    }
}

#if APPLIANCE_V2_ENABLE_DISPLAY
#define DISPLAY_COLOR_BLACK 0x0000
#define DISPLAY_COLOR_WHITE 0xFFFF
#define DISPLAY_COLOR_GRAY 0x8410
#define DISPLAY_COLOR_DARK 0x18E3
#define DISPLAY_COLOR_GREEN 0x07E0
#define DISPLAY_COLOR_YELLOW 0xFFE0
#define DISPLAY_COLOR_RED 0xF800
#define DISPLAY_COLOR_ORANGE 0xFC00
#define DISPLAY_COLOR_BLUE 0x001F

static uint16_t display_swap_color(uint16_t color)
{
    return (uint16_t)((color << 8) | (color >> 8));
}

static esp_err_t display_send_cmd(uint8_t cmd)
{
    if (display_spi == NULL) {
        return ESP_FAIL;
    }
    gpio_set_level((gpio_num_t)APPLIANCE_V2_DISPLAY_PIN_DC, 0);
    spi_transaction_t t = {0};
    t.length = 8;
    t.tx_buffer = &cmd;
    return spi_device_polling_transmit(display_spi, &t);
}

static esp_err_t display_send_data(const void *data, size_t len)
{
    if (display_spi == NULL || data == NULL || len == 0) {
        return ESP_FAIL;
    }
    gpio_set_level((gpio_num_t)APPLIANCE_V2_DISPLAY_PIN_DC, 1);
    spi_transaction_t t = {0};
    t.length = len * 8;
    t.tx_buffer = data;
    return spi_device_polling_transmit(display_spi, &t);
}

static void display_set_window(uint16_t x0, uint16_t y0, uint16_t x1, uint16_t y1)
{
    uint8_t data[4];
    display_send_cmd(0x2A);
    data[0] = (uint8_t)(x0 >> 8);
    data[1] = (uint8_t)x0;
    data[2] = (uint8_t)(x1 >> 8);
    data[3] = (uint8_t)x1;
    display_send_data(data, sizeof(data));
    display_send_cmd(0x2B);
    data[0] = (uint8_t)(y0 >> 8);
    data[1] = (uint8_t)y0;
    data[2] = (uint8_t)(y1 >> 8);
    data[3] = (uint8_t)y1;
    display_send_data(data, sizeof(data));
    display_send_cmd(0x2C);
}

static void display_fill_rect(int x, int y, int w, int h, uint16_t color)
{
    if (!display_available || w <= 0 || h <= 0) {
        return;
    }
    if (x < 0) {
        w += x;
        x = 0;
    }
    if (y < 0) {
        h += y;
        y = 0;
    }
    if (x >= APPLIANCE_V2_DISPLAY_WIDTH || y >= APPLIANCE_V2_DISPLAY_HEIGHT || w <= 0 || h <= 0) {
        return;
    }
    if (x + w > APPLIANCE_V2_DISPLAY_WIDTH) {
        w = APPLIANCE_V2_DISPLAY_WIDTH - x;
    }
    if (y + h > APPLIANCE_V2_DISPLAY_HEIGHT) {
        h = APPLIANCE_V2_DISPLAY_HEIGHT - y;
    }
    display_set_window((uint16_t)x, (uint16_t)y, (uint16_t)(x + w - 1), (uint16_t)(y + h - 1));
    uint16_t line[64];
    uint16_t encoded = display_swap_color(color);
    for (size_t i = 0; i < sizeof(line) / sizeof(line[0]); i++) {
        line[i] = encoded;
    }
    int pixels = w * h;
    while (pixels > 0) {
        int chunk = pixels > (int)(sizeof(line) / sizeof(line[0])) ? (int)(sizeof(line) / sizeof(line[0])) : pixels;
        display_send_data(line, (size_t)chunk * sizeof(uint16_t));
        pixels -= chunk;
    }
}

static uint8_t display_font_rows(char c, uint8_t row)
{
    static const uint8_t digits[10][7] = {
        {14,17,19,21,25,17,14},{4,12,4,4,4,4,14},{14,17,1,2,4,8,31},{30,1,1,14,1,1,30},{2,6,10,18,31,2,2},
        {31,16,30,1,1,17,14},{6,8,16,30,17,17,14},{31,1,2,4,8,8,8},{14,17,17,14,17,17,14},{14,17,17,15,1,2,12}
    };
    if (row >= 7) {
        return 0;
    }
    if (c >= '0' && c <= '9') {
        return digits[c - '0'][row];
    }
    switch (c) {
    case 'A': {static const uint8_t r[7]={14,17,17,31,17,17,17}; return r[row];}
    case 'B': {static const uint8_t r[7]={30,17,17,30,17,17,30}; return r[row];}
    case 'C': {static const uint8_t r[7]={14,17,16,16,16,17,14}; return r[row];}
    case 'D': {static const uint8_t r[7]={30,17,17,17,17,17,30}; return r[row];}
    case 'E': {static const uint8_t r[7]={31,16,16,30,16,16,31}; return r[row];}
    case 'F': {static const uint8_t r[7]={31,16,16,30,16,16,16}; return r[row];}
    case 'G': {static const uint8_t r[7]={14,17,16,23,17,17,15}; return r[row];}
    case 'H': {static const uint8_t r[7]={17,17,17,31,17,17,17}; return r[row];}
    case 'I': {static const uint8_t r[7]={14,4,4,4,4,4,14}; return r[row];}
    case 'K': {static const uint8_t r[7]={17,18,20,24,20,18,17}; return r[row];}
    case 'L': {static const uint8_t r[7]={16,16,16,16,16,16,31}; return r[row];}
    case 'M': {static const uint8_t r[7]={17,27,21,21,17,17,17}; return r[row];}
    case 'N': {static const uint8_t r[7]={17,25,21,19,17,17,17}; return r[row];}
    case 'O': {static const uint8_t r[7]={14,17,17,17,17,17,14}; return r[row];}
    case 'P': {static const uint8_t r[7]={30,17,17,30,16,16,16}; return r[row];}
    case 'R': {static const uint8_t r[7]={30,17,17,30,20,18,17}; return r[row];}
    case 'S': {static const uint8_t r[7]={15,16,16,14,1,1,30}; return r[row];}
    case 'T': {static const uint8_t r[7]={31,4,4,4,4,4,4}; return r[row];}
    case 'U': {static const uint8_t r[7]={17,17,17,17,17,17,14}; return r[row];}
    case 'V': {static const uint8_t r[7]={17,17,17,17,17,10,4}; return r[row];}
    case 'W': {static const uint8_t r[7]={17,17,17,21,21,21,10}; return r[row];}
    case 'Y': {static const uint8_t r[7]={17,17,10,4,4,4,4}; return r[row];}
    case ':': {static const uint8_t r[7]={0,4,4,0,4,4,0}; return r[row];}
    case '.': {static const uint8_t r[7]={0,0,0,0,0,12,12}; return r[row];}
    case '-': {static const uint8_t r[7]={0,0,0,31,0,0,0}; return r[row];}
    case '/': {static const uint8_t r[7]={1,2,2,4,8,8,16}; return r[row];}
    default: return 0;
    }
}

static void display_draw_char(int x, int y, char c, uint16_t color, int scale)
{
    if (c >= 'a' && c <= 'z') {
        c = (char)(c - 32);
    }
    for (uint8_t row = 0; row < 7; row++) {
        uint8_t bits = display_font_rows(c, row);
        for (uint8_t col = 0; col < 5; col++) {
            if (bits & (1U << (4U - col))) {
                display_fill_rect(x + col * scale, y + row * scale, scale, scale, color);
            }
        }
    }
}

static void display_draw_text(int x, int y, const char *text, uint16_t color, int scale)
{
    if (text == NULL) {
        return;
    }
    int cursor = x;
    for (size_t i = 0; text[i] != '\0'; i++) {
        if (text[i] == ' ') {
            cursor += 4 * scale;
            continue;
        }
        display_draw_char(cursor, y, text[i], color, scale);
        cursor += 6 * scale;
        if (cursor > APPLIANCE_V2_DISPLAY_WIDTH - 6 * scale) {
            break;
        }
    }
}

static void display_draw_pixel_icon(int x, int y, const uint8_t rows[16], uint16_t color, int scale)
{
    for (uint8_t row = 0; row < 16; row++) {
        for (uint8_t col = 0; col < 8; col++) {
            if (rows[row] & (1U << (7U - col))) {
                display_fill_rect(x + col * scale, y + row * scale, scale, scale, color);
            }
        }
    }
}

static uint16_t display_box_color(display_box_state_t state)
{
    switch (state) {
    case DISPLAY_BOX_OK: return DISPLAY_COLOR_GREEN;
    case DISPLAY_BOX_WARN: return DISPLAY_COLOR_YELLOW;
    case DISPLAY_BOX_ALERT: return DISPLAY_COLOR_RED;
    case DISPLAY_BOX_OFF:
    default: return DISPLAY_COLOR_GRAY;
    }
}

static void display_draw_status_boxes(const display_snapshot_t *state)
{
    display_fill_rect(8, APPLIANCE_V2_DISPLAY_HEIGHT - 48, 68, 38, DISPLAY_COLOR_DARK);
    display_fill_rect(86, APPLIANCE_V2_DISPLAY_HEIGHT - 48, 68, 38, DISPLAY_COLOR_DARK);
    display_fill_rect(164, APPLIANCE_V2_DISPLAY_HEIGHT - 48, 68, 38, DISPLAY_COLOR_DARK);
    display_fill_rect(12, APPLIANCE_V2_DISPLAY_HEIGHT - 44, 14, 14, display_box_color(state->upstream_box));
    display_fill_rect(90, APPLIANCE_V2_DISPLAY_HEIGHT - 44, 14, 14, display_box_color(state->nat_box));
    display_fill_rect(168, APPLIANCE_V2_DISPLAY_HEIGHT - 44, 14, 14, display_box_color(state->ids_box));
    display_draw_text(30, APPLIANCE_V2_DISPLAY_HEIGHT - 42, "UP", DISPLAY_COLOR_WHITE, 1);
    display_draw_text(108, APPLIANCE_V2_DISPLAY_HEIGHT - 42, "NAT", DISPLAY_COLOR_WHITE, 1);
    display_draw_text(186, APPLIANCE_V2_DISPLAY_HEIGHT - 42, "IDS", DISPLAY_COLOR_WHITE, 1);
}

static void display_draw_normal(const display_snapshot_t *state)
{
    static const uint8_t shield[16] = {0x3C,0x7E,0xFF,0xDB,0xDB,0xDB,0xDB,0xC3,0xC3,0x66,0x66,0x3C,0x3C,0x18,0x18,0x00};
    display_fill_rect(0, 0, APPLIANCE_V2_DISPLAY_WIDTH, APPLIANCE_V2_DISPLAY_HEIGHT, DISPLAY_COLOR_BLACK);
    display_draw_pixel_icon(32, 34, shield, DISPLAY_COLOR_GREEN, 7);
    display_draw_text(118, 46, "NORMAL", DISPLAY_COLOR_GREEN, 2);
    display_draw_text(118, 76, state->clock_label, DISPLAY_COLOR_WHITE, 2);
    char line[24];
    snprintf(line, sizeof(line), "CL:%u", state->client_count);
    display_draw_text(118, 106, line, DISPLAY_COLOR_WHITE, 2);
    snprintf(line, sizeof(line), "RISK:%u", state->highest_risk_score);
    display_draw_text(118, 136, line, DISPLAY_COLOR_WHITE, 1);
    display_draw_status_boxes(state);
}

static void display_draw_suspicious_dns(const display_snapshot_t *state)
{
    static const uint8_t skull[16] = {0x3C,0x7E,0xDB,0xFF,0xA5,0xFF,0xBD,0x7E,0x3C,0x24,0x3C,0x24,0x24,0x00,0x00,0x00};
    display_fill_rect(0, 0, APPLIANCE_V2_DISPLAY_WIDTH, APPLIANCE_V2_DISPLAY_HEIGHT, DISPLAY_COLOR_BLACK);
    display_draw_pixel_icon(28, 24, skull, DISPLAY_COLOR_RED, 8);
    display_draw_text(112, 38, "DNS SUS", DISPLAY_COLOR_YELLOW, 2);
    display_draw_text(112, 70, state->clock_label, DISPLAY_COLOR_WHITE, 2);
    char domain[DISPLAY_DOMAIN_LABEL_LEN];
    strlcpy(domain, state->last_suspicious_domain, sizeof(domain));
    display_draw_text(16, 164, domain, DISPLAY_COLOR_RED, 1);
    display_draw_status_boxes(state);
}

static void display_draw_attack(const display_snapshot_t *state)
{
    static const uint8_t alert[16] = {0x18,0x18,0x3C,0x3C,0x7E,0x7E,0xDB,0xDB,0xFF,0xFF,0x18,0x18,0x00,0x18,0x18,0x00};
    display_fill_rect(0, 0, APPLIANCE_V2_DISPLAY_WIDTH, APPLIANCE_V2_DISPLAY_HEIGHT, DISPLAY_COLOR_BLACK);
    display_draw_pixel_icon(32, 18, alert, DISPLAY_COLOR_RED, 8);
    display_draw_text(116, 42, "ATTACK", DISPLAY_COLOR_RED, 2);
    display_draw_text(116, 76, state->clock_label, DISPLAY_COLOR_WHITE, 2);
    char line[24];
    snprintf(line, sizeof(line), "RISK:%u", state->highest_risk_score);
    display_draw_text(116, 110, line, DISPLAY_COLOR_ORANGE, 2);
    snprintf(line, sizeof(line), "CL:%u", state->client_count);
    display_draw_text(116, 142, line, DISPLAY_COLOR_WHITE, 1);
    display_draw_status_boxes(state);
}

static bool display_snapshot_changed(const display_snapshot_t *a, const display_snapshot_t *b)
{
    return a->state != b->state ||
           a->upstream_box != b->upstream_box ||
           a->nat_box != b->nat_box ||
           a->ids_box != b->ids_box ||
           a->client_count != b->client_count ||
           a->highest_risk_score != b->highest_risk_score ||
           strcmp(a->clock_label, b->clock_label) != 0 ||
           strcmp(a->last_suspicious_domain, b->last_suspicious_domain) != 0;
}

static void display_draw_snapshot(const display_snapshot_t *state)
{
    if (state->state == DISPLAY_STATE_ATTACK) {
        display_draw_attack(state);
    } else if (state->state == DISPLAY_STATE_SUSPICIOUS_DNS) {
        display_draw_suspicious_dns(state);
    } else {
        display_draw_normal(state);
    }
}

static bool display_pins_configured(void)
{
    return APPLIANCE_V2_DISPLAY_PIN_MOSI >= 0 &&
           APPLIANCE_V2_DISPLAY_PIN_SCLK >= 0 &&
           APPLIANCE_V2_DISPLAY_PIN_CS >= 0 &&
           APPLIANCE_V2_DISPLAY_PIN_DC >= 0;
}
#endif

static void display_init(void)
{
#if APPLIANCE_V2_ENABLE_DISPLAY
    display_available = false;
    if (!display_pins_configured() || APPLIANCE_V2_DISPLAY_DRIVER == APPLIANCE_V2_DISPLAY_DRIVER_NONE) {
        add_event("WARN", "display", "Display enabled but driver/pins are incomplete");
        return;
    }

    spi_bus_config_t buscfg = {
        .mosi_io_num = APPLIANCE_V2_DISPLAY_PIN_MOSI,
        .miso_io_num = APPLIANCE_V2_DISPLAY_PIN_MISO,
        .sclk_io_num = APPLIANCE_V2_DISPLAY_PIN_SCLK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
        .max_transfer_sz = 4096,
    };
    spi_device_interface_config_t devcfg = {
        .clock_speed_hz = 20 * 1000 * 1000,
        .mode = 0,
        .spics_io_num = APPLIANCE_V2_DISPLAY_PIN_CS,
        .queue_size = 1,
    };
    esp_err_t ret = spi_bus_initialize(SPI2_HOST, &buscfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) {
        add_event("WARN", "display", "SPI bus init failed: %s", esp_err_to_name(ret));
        return;
    }
    ret = spi_bus_add_device(SPI2_HOST, &devcfg, &display_spi);
    if (ret != ESP_OK) {
        spi_bus_free(SPI2_HOST);
        add_event("WARN", "display", "SPI display attach failed: %s", esp_err_to_name(ret));
        return;
    }
    gpio_set_direction((gpio_num_t)APPLIANCE_V2_DISPLAY_PIN_DC, GPIO_MODE_OUTPUT);
    if (APPLIANCE_V2_DISPLAY_PIN_RST >= 0) {
        gpio_set_direction((gpio_num_t)APPLIANCE_V2_DISPLAY_PIN_RST, GPIO_MODE_OUTPUT);
        gpio_set_level((gpio_num_t)APPLIANCE_V2_DISPLAY_PIN_RST, 0);
        vTaskDelay(pdMS_TO_TICKS(50));
        gpio_set_level((gpio_num_t)APPLIANCE_V2_DISPLAY_PIN_RST, 1);
        vTaskDelay(pdMS_TO_TICKS(120));
    }
    if (APPLIANCE_V2_DISPLAY_PIN_BL >= 0) {
        gpio_set_direction((gpio_num_t)APPLIANCE_V2_DISPLAY_PIN_BL, GPIO_MODE_OUTPUT);
        gpio_set_level((gpio_num_t)APPLIANCE_V2_DISPLAY_PIN_BL, 1);
    }

    display_send_cmd(0x01);
    vTaskDelay(pdMS_TO_TICKS(120));
    display_send_cmd(0x11);
    vTaskDelay(pdMS_TO_TICKS(120));
    uint8_t color_mode = 0x55;
    display_send_cmd(0x3A);
    display_send_data(&color_mode, 1);
    uint8_t madctl = 0x00;
    display_send_cmd(0x36);
    display_send_data(&madctl, 1);
    if (APPLIANCE_V2_DISPLAY_DRIVER == APPLIANCE_V2_DISPLAY_DRIVER_ST7789) {
        display_send_cmd(0x21);
    }
    display_send_cmd(0x29);
    vTaskDelay(pdMS_TO_TICKS(20));

    display_available = true;
    add_event("INFO", "display", "Local display initialized driver=%d size=%dx%d", APPLIANCE_V2_DISPLAY_DRIVER, APPLIANCE_V2_DISPLAY_WIDTH, APPLIANCE_V2_DISPLAY_HEIGHT);
#else
    display_available = false;
#endif
}

static void display_update_if_needed(void)
{
    display_snapshot_t snapshot;
    compute_display_state(&snapshot);
#if APPLIANCE_V2_ENABLE_DISPLAY
    static bool drawn_once = false;
    static display_snapshot_t last_snapshot;
    uint64_t now_ms = uptime_ms();
    if (!display_available || now_ms - display_last_update_ms < DISPLAY_REFRESH_MIN_MS) {
        return;
    }
    if (!drawn_once || display_snapshot_changed(&snapshot, &last_snapshot)) {
        display_draw_snapshot(&snapshot);
        last_snapshot = snapshot;
        drawn_once = true;
        display_last_update_ms = now_ms;
    }
#else
    display_last_update_ms = uptime_ms();
#endif
}

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
    if (in == NULL) {
        out[0] = '\0';
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
    if (level == NULL) {
        level = "INFO";
    }
    if (source == NULL) {
        source = "app";
    }
    if (fmt == NULL) {
        fmt = "event";
    }
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
    } else if (strcmp(route, "/clients") == 0) {
        traffic.clients++;
    } else if (strcmp(route, "/api/clients") == 0) {
        traffic.api_clients++;
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
    if (out == NULL || out_len == 0) {
        return;
    }
    strlcpy(out, "n/d", out_len);
    if (req == NULL) {
        return;
    }
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
    if (route == NULL) {
        route = "n/d";
    }
    if (note == NULL) {
        note = "";
    }
    char ip[24];
    char agent[64] = "n/d";
    request_client_ip(req, ip, sizeof(ip));
    if (httpd_req_get_hdr_value_str(req, "User-Agent", agent, sizeof(agent)) != ESP_OK) {
        strlcpy(agent, "n/d", sizeof(agent));
    }
    if (level != NULL && strcmp(level, "SECURITY") == 0) {
        uint64_t now_ms = uptime_ms();
        if (state_mutex != NULL) {
            xSemaphoreTake(state_mutex, portMAX_DELAY);
            display_note_attack(now_ms);
            xSemaphoreGive(state_mutex);
        } else {
            display_note_attack(now_ms);
        }
    }
    add_event(level, "http", "GET %s from %s ua=%s %s", route, ip, agent, note);
}

static void sntp_sync_callback(struct timeval *tv)
{
    (void)tv;
    time_synchronized = true;
    sntp_sync_event_pending = true;
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


static uint32_t hash_domain(const char *domain)
{
    uint32_t hash = 2166136261U;
    if (domain == NULL) {
        return hash;
    }
    for (size_t i = 0; domain[i] != '\0'; i++) {
        char c = domain[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c + 32);
        }
        hash ^= (uint8_t)c;
        hash *= 16777619U;
    }
    return hash == 0 ? 1U : hash;
}

static const char *risk_classification(uint8_t score)
{
    if (score >= 15U) {
        return "suspeito";
    }
    if (score >= 5U) {
        return "atencao";
    }
    return "baixo";
}

static void ids_add_score_locked(ids_client_t *client, uint8_t delta, const char *label)
{
    if (client == NULL || delta == 0) {
        return;
    }
    uint16_t next = (uint16_t)client->risk_score + delta;
    client->risk_score = next > IDS_RISK_MAX ? IDS_RISK_MAX : (uint8_t)next;
    if (label != NULL) {
        strlcpy(client->last_event_label, label, sizeof(client->last_event_label));
    }
}

static ids_client_t *ids_get_client_locked(const char *client_ip, uint64_t now_ms)
{
    ids_client_t *oldest = &ids_clients[0];
    for (uint32_t i = 0; i < IDS_CLIENT_CAPACITY; i++) {
        ids_client_t *client = &ids_clients[i];
        if (client->active && strcmp(client->client_ip, client_ip) == 0) {
            return client;
        }
        if (!client->active) {
            memset(client, 0, sizeof(*client));
            client->active = true;
            strlcpy(client->client_ip, client_ip, sizeof(client->client_ip));
            client->first_seen_ms = now_ms;
            client->last_seen_ms = now_ms;
            strlcpy(client->last_event_label, "observed", sizeof(client->last_event_label));
            total_clients_seen++;
            return client;
        }
        if (client->last_seen_ms < oldest->last_seen_ms) {
            oldest = client;
        }
    }

    memset(oldest, 0, sizeof(*oldest));
    oldest->active = true;
    strlcpy(oldest->client_ip, client_ip, sizeof(oldest->client_ip));
    oldest->first_seen_ms = now_ms;
    oldest->last_seen_ms = now_ms;
    strlcpy(oldest->last_event_label, "observed_reused_slot", sizeof(oldest->last_event_label));
    total_clients_seen++;
    return oldest;
}

static bool ids_record_unique_domain_locked(ids_client_t *client, const char *domain)
{
    if (client == NULL || domain == NULL || domain[0] == '\0') {
        return false;
    }
    uint32_t hash = hash_domain(domain);
    for (uint32_t i = 0; i < IDS_DOMAIN_HASH_CAPACITY; i++) {
        if (client->domain_hashes[i] == hash) {
            return false;
        }
    }
    client->domain_hashes[client->domain_hash_write_index] = hash;
    client->domain_hash_write_index = (client->domain_hash_write_index + 1U) % IDS_DOMAIN_HASH_CAPACITY;
    if (client->unique_domain_count < UINT16_MAX) {
        client->unique_domain_count++;
    }
    return true;
}

static void ids_record_dns_query_locked(const char *client_ip, const char *domain, bool suspicious, uint64_t now_ms, bool *burst_detected)
{
    if (burst_detected != NULL) {
        *burst_detected = false;
    }
    ids_client_t *client = ids_get_client_locked(client_ip, now_ms);
    client->last_seen_ms = now_ms;
    client->dns_query_count++;
    strlcpy(client->last_domain, domain, sizeof(client->last_domain));

    if (suspicious) {
        client->suspicious_dns_count++;
        ids_add_score_locked(client, 5U, "suspicious_dns");
    }

    bool new_domain = ids_record_unique_domain_locked(client, domain);
    if (new_domain && client->unique_domain_count >= IDS_UNIQUE_DOMAIN_THRESHOLD && !client->unique_risk_applied) {
        ids_add_score_locked(client, 2U, "many_unique_domains");
        client->unique_risk_applied = true;
    }

    if (client->burst_window_start_ms == 0 || now_ms - client->burst_window_start_ms > IDS_DNS_BURST_WINDOW_MS) {
        client->burst_window_start_ms = now_ms;
        client->burst_window_count = 1;
    } else if (client->burst_window_count < UINT16_MAX) {
        client->burst_window_count++;
    }

    if (client->burst_window_count >= IDS_DNS_BURST_THRESHOLD &&
        (client->last_burst_event_ms == 0 || now_ms - client->last_burst_event_ms >= IDS_DNS_BURST_COOLDOWN_MS)) {
        ids_add_score_locked(client, 1U, "dns_burst");
        client->last_burst_event_ms = now_ms;
        dns_burst_count++;
        if (burst_detected != NULL) {
            *burst_detected = true;
        }
    }
}

static void ids_summary_locked(uint32_t *active_clients, uint8_t *highest_score, char *highest_client, size_t highest_client_len, char *last_domain, size_t last_domain_len)
{
    uint32_t active = 0;
    uint8_t high_score = 0;
    const ids_client_t *high = NULL;
    const ids_client_t *last = NULL;
    for (uint32_t i = 0; i < IDS_CLIENT_CAPACITY; i++) {
        const ids_client_t *client = &ids_clients[i];
        if (!client->active) {
            continue;
        }
        active++;
        if (high == NULL || client->risk_score > high_score) {
            high = client;
            high_score = client->risk_score;
        }
        if (last == NULL || client->last_seen_ms > last->last_seen_ms) {
            last = client;
        }
    }
    if (active_clients != NULL) {
        *active_clients = active;
    }
    if (highest_score != NULL) {
        *highest_score = high_score;
    }
    if (highest_client != NULL && highest_client_len > 0) {
        strlcpy(highest_client, high != NULL ? high->client_ip : "n/d", highest_client_len);
    }
    if (last_domain != NULL && last_domain_len > 0) {
        strlcpy(last_domain, last != NULL ? last->last_domain : "", last_domain_len);
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
    if (domain != NULL && domain_len > 0) {
        domain[0] = '\0';
    }
    if (qtype != NULL) {
        *qtype = 0;
    }
    if (packet == NULL || domain == NULL || qtype == NULL || len < 17 || len > DNS_PACKET_MAX || domain_len == 0) {
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
    if (client == NULL) {
        client = "n/d";
    }
    if (domain == NULL || domain[0] == '\0') {
        return;
    }
    if (query_type == NULL) {
        query_type = "OTHER";
    }
    char timestamp[TIMESTAMP_LEN];
    char label[16];
    bool synced = false;
    bool suspicious = is_suspicious_domain(domain);
    bool first_observed = false;
    bool burst_detected = false;
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
    ids_record_dns_query_locked(client, domain, suspicious, now_ms, &burst_detected);
    if (suspicious) {
        display_note_suspicious_dns(domain, now_ms);
    }
    if (burst_detected) {
        display_note_attack(now_ms);
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
    if (burst_detected) {
        add_event("SECURITY", "ids", "DNS burst detected from %s", client);
    }
}

static int forward_dns_once(const uint8_t *query, ssize_t query_len, uint8_t *response, size_t response_len, const char *server_ip)
{
    if (query == NULL || response == NULL || server_ip == NULL || query_len <= 0 || query_len > DNS_PACKET_MAX || response_len < DNS_PACKET_MAX) {
        return -1;
    }
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        return -1;
    }
    struct timeval timeout = {.tv_sec = 0, .tv_usec = 700000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    struct sockaddr_in upstream = {0};
    upstream.sin_family = AF_INET;
    upstream.sin_port = htons(53);
    if (inet_pton(AF_INET, server_ip, &upstream.sin_addr) != 1) {
        close(sock);
        return -1;
    }

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
    uint8_t *query = calloc(1, DNS_PACKET_MAX);
    uint8_t *response = calloc(1, DNS_PACKET_MAX);
    if (query == NULL || response == NULL) {
        add_event("ERROR", "dns", "DNS proxy buffer allocation failed");
        free(query);
        free(response);
        vTaskDelete(NULL);
        return;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        add_event("ERROR", "dns", "DNS proxy socket creation failed");
        free(query);
        free(response);
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
        free(query);
        free(response);
        vTaskDelete(NULL);
        return;
    }

    dns_monitoring_enabled = true;
    add_event("INFO", "dns", "DNS monitor/proxy started on UDP port %d", DNS_PROXY_PORT);

    while (true) {
        struct sockaddr_in client_addr = {0};
        socklen_t client_len = sizeof(client_addr);
        ssize_t len = recvfrom(sock, query, DNS_PACKET_MAX, 0, (struct sockaddr *)&client_addr, &client_len);
        if (len <= 0 || len > DNS_PACKET_MAX) {
            continue;
        }

        char client_ip[DNS_CLIENT_LEN] = "n/d";
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        char domain[DNS_DOMAIN_LEN] = "";
        uint16_t qtype = 0;
        if (parse_dns_query(query, len, domain, sizeof(domain), &qtype) && (qtype == 1 || qtype == 28)) {
            record_dns_query(client_ip, domain, dns_query_type_label(qtype));
        }

        int resp_len = forward_dns_once(query, len, response, DNS_PACKET_MAX, "1.1.1.1");
        if (resp_len <= 0) {
            resp_len = forward_dns_once(query, len, response, DNS_PACKET_MAX, "8.8.8.8");
        }
        if (resp_len > 0 && resp_len <= DNS_PACKET_MAX) {
            sendto(sock, response, resp_len, 0, (struct sockaddr *)&client_addr, client_len);
        }
    }
}

static void start_dns_proxy(void)
{
    BaseType_t ok = xTaskCreatePinnedToCore(dns_proxy_task, "dnsProxy", 6144, NULL, 4, &dns_task_handle, 0);
    if (ok != pdPASS) {
        dns_task_handle = NULL;
        add_event("ERROR", "dns", "DNS proxy task creation failed");
    }
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

        if (upstream_configured && sta_retry_count < STA_MAXIMUM_RETRY && !sta_reconnect_pending) {
            sta_retry_count++;
            sta_reconnect_pending = true;
            sta_next_reconnect_ms = uptime_ms() + (uint64_t)(2000U * sta_retry_count);
            add_event("INFO", "wifi", "STA reconnect scheduled %u/%u", sta_retry_count, STA_MAXIMUM_RETRY);
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
        sta_reconnect_pending = false;
        sta_retry_count = 0;
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
        "['NAT',s.nat.active?'ativo':(s.nat.attempted?'falhou':'inativo')],['Display',(s.display&&s.display.enabled?(s.display.available?'ok':'indisp'):'off')+' / '+(s.display?s.display.state:'n/d')],['Clientes AP',s.clients.count],['Clientes observados',s.clients_observed.total_clients_seen],['Maior risk',s.clients_observed.highest_risk_score],"
        "['Requests',s.traffic.total],['DNS queries',s.dns.total_queries],['Último domínio IDS',s.clients_observed.last_domain||'n/d'],['Último domínio',s.dns.last_domain||'n/d'],['Horário',s.time.synced?s.time.timestamp:'unsynced'],['404',s.traffic.not_found],['Sensitive',s.traffic.sensitive_path_hits],['Scan',s.traffic.suspicious_scan_count],['Heap',s.heap_free],['Última rota',s.traffic.last_route]"
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
        "DNS: /dns e /api/dns\n"
        "Clientes: /clients e /api/clients\n");
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
    uint32_t ids_active_clients = 0;
    uint8_t ids_highest_score = 0;
    uint32_t total_clients_seen_snapshot = total_clients_seen;
    uint64_t dns_burst_snapshot = dns_burst_count;
    char ids_highest_client[DNS_CLIENT_LEN];
    char ids_last_domain[DNS_DOMAIN_LEN];
    ids_summary_locked(&ids_active_clients, &ids_highest_score, ids_highest_client, sizeof(ids_highest_client), ids_last_domain, sizeof(ids_last_domain));
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

    display_snapshot_t display_snapshot;
    compute_display_state(&display_snapshot);

    char project_json[64];
    char version_json[24];
    char ap_ssid_json[40];
    char last_route_json[LAST_ROUTE_LEN * 2];
    char time_json[TIMESTAMP_LEN * 2];
    char dns_domain_json[DNS_DOMAIN_LEN * 2];
    char dns_client_json[DNS_CLIENT_LEN * 2];
    char dns_type_json[DNS_QUERY_TYPE_LEN * 2];
    char ids_highest_client_json[DNS_CLIENT_LEN * 2];
    char ids_last_domain_json[DNS_DOMAIN_LEN * 2];
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
    json_escape_string(ids_highest_client, ids_highest_client_json, sizeof(ids_highest_client_json));
    json_escape_string(ids_last_domain, ids_last_domain_json, sizeof(ids_last_domain_json));

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
        "\"clients_observed\":{\"active\":%lu,\"total_clients_seen\":%lu,\"highest_risk_score\":%u,\"highest_risk_client\":\"%s\",\"last_domain\":\"%s\",\"dns_burst_count\":%llu,\"suspicious_dns_count\":%llu},"
        "\"ids\":{\"active_clients\":%lu,\"total_clients_seen\":%lu,\"highest_risk_score\":%u,\"highest_risk_client\":\"%s\",\"dns_burst_count\":%llu,\"suspicious_dns_count\":%llu},"
        "\"dns\":{\"monitoring_enabled\":%s,\"total_queries\":%llu,\"suspicious_count\":%llu,\"last_domain\":\"%s\",\"last_client\":\"%s\",\"last_query_type\":\"%s\"},"
        "\"traffic\":{\"total\":%llu,\"root\":%llu,\"status\":%llu,\"api\":%llu,\"api_status\":%llu,\"logs\":%llu,\"api_events\":%llu,\"traffic\":%llu,\"report\":%llu,\"clients\":%llu,\"api_clients\":%llu,\"demo\":%llu,\"demo_scan\":%llu,\"demo_security\":%llu,\"demo_info\":%llu,\"favicon\":%llu,\"not_found\":%llu,\"sensitive_path_hits\":%llu,\"suspicious_scan_count\":%llu,\"demo_scan_count\":%llu,\"last_route\":\"%s\",\"top_routes\":[",
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
        (unsigned long)ids_active_clients,
        (unsigned long)total_clients_seen_snapshot,
        ids_highest_score,
        ids_highest_client_json,
        ids_last_domain_json,
        (unsigned long long)dns_burst_snapshot,
        (unsigned long long)suspicious_dns_snapshot,
        (unsigned long)ids_active_clients,
        (unsigned long)total_clients_seen_snapshot,
        ids_highest_score,
        ids_highest_client_json,
        (unsigned long long)dns_burst_snapshot,
        (unsigned long long)suspicious_dns_snapshot,
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
        (unsigned long long)traffic_snapshot.clients,
        (unsigned long long)traffic_snapshot.api_clients,
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
        "\"display\":{\"enabled\":%s,\"available\":%s,\"state\":\"%s\",\"last_update_ms\":%llu},"
        "\"limitations\":[\"events_only_in_ram\",\"no_firewall_professional\",\"no_https_inspection\",\"nat_requires_sta_ip\"]}",
        (unsigned long)event_count_snapshot,
        EVENT_CAPACITY,
        ROUTE_TRACK_CAPACITY,
        APPLIANCE_V2_ENABLE_DISPLAY ? "true" : "false",
        display_available ? "true" : "false",
        display_state_name(display_snapshot.state),
        (unsigned long long)display_last_update_ms);

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

    dns_query_t *snapshot = calloc(DNS_RECENT_CAPACITY, sizeof(dns_query_t));
    if (snapshot == NULL) {
        free(json);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no memory");
        return ESP_FAIL;
    }
    uint32_t count_snapshot;
    uint32_t write_snapshot;
    uint64_t total_snapshot;
    uint64_t suspicious_snapshot;
    bool enabled_snapshot;

    xSemaphoreTake(state_mutex, portMAX_DELAY);
    memcpy(snapshot, dns_queries, DNS_RECENT_CAPACITY * sizeof(dns_query_t));
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
    free(snapshot);
    free(json);
    return ret;
}


static esp_err_t api_clients_handler(httpd_req_t *req)
{
    increment_route_counter("/api/clients");
    char *json = calloc(1, 8192);
    ids_client_t *snapshot = calloc(IDS_CLIENT_CAPACITY, sizeof(ids_client_t));
    if (json == NULL || snapshot == NULL) {
        free(json);
        free(snapshot);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "no memory");
        return ESP_FAIL;
    }

    uint32_t total_seen_snapshot = 0;
    uint64_t burst_snapshot = 0;
    uint64_t suspicious_snapshot = 0;
    xSemaphoreTake(state_mutex, portMAX_DELAY);
    memcpy(snapshot, ids_clients, IDS_CLIENT_CAPACITY * sizeof(ids_client_t));
    total_seen_snapshot = total_clients_seen;
    burst_snapshot = dns_burst_count;
    suspicious_snapshot = suspicious_dns_count;
    xSemaphoreGive(state_mutex);

    size_t used = snprintf(json, 8192,
        "{\"total_clients_seen\":%lu,\"dns_burst_count\":%llu,\"suspicious_dns_count\":%llu,\"clients\":[",
        (unsigned long)total_seen_snapshot,
        (unsigned long long)burst_snapshot,
        (unsigned long long)suspicious_snapshot);

    bool first = true;
    for (uint32_t i = 0; i < IDS_CLIENT_CAPACITY && used < 7800; i++) {
        ids_client_t *client = &snapshot[i];
        if (!client->active) {
            continue;
        }
        char ip_json[DNS_CLIENT_LEN * 2];
        char domain_json[DNS_DOMAIN_LEN * 2];
        char event_json[IDS_EVENT_LABEL_LEN * 2];
        char first_label[16];
        char last_label[16];
        json_escape_string(client->client_ip, ip_json, sizeof(ip_json));
        json_escape_string(client->last_domain, domain_json, sizeof(domain_json));
        json_escape_string(client->last_event_label, event_json, sizeof(event_json));
        format_uptime_label(client->first_seen_ms, first_label, sizeof(first_label));
        format_uptime_label(client->last_seen_ms, last_label, sizeof(last_label));
        used += snprintf(json + used, 8192 - used,
            "%s{\"client_ip\":\"%s\",\"first_seen_ms\":%llu,\"first_seen\":\"%s\",\"last_seen_ms\":%llu,\"last_seen\":\"%s\",\"dns_query_count\":%llu,\"suspicious_dns_count\":%lu,\"unique_domain_count\":%u,\"last_domain\":\"%s\",\"risk_score\":%u,\"classification\":\"%s\",\"last_event_label\":\"%s\"}",
            first ? "" : ",",
            ip_json,
            (unsigned long long)client->first_seen_ms,
            first_label,
            (unsigned long long)client->last_seen_ms,
            last_label,
            (unsigned long long)client->dns_query_count,
            (unsigned long)client->suspicious_dns_count,
            client->unique_domain_count,
            domain_json,
            client->risk_score,
            risk_classification(client->risk_score),
            event_json);
        first = false;
    }

    snprintf(json + used, 8192 - used,
        "],\"limitations\":[\"ram_only\",\"dns_metadata_only\",\"no_https_content_inspection\",\"small_client_capacity\",\"approximate_unique_domains\",\"heuristic_score_only\"]}");
    httpd_resp_set_type(req, "application/json");
    esp_err_t ret = httpd_resp_sendstr(req, json);
    free(snapshot);
    free(json);
    return ret;
}

static esp_err_t clients_handler(httpd_req_t *req)
{
    increment_route_counter("/clients");
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr_chunk(req, "<!doctype html><html lang=\"pt-BR\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Clientes</title><style>");
    httpd_resp_sendstr_chunk(req, html_style);
    httpd_resp_sendstr_chunk(req,
        "</style></head><body><header><h1>Clientes observados</h1><div>IDS didático baseado em metadados DNS dos clientes do AP.</div>"
        "<nav><a href=\"/\">Dashboard</a><a href=\"/traffic\">Traffic</a><a href=\"/dns\">DNS</a><a href=\"/logs\">Logs</a><a href=\"/api/clients\">JSON</a></nav></header>"
        "<main><section class=\"grid\" id=\"cards\"></section><section class=\"card\"><h2>Tabela de clientes</h2><table><thead><tr><th>IP</th><th>Primeiro visto</th><th>Último visto</th><th>DNS</th><th>Suspeitas</th><th>Último domínio</th><th>Score</th><th>Classificação</th></tr></thead><tbody id=\"clientRows\"></tbody></table></section>"
        "<section class=\"card\"><p>O score é heurístico e didático. O sistema usa DNS/metadados observáveis e não inspeciona conteúdo HTTPS.</p></section></main>"
        "<script>function escapeHtml(v){return String(v==null?'':v).replace(/[&<>\"']/g,function(c){return c==='&'?'&amp;':c==='<'?'&lt;':c==='>'?'&gt;':c==='\"'?'&quot;':'&#39;';});}"
        "function card(label,value){return '<div class=\"card\"><div class=\"label\">'+escapeHtml(label)+'</div><div class=\"value\">'+escapeHtml(value)+'</div></div>'; }"
        "function row(x){return '<tr><td>'+escapeHtml(x.client_ip)+'</td><td>'+escapeHtml(x.first_seen)+'</td><td>'+escapeHtml(x.last_seen)+'</td><td>'+Number(x.dns_query_count||0)+'</td><td>'+Number(x.suspicious_dns_count||0)+'</td><td><code>'+escapeHtml(x.last_domain||'n/d')+'</code></td><td>'+Number(x.risk_score||0)+'</td><td>'+escapeHtml(x.classification)+'</td></tr>'; }"
        "async function load(){const d=await fetch('/api/clients').then(r=>r.json());const cs=d.clients||[];const high=cs.reduce((a,c)=>Number(c.risk_score||0)>Number(a.risk_score||0)?c:a,{});cards.innerHTML=[['Clientes vistos',d.total_clients_seen],['Ativos em RAM',cs.length],['Maior score',high.risk_score||0],['Cliente maior risco',high.client_ip||'n/d'],['DNS burst',d.dns_burst_count],['DNS suspeito',d.suspicious_dns_count]].map(c=>card(c[0],c[1])).join('');clientRows.innerHTML=cs.map(row).join('');}load();setInterval(load,5000);</script></body></html>");
    return httpd_resp_sendstr_chunk(req, NULL);
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
        "<nav><a href=\"/\">Dashboard</a><a href=\"/logs\">Logs</a><a href=\"/clients\">Clientes</a><a href=\"/demo/scan\">Demo scan</a><a href=\"/api/status\">JSON</a></nav></header>"
        "<main><section class=\"grid\" id=\"cards\"></section><section class=\"card\"><h2>Top routes</h2><table><thead><tr><th>Rota</th><th>Hits</th></tr></thead><tbody id=\"routes\"></tbody></table></section></main>"
        "<script>function escapeHtml(v){return String(v==null?'':v).replace(/[&<>\"']/g,function(c){return c==='&'?'&amp;':c==='<'?'&lt;':c==='>'?'&gt;':c==='\"'?'&quot;':'&#39;';});}function card(label,value){return '<div class=\"card\"><div class=\"label\">'+escapeHtml(label)+'</div><div class=\"value\">'+escapeHtml(value)+'</div></div>'; }function routeRow(x){return '<tr><td><code>'+escapeHtml(x.route)+'</code></td><td>'+Number(x.count||0)+'</td></tr>'; }async function load(){const s=await fetch('/api/status').then(r=>r.json());cards.innerHTML=[['Total requests',s.traffic.total],['DNS queries',s.dns.total_queries],['Clientes observados',s.clients_observed.total_clients_seen],['Maior score',s.clients_observed.highest_risk_score],['DNS burst',s.clients_observed.dns_burst_count],['Último domínio',s.dns.last_domain||'n/d'],['Último cliente DNS',s.dns.last_client||'n/d'],['DNS suspeito',s.dns.suspicious_count],['404',s.traffic.not_found],['Sensíveis',s.traffic.sensitive_path_hits],['Scan suspeito',s.traffic.suspicious_scan_count],['Demo scan',s.traffic.demo_scan_count],['Última rota',s.traffic.last_route]].map(c=>card(c[0],c[1])).join('');routes.innerHTML=(s.traffic.top_routes||[]).map(routeRow).join('');}load();setInterval(load,5000);</script></body></html>");
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
        "<section class=\"card\"><h2>DNS/Tráfego observado</h2><table><tr><td>Monitor DNS</td><td>Registra consultas de domínio feitas por clientes do AP via proxy DNS local.</td></tr><tr><td>Privacidade</td><td>HTTPS continua criptografado; o sistema não lê conteúdo das páginas.</td></tr><tr><td>Escopo</td><td>Detecção didática por domínios de teste suspeitos, sem bloqueio nesta sprint.</td></tr></table></section><section class=\"card\"><h2>Clientes e risco didático</h2><table><tr><td>Score</td><td>Heurística didática em RAM: +5 por domínio suspeito, +1 por burst DNS e +2 por muitos domínios únicos aproximados.</td></tr><tr><td>Classificação</td><td>0-4 baixo, 5-14 atenção, 15+ suspeito.</td></tr><tr><td>Limitação</td><td>Usa DNS/metadados observáveis e não inspeciona HTTPS nem conteúdo de páginas.</td></tr></table></section></main>"
        "<script>function escapeHtml(v){return String(v==null?'':v).replace(/[&<>\"']/g,function(c){return c==='&'?'&amp;':c==='<'?'&lt;':c==='>'?'&gt;':c==='\"'?'&quot;':'&#39;';});}"
        "function card(label,value){return '<div class=\"card\"><div class=\"label\">'+escapeHtml(label)+'</div><div class=\"value\">'+escapeHtml(value)+'</div></div>'; }"
        "fetch('/api/status').then(r=>r.json()).then(s=>cards.innerHTML=[['Projeto',s.project],['Versão',s.version],['NAT',s.nat.active?'ativo':'inativo'],['Upstream',s.upstream.connected?s.upstream.ip:'n/d'],['Display',(s.display&&s.display.enabled?(s.display.available?'ok':'indisp'):'off')+' / '+(s.display?s.display.state:'n/d')],['Horário',s.time.synced?s.time.timestamp:'unsynced'],['Heap livre',s.heap_free],['Requests',s.traffic.total],['DNS queries',s.dns.total_queries],['Último domínio IDS',s.clients_observed.last_domain||'n/d'],['DNS suspeito',s.dns.suspicious_count],['Último domínio',s.dns.last_domain||'n/d']].map(c=>card(c[0],c[1])).join(''));</script></body></html>");
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
        "{\"path\":\"/api/dns\",\"type\":\"dns\"},{\"path\":\"/api/clients\",\"type\":\"clients\"},"
        "{\"path\":\"/traffic\",\"type\":\"html\"},"
        "{\"path\":\"/dns\",\"type\":\"html\"},{\"path\":\"/clients\",\"type\":\"html\"},"
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
    config.stack_size = 12288;
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
        {.uri = "/api/clients", .method = HTTP_GET, .handler = api_clients_handler, .user_ctx = NULL},
        {.uri = "/dns", .method = HTTP_GET, .handler = dns_handler, .user_ctx = NULL},
        {.uri = "/clients", .method = HTTP_GET, .handler = clients_handler, .user_ctx = NULL},
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

static void service_deferred_events(void)
{
    if (sntp_sync_event_pending) {
        sntp_sync_event_pending = false;
        snapshot_time(last_timestamp, sizeof(last_timestamp), NULL);
        add_event("INFO", "time", "SNTP synchronized: %s", last_timestamp);
    }

    if (sta_reconnect_pending && upstream_configured && !upstream_connected && uptime_ms() >= sta_next_reconnect_ms) {
        sta_reconnect_pending = false;
        upstream_connecting = true;
        add_event("INFO", "wifi", "STA reconnect attempt %u/%u", sta_retry_count, STA_MAXIMUM_RETRY);
        esp_wifi_connect();
    }
}

static void log_runtime_diagnostics(const char *phase)
{
    if (phase == NULL) {
        phase = "runtime";
    }
    add_event("INFO", "diag", "%s heap_free=%lu heap_min=%lu main_stack_hwm=%lu dns_stack_hwm=%lu",
              phase,
              (unsigned long)esp_get_free_heap_size(),
              (unsigned long)esp_get_minimum_free_heap_size(),
              (unsigned long)uxTaskGetStackHighWaterMark(NULL),
              dns_task_handle != NULL ? (unsigned long)uxTaskGetStackHighWaterMark(dns_task_handle) : 0UL);
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
    display_init();
    log_runtime_diagnostics("after_services_start");

    while (true) {
        service_deferred_events();
        display_update_if_needed();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
