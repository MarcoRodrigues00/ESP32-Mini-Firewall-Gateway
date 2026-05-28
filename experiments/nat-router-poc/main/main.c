#include <stdbool.h>
#include <string.h>

#include "config.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "nvs_flash.h"
#include "dhcpserver/dhcpserver.h"
#include "lwip/inet.h"
#include "lwip/lwip_napt.h"
#include "lwip/opt.h"

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_FAIL_BIT BIT1
#define STA_MAXIMUM_RETRY 8
#define UPSTREAM_CONNECT_TIMEOUT_MS 45000
#define AP_DNS_PRIMARY_A 1
#define AP_DNS_PRIMARY_B 1
#define AP_DNS_PRIMARY_C 1
#define AP_DNS_PRIMARY_D 1
#define AP_DNS_FALLBACK_A 8
#define AP_DNS_FALLBACK_B 8
#define AP_DNS_FALLBACK_C 8
#define AP_DNS_FALLBACK_D 8

static const char *TAG = "nat_poc";
static EventGroupHandle_t wifi_event_group;
static int retry_count = 0;
static esp_netif_t *ap_netif = NULL;
static esp_netif_t *sta_netif = NULL;
static bool upstream_configured = false;
static bool upstream_connecting = false;
static bool upstream_has_ip = false;
static bool napt_active = false;
static bool napt_attempted = false;
static uint8_t last_disconnect_reason = 0;
static esp_netif_dns_info_t ap_dns_info = { .ip = ESP_IP4ADDR_INIT(AP_DNS_PRIMARY_A, AP_DNS_PRIMARY_B, AP_DNS_PRIMARY_C, AP_DNS_PRIMARY_D) };
static esp_netif_dns_info_t ap_dns_backup_info = { .ip = ESP_IP4ADDR_INIT(AP_DNS_FALLBACK_A, AP_DNS_FALLBACK_B, AP_DNS_FALLBACK_C, AP_DNS_FALLBACK_D) };

static bool is_upstream_configured(void)
{
    return strlen(NAT_POC_UPSTREAM_SSID) > 0 && strcmp(NAT_POC_UPSTREAM_SSID, "YOUR_UPSTREAM_WIFI") != 0;
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
    case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY:
        return "no ap found with compatible security";
    case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD:
        return "no ap found in authmode threshold";
    case WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD:
        return "no ap found in rssi threshold";
    default:
        return "other";
    }
}

static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    (void)arg;
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        ESP_LOGI(TAG, "WIFI_EVENT_STA_START: upstream ssid=%s", NAT_POC_UPSTREAM_SSID);
        if (upstream_configured) {
            upstream_connecting = true;
            ESP_LOGI(TAG, "STA connecting to upstream ssid=%s", NAT_POC_UPSTREAM_SSID);
            esp_wifi_connect();
        } else {
            upstream_connecting = false;
            ESP_LOGW(TAG, "STA upstream not configured. Set NAT_POC_UPSTREAM_SSID in include/config.local.h");
        }
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED) {
        wifi_event_sta_connected_t *event = (wifi_event_sta_connected_t *)event_data;
        ESP_LOGI(TAG, "WIFI_EVENT_STA_CONNECTED: upstream ssid=%s channel=%d authmode=%d", NAT_POC_UPSTREAM_SSID, event->channel, event->authmode);
        upstream_connecting = true;
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *event = (wifi_event_sta_disconnected_t *)event_data;
        last_disconnect_reason = event->reason;
        upstream_has_ip = false;
        napt_active = false;
        xEventGroupClearBits(wifi_event_group, WIFI_CONNECTED_BIT);
        ESP_LOGW(TAG, "WIFI_EVENT_STA_DISCONNECTED: upstream ssid=%s reason=%u (%s)", NAT_POC_UPSTREAM_SSID, event->reason, wifi_reason_description(event->reason));
        if (!upstream_configured) {
            upstream_connecting = false;
            ESP_LOGW(TAG, "STA reconnect skipped because upstream is not configured");
            return;
        }
        if (retry_count < STA_MAXIMUM_RETRY) {
            ++retry_count;
            upstream_connecting = true;
            ESP_LOGW(TAG, "STA reconnect retry %d/%d", retry_count, STA_MAXIMUM_RETRY);
            esp_wifi_connect();
        } else {
            upstream_connecting = false;
            ESP_LOGE(TAG, "STA retries exhausted. Last reason=%u (%s)", last_disconnect_reason, wifi_reason_description(last_disconnect_reason));
            xEventGroupSetBits(wifi_event_group, WIFI_FAIL_BIT);
        }
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STACONNECTED) {
        wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
        ESP_LOGI(TAG, "WIFI_EVENT_AP_STACONNECTED: AP client connected, aid=%d", event->aid);
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_AP_STADISCONNECTED) {
        wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
        ESP_LOGI(TAG, "WIFI_EVENT_AP_STADISCONNECTED: AP client disconnected, aid=%d", event->aid);
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
        retry_count = 0;
        upstream_connecting = false;
        upstream_has_ip = true;
        ESP_LOGI(TAG, "IP_EVENT_STA_GOT_IP: upstream ssid=%s", NAT_POC_UPSTREAM_SSID);
        ESP_LOGI(TAG, "STA IP: " IPSTR, IP2STR(&event->ip_info.ip));
        ESP_LOGI(TAG, "STA gateway: " IPSTR, IP2STR(&event->ip_info.gw));
        ESP_LOGI(TAG, "STA netmask: " IPSTR, IP2STR(&event->ip_info.netmask));
        xEventGroupSetBits(wifi_event_group, WIFI_CONNECTED_BIT);
    }
}

static void configure_ap_ip_and_dns(void)
{
    esp_netif_ip_info_t ip_info;
    IP4_ADDR(&ip_info.ip, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.gw, 192, 168, 4, 1);
    IP4_ADDR(&ip_info.netmask, 255, 255, 255, 0);

    esp_netif_dns_info_t dns_primary = { .ip = ESP_IP4ADDR_INIT(AP_DNS_PRIMARY_A, AP_DNS_PRIMARY_B, AP_DNS_PRIMARY_C, AP_DNS_PRIMARY_D) };
    esp_netif_dns_info_t dns_fallback = { .ip = ESP_IP4ADDR_INIT(AP_DNS_FALLBACK_A, AP_DNS_FALLBACK_B, AP_DNS_FALLBACK_C, AP_DNS_FALLBACK_D) };
    dhcps_offer_t dhcps_dns_offer = OFFER_DNS;

    ESP_ERROR_CHECK(esp_netif_dhcps_stop(ap_netif));
    ESP_ERROR_CHECK(esp_netif_set_ip_info(ap_netif, &ip_info));
    ESP_ERROR_CHECK(esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_MAIN, &dns_primary));
    ESP_ERROR_CHECK(esp_netif_set_dns_info(ap_netif, ESP_NETIF_DNS_BACKUP, &dns_fallback));
    ap_dns_info = dns_primary;
    ap_dns_backup_info = dns_fallback;

    ESP_ERROR_CHECK(esp_netif_dhcps_option(
        ap_netif,
        ESP_NETIF_OP_SET,
        ESP_NETIF_DOMAIN_NAME_SERVER,
        &dhcps_dns_offer,
        sizeof(dhcps_dns_offer)));

    ESP_ERROR_CHECK(esp_netif_dhcps_start(ap_netif));
    ESP_LOGI(TAG, "AP IP: " IPSTR, IP2STR(&ip_info.ip));
    ESP_LOGI(TAG, "AP DHCP gateway: " IPSTR, IP2STR(&ip_info.gw));
    ESP_LOGI(TAG, "AP DNS configured on netif: primary=" IPSTR " backup=" IPSTR, IP2STR(&ap_dns_info.ip.u_addr.ip4), IP2STR(&ap_dns_backup_info.ip.u_addr.ip4));
    ESP_LOGI(TAG, "AP DHCP server announces DNS: primary=" IPSTR " backup=" IPSTR, IP2STR(&ap_dns_info.ip.u_addr.ip4), IP2STR(&ap_dns_backup_info.ip.u_addr.ip4));
}

static void start_wifi_ap_sta(void)
{
    wifi_event_group = xEventGroupCreate();
    upstream_configured = is_upstream_configured();

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    sta_netif = esp_netif_create_default_wifi_sta();
    ap_netif = esp_netif_create_default_wifi_ap();
    configure_ap_ip_and_dns();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE));
    ESP_LOGI(TAG, "Wi-Fi power save disabled: WIFI_PS_NONE");

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, NULL));

    wifi_config_t sta_config = {0};
    strlcpy((char *)sta_config.sta.ssid, NAT_POC_UPSTREAM_SSID, sizeof(sta_config.sta.ssid));
    strlcpy((char *)sta_config.sta.password, NAT_POC_UPSTREAM_PASSPHRASE, sizeof(sta_config.sta.password));
    sta_config.sta.threshold.authmode = WIFI_AUTH_OPEN;
    sta_config.sta.pmf_cfg.capable = true;
    sta_config.sta.pmf_cfg.required = false;

    wifi_config_t ap_config = {0};
    strlcpy((char *)ap_config.ap.ssid, NAT_POC_AP_SSID, sizeof(ap_config.ap.ssid));
    strlcpy((char *)ap_config.ap.password, NAT_POC_AP_PASSPHRASE, sizeof(ap_config.ap.password));
    ap_config.ap.ssid_len = strlen(NAT_POC_AP_SSID);
    ap_config.ap.channel = NAT_POC_AP_CHANNEL;
    ap_config.ap.max_connection = NAT_POC_AP_MAX_CLIENTS;
    ap_config.ap.authmode = strlen(NAT_POC_AP_PASSPHRASE) == 0 ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA_WPA2_PSK;
    ap_config.ap.pmf_cfg.required = false;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_config));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_LOGI(TAG, "AP started: ssid=%s ip=192.168.4.1 channel=%d dns_primary=" IPSTR " dns_backup=" IPSTR, NAT_POC_AP_SSID, NAT_POC_AP_CHANNEL, IP2STR(&ap_dns_info.ip.u_addr.ip4), IP2STR(&ap_dns_backup_info.ip.u_addr.ip4));
    ESP_LOGI(TAG, "Upstream configured=%s ssid=%s", upstream_configured ? "yes" : "no", NAT_POC_UPSTREAM_SSID);
}

static bool enable_napt_on_ap(void)
{
    napt_attempted = true;
#if IP_NAPT && IP_FORWARD
    esp_netif_ip_info_t ap_ip;
    ESP_ERROR_CHECK(esp_netif_get_ip_info(ap_netif, &ap_ip));
    ip_napt_enable(ap_ip.ip.addr, 1);
    napt_active = true;
    ESP_LOGI(TAG, "NAPT requested on AP IP " IPSTR, IP2STR(&ap_ip.ip));
    ESP_LOGI(TAG, "NAPT active=yes; AP DHCP DNS primary=" IPSTR " backup=" IPSTR, IP2STR(&ap_dns_info.ip.u_addr.ip4), IP2STR(&ap_dns_backup_info.ip.u_addr.ip4));
    return true;
#else
    napt_active = false;
    ESP_LOGE(TAG, "NAPT not compiled in: IP_NAPT=%d IP_FORWARD=%d", IP_NAPT, IP_FORWARD);
    return false;
#endif
}

static void log_periodic_status(void)
{
    wifi_sta_list_t clients;
    uint16_t client_count = 0;
    if (esp_wifi_ap_get_sta_list(&clients) == ESP_OK) {
        client_count = clients.num;
    }

#if IP_NAPT && IP_FORWARD
    const bool napt_compiled = true;
#else
    const bool napt_compiled = false;
#endif

    if (!upstream_configured) {
        ESP_LOGW(TAG, "status: upstream without configuration; AP clients=%u; configure NAT_POC_UPSTREAM_SSID in config.local.h", client_count);
    } else if (upstream_connecting && !upstream_has_ip) {
        ESP_LOGI(TAG, "status: upstream trying to connect; AP clients=%u; last_disconnect_reason=%u (%s)", client_count, last_disconnect_reason, wifi_reason_description(last_disconnect_reason));
    } else if (upstream_has_ip && client_count == 0) {
        ESP_LOGI(TAG, "status: upstream connected, no AP client connected; NAPT active=%s; AP DNS primary=" IPSTR " backup=" IPSTR, napt_active ? "yes" : "no", IP2STR(&ap_dns_info.ip.u_addr.ip4), IP2STR(&ap_dns_backup_info.ip.u_addr.ip4));
    } else if (client_count > 0 && !napt_active) {
        ESP_LOGW(TAG, "status: AP client connected but NAT inactive; upstream_ip=%s napt_compiled=%s attempted=%s", upstream_has_ip ? "yes" : "no", napt_compiled ? "yes" : "no", napt_attempted ? "yes" : "no");
    } else if (!napt_compiled) {
        ESP_LOGE(TAG, "status: NAPT not compiled/supported; AP clients=%u upstream_ip=%s", client_count, upstream_has_ip ? "yes" : "no");
    } else {
        ESP_LOGI(TAG, "status: upstream connected, AP clients=%u, NAPT active=%s, AP DNS primary=" IPSTR " backup=" IPSTR, client_count, napt_active ? "yes" : "no", IP2STR(&ap_dns_info.ip.u_addr.ip4), IP2STR(&ap_dns_backup_info.ip.u_addr.ip4));
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    ESP_LOGI(TAG, "ESP32 NAT Router PoC starting");
    ESP_LOGI(TAG, "This is isolated from the main TDE firmware");
    ESP_LOGI(TAG, "Build flags: IP_NAPT=%d IP_FORWARD=%d", IP_NAPT, IP_FORWARD);

    start_wifi_ap_sta();

    EventBits_t bits = xEventGroupWaitBits(
        wifi_event_group,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE,
        pdFALSE,
        pdMS_TO_TICKS(UPSTREAM_CONNECT_TIMEOUT_MS));

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "Upstream IP received. Starting NAPT after IP_EVENT_STA_GOT_IP.");
        if (enable_napt_on_ap()) {
            ESP_LOGI(TAG, "NAPT enabled. Connect a client to %s and test HTTP/HTTPS browsing.", NAT_POC_AP_SSID);
        } else {
            ESP_LOGE(TAG, "NAPT unavailable in this build. Check sdkconfig and ESP-IDF support.");
        }
    } else if (bits & WIFI_FAIL_BIT) {
        ESP_LOGE(TAG, "Upstream failed before timeout. Last reason=%u (%s). AP remains available, NAT inactive.", last_disconnect_reason, wifi_reason_description(last_disconnect_reason));
    } else {
        ESP_LOGE(TAG, "Upstream timeout after %d ms. AP remains available, NAT inactive.", UPSTREAM_CONNECT_TIMEOUT_MS);
    }

    while (true) {
        log_periodic_status();
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}
