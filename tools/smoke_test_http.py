#!/usr/bin/env python3
"""HTTP smoke test for ESP32 Mini Firewall Gateway.

Uses only Python standard library. It validates the main HTML/JSON routes,
triggers controlled demo events, and writes a Markdown report under evidencias/.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

DEFAULT_BASE_URL = "http://192.168.4.1"
TIMEOUT_SECONDS = 5


class Result:
    def __init__(self, name: str, url: str, passed: bool, detail: str) -> None:
        self.name = name
        self.url = url
        self.passed = passed
        self.detail = detail


def normalize_base_url(value: str) -> str:
    value = value.strip().rstrip("/")
    if not value:
        raise ValueError("base URL vazia")
    return value


def make_url(base_url: str, path: str) -> str:
    return urllib.parse.urljoin(base_url + "/", path.lstrip("/"))


def fetch(url: str, timeout: int = TIMEOUT_SECONDS) -> Tuple[int, str, bytes, str]:
    request = urllib.request.Request(url, headers={"User-Agent": "esp32-smoke-test/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read()
            final_url = response.geturl()
            content_type = response.headers.get("Content-Type", "")
            return response.status, content_type, body, final_url
    except urllib.error.HTTPError as exc:
        body = exc.read()
        return exc.code, exc.headers.get("Content-Type", ""), body, exc.geturl()


def decode_body(body: bytes) -> str:
    return body.decode("utf-8", errors="replace")


def markdown_escape(value: Any) -> str:
    text = str(value).replace("\n", " ").replace("\r", " ")
    return text.replace("|", "\\|")


def has_any_term(text: str, terms: Iterable[str]) -> bool:
    lower = text.lower()
    return any(term.lower() in lower for term in terms)


def add_result(results: List[Result], name: str, url: str, passed: bool, detail: str) -> None:
    results.append(Result(name, url, passed, detail))


def check_html(results: List[Result], base_url: str, path: str, terms: Iterable[str]) -> None:
    url = make_url(base_url, path)
    try:
        status, content_type, body, final_url = fetch(url)
        text = decode_body(body)
        ok_status = status == 200
        ok_body = len(text.strip()) > 0
        ok_terms = has_any_term(text, terms)
        detail = f"HTTP {status}, {len(body)} bytes"
        if final_url != url:
            detail += f", final={final_url}"
        if content_type:
            detail += f", content-type={content_type}"
        if not ok_terms:
            detail += ", termos esperados ausentes"
        add_result(results, f"HTML {path}", url, ok_status and ok_body and ok_terms, detail)
    except Exception as exc:  # noqa: BLE001 - script report should capture every failure
        add_result(results, f"HTML {path}", url, False, f"erro: {exc}")


def check_json_route(results: List[Result], base_url: str, path: str) -> Optional[Any]:
    url = make_url(base_url, path)
    try:
        status, content_type, body, final_url = fetch(url)
        text = decode_body(body)
        data = json.loads(text)
        ok = status == 200
        detail = f"HTTP {status}, JSON valido, {len(body)} bytes"
        if final_url != url:
            detail += f", final={final_url}"
        if content_type:
            detail += f", content-type={content_type}"
        add_result(results, f"JSON {path}", url, ok, detail)
        return data
    except Exception as exc:  # noqa: BLE001
        add_result(results, f"JSON {path}", url, False, f"erro: {exc}")
        return None


def require_keys(results: List[Result], name: str, url: str, data: Any, keys: Iterable[str]) -> None:
    missing = []
    if not isinstance(data, dict):
        add_result(results, name, url, False, "JSON nao e objeto")
        return
    for key in keys:
        if key not in data:
            missing.append(key)
    add_result(
        results,
        name,
        url,
        not missing,
        "campos ok" if not missing else "faltando: " + ", ".join(missing),
    )


def validate_status(results: List[Result], base_url: str, data: Any) -> Dict[str, Any]:
    url = make_url(base_url, "/api/status")
    if not isinstance(data, dict):
        add_result(results, "Schema /api/status", url, False, "JSON nao e objeto")
        return {}

    checks = {
        "project_name ou project": bool(data.get("project_name") or data.get("project")),
        "firmware_version ou version": bool(data.get("firmware_version") or data.get("version")),
        "uptime_ms": "uptime_ms" in data,
        "free_heap": "free_heap" in data,
        "modules": isinstance(data.get("modules"), list),
        "firewall": isinstance(data.get("firewall"), dict),
        "gateway": isinstance(data.get("gateway"), dict),
        "traffic": isinstance(data.get("traffic"), dict),
        "nat ou gateway.nat": isinstance(data.get("nat"), dict) or isinstance(data.get("gateway"), dict) and "nat_enabled" in data.get("gateway", {}),
        "storage ou persistence": isinstance(data.get("storage"), dict) or isinstance(data.get("persistence"), dict),
    }
    firewall = data.get("firewall") if isinstance(data.get("firewall"), dict) else {}
    ids_obj = data.get("ids") if isinstance(data.get("ids"), dict) else {}
    ids_ok = bool(firewall.get("ids_enabled") is not None or ids_obj.get("enabled") is not None)
    checks["ids_enabled em firewall ou ids"] = ids_ok
    missing = [name for name, ok in checks.items() if not ok]
    add_result(
        results,
        "Schema /api/status",
        url,
        not missing,
        "campos principais ok" if not missing else "faltando: " + ", ".join(missing),
    )
    return data


def validate_wifi_upstream(results: List[Result], base_url: str, data: Any) -> None:
    url = make_url(base_url, "/api/status")
    if not isinstance(data, dict):
        add_result(results, "Schema Wi-Fi upstream", url, False, "JSON nao e objeto")
        return
    gateway = data.get("gateway") if isinstance(data.get("gateway"), dict) else {}
    upstream = data.get("wifi_upstream") if isinstance(data.get("wifi_upstream"), dict) else gateway
    checks = {
        "configured/sta_configured": "configured" in upstream or "sta_configured" in upstream,
        "ssid_present ou ssid_masked": "ssid_present" in upstream or "ssid_masked" in upstream,
        "passphrase_present": "passphrase_present" in upstream,
        "connected/sta_connected": "connected" in upstream or "sta_connected" in upstream,
        "ip/upstream_ip": "ip" in upstream or "upstream_ip" in upstream,
        "rssi/upstream_rssi": "rssi" in upstream or "upstream_rssi" in upstream,
        "last_attempt_ms": "last_attempt_ms" in upstream or "last_connect_attempt_ms" in upstream,
        "last_status": "last_status" in upstream,
        "last_error": "last_error" in upstream,
    }
    missing = [name for name, ok in checks.items() if not ok]
    forbidden = []
    for key in upstream.keys():
        lowered = str(key).lower()
        if lowered in {"pass" + "word", "credencial"} or lowered == "passphrase":
            forbidden.append(str(key))
    add_result(
        results,
        "Schema Wi-Fi upstream",
        url,
        not missing and not forbidden,
        "campos ok; sem segredo exposto" if not missing and not forbidden else "faltando: " + ", ".join(missing) + ("; chaves proibidas: " + ", ".join(forbidden) if forbidden else ""),
    )

def validate_nat_status(results: List[Result], base_url: str, data: Any) -> None:
    url = make_url(base_url, "/api/status")
    if not isinstance(data, dict):
        add_result(results, "Schema NAT experimental", url, False, "JSON nao e objeto")
        return
    nat = data.get("nat") if isinstance(data.get("nat"), dict) else None
    gateway = data.get("gateway") if isinstance(data.get("gateway"), dict) else {}
    checks = {}
    if isinstance(nat, dict):
        checks = {
            "experimental_enabled": "experimental_enabled" in nat,
            "supported": "supported" in nat,
            "enabled": "enabled" in nat,
            "active": "active" in nat,
            "last_status": "last_status" in nat,
            "last_error": "last_error" in nat,
            "note": "note" in nat,
        }
    else:
        checks = {
            "gateway.nat_enabled": "nat_enabled" in gateway,
            "gateway.nat_active": "nat_active" in gateway,
            "gateway.nat_supported": "nat_supported" in gateway,
            "gateway.nat_status": "nat_status" in gateway,
            "gateway.nat_error": "nat_error" in gateway,
            "gateway.nat_note": "nat_note" in gateway,
        }
    missing = [name for name, ok in checks.items() if not ok]
    add_result(
        results,
        "Schema NAT experimental",
        url,
        not missing,
        "campos NAT ok" if not missing else "faltando: " + ", ".join(missing),
    )


def validate_traffic(results: List[Result], base_url: str, data: Any, label: str = "Schema /api/traffic") -> None:
    url = make_url(base_url, "/api/traffic")
    if not isinstance(data, dict):
        add_result(results, label, url, False, "JSON nao e objeto")
        return
    checks = {
        "total_requests": "total_requests" in data,
        "not_found_count": "not_found_count" in data,
        "sensitive_path_hits": "sensitive_path_hits" in data,
        "suspicious_scan_count": "suspicious_scan_count" in data,
        "ids_events": "ids_events" in data,
        "last_ip": "last_ip" in data,
        "last_route": "last_route" in data,
        "last_user_agent_short": "last_user_agent_short" in data,
        "top_routes": isinstance(data.get("top_routes"), list),
        "scan_window_ms": "scan_window_ms" in data or "window_ms" in data,
        "scan_cooldown_ms": "scan_cooldown_ms" in data,
    }
    missing = [name for name, ok in checks.items() if not ok]
    add_result(results, label, url, not missing, "campos ok" if not missing else "faltando: " + ", ".join(missing))

def validate_events(results: List[Result], base_url: str, data: Any, label: str = "Schema /api/events") -> None:
    url = make_url(base_url, "/api/events")
    if not isinstance(data, dict):
        add_result(results, label, url, False, "JSON nao e objeto")
        return
    missing = [key for key in ("count", "capacity", "events") if key not in data]
    events_ok = isinstance(data.get("events"), list)
    if not events_ok and "events" not in missing:
        missing.append("events(list)")
    add_result(results, label, url, not missing, "campos ok" if not missing else "faltando: " + ", ".join(missing))


def validate_persistent(results: List[Result], base_url: str, data: Any, label: str = "Schema /api/events/persistent") -> None:
    url = make_url(base_url, "/api/events/persistent")
    if not isinstance(data, dict):
        add_result(results, label, url, False, "JSON nao e objeto")
        return
    checks = {
        "available": "available" in data,
        "file_size ou size": "file_size" in data or "size" in data,
        "max_size ou limit": "max_size" in data or "limit" in data,
        "events ou lines": "events" in data or "lines" in data,
    }
    missing = [name for name, ok in checks.items() if not ok]
    add_result(results, label, url, not missing, "campos ok" if not missing else "faltando: " + ", ".join(missing))


def trigger_demo(results: List[Result], base_url: str, path: str) -> None:
    url = make_url(base_url, path)
    try:
        status, _content_type, body, final_url = fetch(url)
        ok = status in (200, 302, 303)
        detail = f"HTTP {status}, {len(body)} bytes"
        if final_url != url:
            detail += f", final={final_url}"
        add_result(results, f"Demo {path}", url, ok, detail)
    except Exception as exc:  # noqa: BLE001
        add_result(results, f"Demo {path}", url, False, f"erro: {exc}")


def event_level_exists(data: Any, levels: Iterable[str]) -> bool:
    wanted = {level.upper() for level in levels}
    if not isinstance(data, dict):
        return False
    events = data.get("events")
    if not isinstance(events, list):
        return False
    for event in events:
        if isinstance(event, dict) and str(event.get("level", "")).upper() in wanted:
            return True
    return False


def flatten_values(value: Any) -> Iterable[str]:
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key)
            yield from flatten_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from flatten_values(item)
    else:
        yield str(value)


def persistent_mentions_relevant_event(data: Any) -> bool:
    text = "\n".join(flatten_values(data)).upper()
    return any(term in text for term in ("WARN", "SECURITY", "FLOOD", "IDS", "SEGURANCA", "EXCESSO"))


def storage_summary(status: Dict[str, Any], persistent: Any) -> Dict[str, Any]:
    storage = status.get("storage") if isinstance(status.get("storage"), dict) else status.get("persistence", {})
    if not isinstance(storage, dict):
        storage = {}
    persistent_obj = persistent if isinstance(persistent, dict) else {}
    return {
        "available": storage.get("available", persistent_obj.get("available", "n/d")),
        "file_size": storage.get("file_size", persistent_obj.get("file_size", persistent_obj.get("size", "n/d"))),
        "max_size": storage.get("max_size", persistent_obj.get("max_size", persistent_obj.get("limit", "n/d"))),
    }


def write_report(
    base_url: str,
    results: List[Result],
    status: Dict[str, Any],
    persistent: Any,
    output_dir: Path,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    now = _dt.datetime.now()
    report_path = output_dir / f"smoke-test-{now:%Y%m%d-%H%M%S}.md"
    passed = all(result.passed for result in results)
    firewall = status.get("firewall", {}) if isinstance(status.get("firewall"), dict) else {}
    traffic = status.get("traffic", {}) if isinstance(status.get("traffic"), dict) else {}
    gateway = status.get("gateway", {}) if isinstance(status.get("gateway"), dict) else {}
    upstream = status.get("wifi_upstream", gateway) if isinstance(status.get("wifi_upstream", gateway), dict) else {}
    nat = status.get("nat") if isinstance(status.get("nat"), dict) else {}
    storage = storage_summary(status, persistent)
    version = status.get("firmware_version") or status.get("version") or "n/d"
    uptime = status.get("uptime_ms", "n/d")
    free_heap = status.get("free_heap", status.get("freeHeap", "n/d"))

    lines = [
        "# Smoke Test HTTP",
        "",
        f"- Data/hora local: {now:%Y-%m-%d %H:%M:%S}",
        f"- Base URL: `{base_url}`",
        f"- Resultado geral: **{'PASS' if passed else 'FAIL'}**",
        "",
        "## Resultados",
        "",
        "| Teste | URL | Resultado | Detalhe |",
        "|---|---|---|---|",
    ]
    for result in results:
        lines.append(
            "| {name} | `{url}` | {status} | {detail} |".format(
                name=markdown_escape(result.name),
                url=markdown_escape(result.url),
                status="PASS" if result.passed else "FAIL",
                detail=markdown_escape(result.detail),
            )
        )

    lines.extend(
        [
            "",
            "## Resumo de /api/status",
            "",
            f"- Firmware/versao: `{version}`",
            f"- Uptime: `{uptime}` ms",
            f"- Heap livre: `{free_heap}` bytes",
            f"- Firewall total requests: `{firewall.get('total_requests', 'n/d')}`",
            f"- Traffic monitor: total=`{traffic.get('total_requests', 'n/d')}` / 404=`{traffic.get('not_found_count', 'n/d')}` / scans=`{traffic.get('suspicious_scan_count', 'n/d')}`",
            f"- Gateway mode: `{gateway.get('mode', 'n/d')}`",
            f"- Gateway upstream: configured=`{upstream.get('sta_configured', upstream.get('configured', 'n/d'))}` / connected=`{upstream.get('sta_connected', upstream.get('connected', 'n/d'))}` / ip=`{upstream.get('upstream_ip', upstream.get('ip', 'n/d'))}`",
            f"- NAT experimental: enabled=`{nat.get('enabled', gateway.get('nat_enabled', 'n/d'))}` / active=`{nat.get('active', gateway.get('nat_active', 'n/d'))}` / status=`{nat.get('last_status', gateway.get('nat_status', 'n/d'))}`",
            f"- Storage available: `{storage['available']}`",
            f"- Persistent log size: `{storage['file_size']}` / `{storage['max_size']}` bytes",
            "",
            "## Teste manual recomendado",
            "",
            "1. Reiniciar o ESP32.",
            "2. Reconectar ao AP `ESP32-Firewall-Lab`.",
            "3. Abrir `/api/events/persistent`.",
            "4. Confirmar que eventos persistentes continuam disponiveis apos reboot.",
            "",
            "## Limitacoes",
            "",
            "- Smoke test nao substitui teste fisico dos sensores.",
            "- INA219 fisico fica para fase final porque depende da solda/montagem.",
            "- Firewall e IDS sao didaticos e baseados em HTTP do painel.",
            "- NAT experimental depende do core/lwIP e do ambiente fisico; o smoke test nao exige internet real.",
            "- Smoke test valida /wifi e schema, mas nao automatiza envio de credencial upstream.",
            "",
        ]
    )
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def run(base_url: str, output_dir: Path) -> Tuple[bool, Path, List[Result]]:
    results: List[Result] = []

    html_checks = [
        ("/", ("ESP32", "Monitor", "Firewall")),
        ("/evidencias", ("Evidencia", "execucao", "Energia", "Seguranca")),
        ("/logs", ("Registro", "eventos", "LittleFS", "Persistencia")),
        ("/eventos", ("Registro", "eventos", "LittleFS", "Persistencia")),
        ("/traffic", ("Traffic Monitor", "requests", "IDS", "HTTPS")),
        ("/gateway", ("Gateway", "AP", "STA", "NAT experimental")),
        ("/wifi", ("Wi-Fi upstream", "SSID", "Passphrase", "recuperacao")),
        ("/demo", ("Demo guiada", "roteiro", "TDE")),
    ]
    for path, terms in html_checks:
        check_html(results, base_url, path, terms)

    status = check_json_route(results, base_url, "/api/status")
    status_obj = validate_status(results, base_url, status) if status is not None else {}
    if status is not None:
        validate_wifi_upstream(results, base_url, status)
        validate_nat_status(results, base_url, status)
        validate_traffic(results, base_url, status.get("traffic"), "Schema traffic em /api/status")

    traffic_before = check_json_route(results, base_url, "/api/traffic")
    if traffic_before is not None:
        validate_traffic(results, base_url, traffic_before)

    events_before = check_json_route(results, base_url, "/api/events")
    if events_before is not None:
        validate_events(results, base_url, events_before)

    persistent_before = check_json_route(results, base_url, "/api/events/persistent")
    if persistent_before is not None:
        validate_persistent(results, base_url, persistent_before)

    for path in ("/demo/info", "/demo/warn", "/demo/security", "/demo/flood", "/demo/ids", "/demo/scan"):
        trigger_demo(results, base_url, path)
        time.sleep(0.15)

    events_after = check_json_route(results, base_url, "/api/events")
    if events_after is not None:
        validate_events(results, base_url, events_after, "Schema /api/events apos demos")
        has_security = event_level_exists(events_after, ("SECURITY",))
        add_result(
            results,
            "Eventos WARN/SECURITY/IDS apos demos",
            make_url(base_url, "/api/events"),
            event_level_exists(events_after, ("WARN", "SECURITY")),
            "WARN ou SECURITY encontrado" if event_level_exists(events_after, ("WARN", "SECURITY")) else "WARN/SECURITY nao encontrado",
        )
        add_result(
            results,
            "Evento SECURITY/IDS apos demo scan",
            make_url(base_url, "/api/events"),
            has_security and "IDS" in "\n".join(flatten_values(events_after)).upper(),
            "SECURITY/IDS encontrado" if has_security else "SECURITY/IDS nao encontrado",
        )

    persistent_after = check_json_route(results, base_url, "/api/events/persistent")
    if persistent_after is not None:
        validate_persistent(results, base_url, persistent_after, "Schema /api/events/persistent apos demos")
        add_result(
            results,
            "Persistentes mencionam evento relevante",
            make_url(base_url, "/api/events/persistent"),
            persistent_mentions_relevant_event(persistent_after),
            "WARN/SECURITY/flood/IDS encontrado" if persistent_mentions_relevant_event(persistent_after) else "sem evento relevante detectavel",
        )

    traffic_after = check_json_route(results, base_url, "/api/traffic")
    if traffic_after is not None:
        validate_traffic(results, base_url, traffic_after, "Schema /api/traffic apos demo scan")

    check_html(results, base_url, "/logs", ("Registro", "eventos", "SECURITY", "Persistencia"))

    # Re-read status near the end for a more useful summary, but do not duplicate schema checks.
    latest_status = check_json_route(results, base_url, "/api/status")
    if isinstance(latest_status, dict):
        status_obj = latest_status

    report_path = write_report(base_url, results, status_obj, persistent_after or persistent_before, output_dir)
    return all(result.passed for result in results), report_path, results


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Smoke test HTTP do ESP32 Mini Firewall Gateway")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help=f"Base URL do ESP32 (default: {DEFAULT_BASE_URL})")
    parser.add_argument("--output-dir", default="evidencias", help="Diretorio para o relatorio Markdown (default: evidencias)")
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    try:
        base_url = normalize_base_url(args.base_url)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 2

    passed, report_path, results = run(base_url, Path(args.output_dir))
    failed = [result for result in results if not result.passed]

    print(f"Resultado geral: {'PASS' if passed else 'FAIL'}")
    print(f"Relatorio: {report_path}")
    if failed:
        print("Falhas:")
        for result in failed:
            print(f"- {result.name}: {result.detail}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
