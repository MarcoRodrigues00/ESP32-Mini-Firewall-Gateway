#!/usr/bin/env python3
"""HTTP smoke test leve para experiments/espidf-appliance-v2.

Usa somente Python standard library. Deve ser executado com a maquina conectada
 ao AP do ESP32 ou com rota para o IP informado em --base-url.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROUTES = [
    ("/", "html"),
    ("/api/status", "json"),
    ("/dns", "html"),
    ("/api/dns", "json"),
    ("/clients", "html"),
    ("/api/clients", "json"),
    ("/traffic", "html"),
    ("/logs", "html"),
    ("/report", "html"),
    ("/demo/security", "html"),
]


def build_url(base_url: str, path: str) -> str:
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def fetch(url: str, timeout: float) -> tuple[int, str, bytes]:
    req = urllib.request.Request(url, headers={"User-Agent": "espidf-v2-smoke/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        status = getattr(resp, "status", resp.getcode())
        ctype = resp.headers.get("content-type", "")
        body = resp.read(65536)
        return int(status), ctype, body


def validate_json(path: str, body: bytes) -> list[str]:
    errors: list[str] = []
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception as exc:  # noqa: BLE001 - script diagnostico simples
        return [f"JSON invalido: {exc}"]

    if path == "/api/status":
        for key in ("ap", "upstream", "nat", "dns", "clients_observed", "traffic", "time", "display"):
            if key not in data:
                errors.append(f"campo ausente em /api/status: {key}")
    elif path == "/api/dns":
        for key in ("monitoring_enabled", "total_queries", "suspicious_count", "recent_queries"):
            if key not in data:
                errors.append(f"campo ausente em /api/dns: {key}")
    elif path == "/api/clients":
        if "clients" not in data:
            errors.append("campo ausente em /api/clients: clients")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description="Smoke HTTP leve da PoC ESP-IDF Appliance v2")
    parser.add_argument("--base-url", default="http://192.168.4.1", help="URL base do ESP32 (default: http://192.168.4.1)")
    parser.add_argument("--timeout", type=float, default=5.0, help="timeout por requisicao em segundos")
    args = parser.parse_args()

    failures = 0
    started = time.monotonic()
    print(f"ESP-IDF v2 smoke HTTP: base={args.base_url}")

    for path, kind in ROUTES:
        url = build_url(args.base_url, path)
        try:
            status, ctype, body = fetch(url, args.timeout)
            ok = 200 <= status < 300 and len(body) > 0
            detail = f"HTTP {status}, {len(body)} bytes, content-type={ctype or 'n/d'}"
            if kind == "json":
                errors = validate_json(path, body)
                if errors:
                    ok = False
                    detail += "; " + "; ".join(errors)
            print(f"{'PASS' if ok else 'FAIL'} {path} - {detail}")
            if not ok:
                failures += 1
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            print(f"FAIL {path} - erro: {exc}")
            failures += 1

    elapsed = time.monotonic() - started
    print(f"Resumo: {'PASS' if failures == 0 else 'FAIL'}; falhas={failures}; duracao={elapsed:.1f}s")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
