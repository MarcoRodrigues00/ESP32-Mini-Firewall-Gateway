#!/usr/bin/env python3
"""Offline validation for the ESP32 Mini Firewall Gateway project.

Runs local build/static checks that can be executed over SSH without connecting
the notebook to the ESP32 access point.
"""

from __future__ import annotations

import datetime as dt
import re
import subprocess
import sys
import unicodedata
from pathlib import Path
from typing import Iterable, List, Sequence

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = ROOT / "evidencias"
SRC_MAIN = ROOT / "src" / "main.cpp"

REQUIRED_ROUTES = [
    "/",
    "/demo",
    "/gateway",
    "/wifi",
    "/traffic",
    "/report",
    "/evidencias",
    "/logs",
    "/eventos",
    "/api/status",
    "/api/events",
    "/api/events/persistent",
    "/api/traffic",
    "/api/report",
    "/logs/clear-persistent",
    "/demo/info",
    "/demo/warn",
    "/demo/security",
    "/demo/flood",
    "/demo/ids",
    "/demo/scan",
]

REQUIRED_CODE_TERMS = [
    "gateway",
    "nat",
    "firewall",
    "ids",
    "traffic",
    "storage",
    "persistence",
    "uptime_ms",
    "time_label",
]

DOC_REQUIREMENTS = [
    ("rota /traffic", ["/traffic"]),
    ("API /api/traffic", ["/api/traffic"]),
    ("rota /report", ["/report"]),
    ("API /api/report", ["/api/report"]),
    ("demo scan /demo/scan", ["/demo/scan"]),
    ("limitacao HTTPS", ["nao inspeciona https", "ausencia de inspecao https", "não inspeciona https"]),
    ("NAT real em PoC separada ESP-IDF", ["nat real", "poc", "esp-idf"]),
]

SCAN_CHECKS = [
    ("AsyncWebServer/ESPAsync", re.compile(r"AsyncWebServer|ESPAsync")),
    ("delay()", re.compile(r"delay\(")),
    ("CDN/framework externo", re.compile(r"cdn|bootstrap|tailwind|unpkg|cdnjs|fonts\.googleapis", re.IGNORECASE)),
    ("termos sensiveis", re.compile(r"token|password|secret|api_key|apikey|senha", re.IGNORECASE)),
]

SCAN_FILES = [
    ROOT / "platformio.ini",
    ROOT / "README.md",
    ROOT / "CHANGELOG.md",
    SRC_MAIN,
    ROOT / "tools" / "smoke_test_http.py",
]


class Check:
    def __init__(self, name: str, status: str, detail: str) -> None:
        self.name = name
        self.status = status
        self.detail = detail


class CommandResult:
    def __init__(self, command: Sequence[str], returncode: int, output: str) -> None:
        self.command = list(command)
        self.returncode = returncode
        self.output = output

    @property
    def status(self) -> str:
        return "PASS" if self.returncode == 0 else "FAIL"


def normalize_text(value: str) -> str:
    decomposed = unicodedata.normalize("NFD", value)
    without_marks = "".join(char for char in decomposed if unicodedata.category(char) != "Mn")
    return without_marks.lower()


def markdown_escape(value: object) -> str:
    return str(value).replace("\n", " ").replace("\r", " ").replace("|", "\\|")


def run_command(command: Sequence[str]) -> CommandResult:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        return CommandResult(command, completed.returncode, completed.stdout)
    except FileNotFoundError as exc:
        return CommandResult(command, 127, str(exc))


def list_project_files() -> List[Path]:
    files: List[Path] = []
    files.extend(path for path in (ROOT / "docs").glob("*.md") if path.is_file())
    files.extend(path for path in SCAN_FILES if path.exists())
    unique = sorted(set(files))
    return [path for path in unique if path.name != "offline_project_check.py"]


def rel(path: Path) -> str:
    return str(path.relative_to(ROOT))


def command_checks() -> tuple[List[Check], List[CommandResult]]:
    commands = [
        ["pio", "run"],
        ["python3", "-m", "py_compile", "tools/smoke_test_http.py"],
        ["python3", "tools/smoke_test_http.py", "--help"],
    ]
    results = [run_command(command) for command in commands]
    checks = [
        Check(
            "comando " + " ".join(result.command),
            result.status,
            "exit code " + str(result.returncode),
        )
        for result in results
    ]
    return checks, results


def scan_checks() -> List[Check]:
    checks: List[Check] = []
    files = list_project_files()
    for name, pattern in SCAN_CHECKS:
        matches: List[str] = []
        src_matches: List[str] = []
        for path in files:
            text = path.read_text(encoding="utf-8", errors="replace")
            for line_number, line in enumerate(text.splitlines(), start=1):
                if pattern.search(line):
                    item = f"{rel(path)}:{line_number}"
                    matches.append(item)
                    if path == SRC_MAIN:
                        src_matches.append(item)

        if not matches:
            checks.append(Check(f"scan {name}", "PASS", "nenhum achado"))
            continue

        if name == "AsyncWebServer/ESPAsync":
            status = "FAIL" if src_matches or any(match.startswith("platformio.ini:") for match in matches) else "WARN"
        elif name == "delay()":
            status = "FAIL" if src_matches else "WARN"
        elif name == "CDN/framework externo":
            status = "FAIL" if src_matches else "WARN"
        else:
            status = "FAIL" if src_matches else "WARN"
        detail = ", ".join(matches[:12])
        if len(matches) > 12:
            detail += " ..."
        checks.append(Check(f"scan {name}", status, detail))
    return checks


def route_checks() -> tuple[List[Check], List[str]]:
    text = SRC_MAIN.read_text(encoding="utf-8", errors="replace")
    registered = sorted(set(re.findall(r'server\.on\(\s*"([^"]+)"', text)))
    missing = [route for route in REQUIRED_ROUTES if route not in registered]
    detail = "rotas ok" if not missing else "faltando: " + ", ".join(missing)
    return [Check("rotas obrigatorias em src/main.cpp", "PASS" if not missing else "FAIL", detail)], registered


def code_object_checks() -> List[Check]:
    text = SRC_MAIN.read_text(encoding="utf-8", errors="replace").lower()
    missing = [term for term in REQUIRED_CODE_TERMS if term.lower() not in text]
    return [
        Check(
            "objetos/campos importantes no firmware",
            "PASS" if not missing else "FAIL",
            "termos ok" if not missing else "faltando: " + ", ".join(missing),
        )
    ]


def documentation_checks() -> List[Check]:
    docs = []
    for path in (ROOT / "README.md", ROOT / "docs" / "api-reference.md"):
        if path.exists():
            docs.append(path.read_text(encoding="utf-8", errors="replace"))
    normalized = normalize_text("\n".join(docs))
    checks: List[Check] = []
    for name, terms in DOC_REQUIREMENTS:
        missing = [term for term in terms if normalize_text(term) not in normalized]
        checks.append(
            Check(
                "documentacao: " + name,
                "PASS" if not missing else "FAIL",
                "mencionado" if not missing else "faltando: " + ", ".join(missing),
            )
        )
    return checks


def git_checks(branch: str) -> List[Check]:
    result = run_command(["git", "status", "--short"])
    if result.returncode != 0:
        return [Check("git status --short", "WARN", "nao foi possivel consultar: " + result.output.strip())]

    changed = [line for line in result.output.splitlines() if line.strip()]
    experiment_changes = [line for line in changed if " experiments/" in line or line[3:].startswith("experiments/")]
    if experiment_changes:
        detail = "; ".join(experiment_changes)
        if branch == "main":
            detail += "; nao incluir experiments/ no commit da main"
        return [Check("alteracoes em experiments/", "WARN", detail)]
    return [Check("alteracoes em experiments/", "PASS", "nenhuma alteracao detectada")]


def current_branch() -> str:
    result = run_command(["git", "branch", "--show-current"])
    if result.returncode != 0:
        return "n/d"
    return result.output.strip() or "n/d"


def overall_status(checks: Iterable[Check]) -> str:
    return "FAIL" if any(check.status == "FAIL" for check in checks) else "PASS"


def write_report(
    now: dt.datetime,
    branch: str,
    checks: List[Check],
    commands: List[CommandResult],
    registered_routes: List[str],
) -> Path:
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    report_path = EVIDENCE_DIR / f"offline-check-{now:%Y%m%d-%H%M%S}.md"
    status = overall_status(checks)
    warnings = sum(1 for check in checks if check.status == "WARN")
    failures = sum(1 for check in checks if check.status == "FAIL")

    lines = [
        "# Offline Project Check",
        "",
        f"- Data/hora local: {now:%Y-%m-%d %H:%M:%S}",
        f"- Branch atual: `{branch}`",
        f"- Resultado geral: **{status}**",
        f"- Checks com FAIL: {failures}",
        f"- Warnings: {warnings}",
        "",
        "## Resumo dos checks",
        "",
        "| Check | Resultado | Detalhe |",
        "|---|---|---|",
    ]
    for check in checks:
        lines.append(f"| {markdown_escape(check.name)} | {check.status} | {markdown_escape(check.detail)} |")

    lines.extend(["", "## Comandos executados", ""])
    for command in commands:
        lines.append(f"- `{' '.join(command.command)}` -> {command.status} (exit code {command.returncode})")

    lines.extend(["", "## Rotas validadas", ""])
    for route in REQUIRED_ROUTES:
        mark = "PASS" if route in registered_routes else "FAIL"
        lines.append(f"- {mark}: `{route}`")

    extra_routes = [route for route in registered_routes if route not in REQUIRED_ROUTES]
    if extra_routes:
        lines.extend(["", "## Rotas adicionais encontradas", ""])
        for route in extra_routes:
            lines.append(f"- `{route}`")

    lines.extend(
        [
            "",
            "## Pendencias para teste real no hardware",
            "",
            "- Conectar um cliente ao AP `ESP32-Firewall-Lab` apenas quando a conexao SSH nao depender da rede atual.",
            "- Executar `python3 tools/smoke_test_http.py --base-url http://192.168.4.1` conectado ao AP.",
            "- Conferir dashboard, logs, eventos persistentes, `/traffic`, `/report` e respostas JSON no ESP32 real.",
            "- Registrar prints ou video das rotas embarcadas funcionando no hardware fisico.",
            "",
            "## Observacao",
            "",
            "Este offline check valida build, estrutura de codigo, documentacao e consistencia da branch sem acessar o AP do ESP32. Ele nao substitui o smoke real no ESP32 nem valida sensores, atuadores, Wi-Fi real, LittleFS em hardware ou comportamento eletrico da montagem.",
        ]
    )
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def print_summary(status: str, warnings: int, report_path: Path) -> None:
    print(f"Resultado geral: {status}")
    print(f"Warnings: {warnings}")
    print(f"Relatorio: {rel(report_path)}")
    print("Proximos passos:")
    print("- Revisar WARN/FAIL no relatorio gerado.")
    print("- Antes da defesa, rodar o smoke real conectado ao AP do ESP32.")
    print("- Na branch main, nao incluir alteracoes em experiments/ no commit.")


def main() -> int:
    now = dt.datetime.now()
    branch = current_branch()
    checks: List[Check] = []

    command_check_results, commands = command_checks()
    checks.extend(command_check_results)
    checks.extend(scan_checks())
    route_check_results, registered_routes = route_checks()
    checks.extend(route_check_results)
    checks.extend(code_object_checks())
    checks.extend(documentation_checks())
    checks.extend(git_checks(branch))

    status = overall_status(checks)
    warnings = sum(1 for check in checks if check.status == "WARN")
    report_path = write_report(now, branch, checks, commands, registered_routes)
    print_summary(status, warnings, report_path)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
