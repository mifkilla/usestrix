#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
usestrix - interactive wrapper for Strix (https://github.com/usestrix/strix).

Why it exists:
  * Strix defaults to --scan-mode deep: forget the flag and you get hours of
    work and tens of dollars.
  * --max-turns is counted PER AGENT, and a scan spawns several of them.
  * Exit code 2 means "vulnerabilities found", not "failure" - easy to
    misread in scripts and CI.
  * A local directory target is mounted WRITABLE; Strix runs the app and
    leaves files behind.
  * In headless mode Strix prints a banner and then goes quiet for minutes.

This wrapper picks sane presets, shows live progress, opens the web viewer
for you, stops scans gracefully, and keeps an auditable record of every run.

Licence: MIT. Not affiliated with the Strix project.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

__version__ = "1.0.0"

# --- optional pretty output: degrade gracefully if rich is missing ---------
try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm, IntPrompt, Prompt
    from rich.table import Table
    C: Console | None = Console()
    RICH = True
except Exception:  # pragma: no cover - plain terminals still work
    RICH = False
    C = None

# --------------------------------------------------------------- paths ----
HOME = Path.home()
WORK = Path(os.environ.get("USESTRIX_HOME", HOME / "strix-runs")).expanduser()
ENGAGEMENTS = WORK / "engagements"
RUNS = WORK / "strix_runs"
STRIX_DIR = Path(os.environ.get("STRIX_CONFIG_DIR", HOME / ".strix")).expanduser()
VIEWER_PORT = int(os.environ.get("USESTRIX_VIEWER_PORT", "3400"))
# English by default everywhere. Russian is opt-in, so behaviour does not
# change under the user's locale: USESTRIX_LANG=ru
LANG = os.environ.get("USESTRIX_LANG", "en").strip().lower()
if LANG not in ("en", "ru"):
    LANG = "en"


def find_strix() -> str | None:
    """Locate the strix binary: PATH first, then the usual install spots."""
    found = shutil.which("strix")
    if found:
        return found
    for cand in (
        HOME / ".local/bin/strix",
        HOME / ".local/share/pipx/venvs/strix-agent/bin/strix",
        Path("/usr/local/bin/strix"),
        Path("/opt/homebrew/bin/strix"),
    ):
        if cand.exists():
            return str(cand)
    return None


STRIX = find_strix()

# ----------------------------------------------------------------- i18n ----
T = {
    "en": {
        "title": "usestrix", "subtitle": "interactive wrapper for Strix",
        "menu": "What do you want to do",
        "new": "New scan|guided, with presets",
        "resume": "Resume a scan|picks up agent history",
        "results": "Show findings|summary for one run",
        "viewer": "Web viewer|open, print link, or stop",
        "stop": "Stop a running scan|graceful, findings are kept",
        "help": "Help|what matters and why",
        "quit": "Quit|",
        "choice": "Choice", "need_number": "  enter a number from 1 to %d",
        "eof": "\n(no more input, exiting)",
        "missing": "\nMissing something required. Cannot run.",
        "target_q": "What are we testing",
        "t_url": "Web app, domain or IP|https://app.example.com, example.com, 10.0.0.5",
        "t_code": "Local directory|path to source on this machine",
        "t_repo": "Repository|https://github.com/user/repo",
        "t_api": "API spec plus live URL|OpenAPI or Postman export",
        "t_list": "Target list file|one target per line",
        "ask_url": "URL, domain or IP", "ask_dir": "Path to directory",
        "ask_repo": "Repository URL", "ask_spec": "Path to OpenAPI/Swagger/Postman",
        "ask_base": "Live API base URL", "ask_list": "Path to list file",
        "no_dir": "no such directory", "no_file": "no such file",
        "writable": ("\nThis directory is mounted WRITABLE. Strix runs the app "
                     "and will leave files behind."),
        "is_copy": "Is this a copy, or is everything committed?",
        "abort_copy": "Stopping. Make a git worktree or commit first.",
        "preset": "Preset", "custom": "Custom|set everything by hand",
        "basis": "basis", "mode_q": "Scan mode",
        "m_quick": "quick|minutes, for CI and a first look",
        "m_std": "standard|30-60 minutes, routine assessment",
        "m_deep": "deep|1-4 hours, expensive. Deliberate choice only",
        "budget_q": "Spending cap, USD", "turns_q": "Turns per AGENT (not per scan)",
        "name_q": "Engagement name", "notes_q": "Your notes in plain words (Enter to skip)",
        "scope_q": "Code scope", "s_full": "full|the whole codebase",
        "s_diff": "diff|changed files only",
        "plan": "Launch plan", "trace": "trace",
        "targets": "targets", "mode": "mode", "cap": "cap",
        "turns": "turns per agent", "scope": "code scope", "preset_row": "preset",
        "run_q": "\nRun it?", "cancelled": "Cancelled. Command saved:",
        "rc_note": ("\nExit code 2 = VULNERABILITIES FOUND, not a failure. 1 = error."),
        "ctrlc": "   Ctrl+C stops the scan gracefully; findings are kept.\n",
        "run_is": "run:", "watch": "WATCH IT IN YOUR BROWSER:",
        "token_warn": "   the link carries a token - do not share it\n",
        "scanning": "scanning", "turn": "turn", "agent": "agent",
        "surfaces": "surfaces", "sarif": "SARIF entries", "spend": "spend",
        "stop_hint": "stop", "stop_key": "Ctrl+C (graceful)",
        "stopping": "\n\nStopping gracefully, Strix will save what it found...",
        "no_react": "no response in 60s, forcing", "result": "Result",
        "clean": "Clean: no confirmed findings.",
        "found": "VULNERABILITIES FOUND. This is the normal exit code.",
        "err": "Execution error, code", "traces": "wrapper trace:",
        "findings_at": "Strix findings:",
        "no_runs": "No runs yet.", "pick_run": "Which run",
        "run_sum": "findings", "no_json": "no findings file",
        "viewer_up": "Viewer is running, processes:", "port": "port",
        "kill_q": "Stop it?", "killed": "Stopped.",
        "open_browser": "\nOpen in your browser:",
        "token_warn2": ("\nThe link carries a token. Whoever gets it can steer a live "
                        "scan.\nDo not share it; never bind to 0.0.0.0."),
        "no_link": "Viewer did not return a link, see",
        "no_scans": "No scans are running.", "running": "Scans running:",
        "stop_q": "Stop them? Findings will be kept",
        "stopped_in": "Stopped after", "no_graceful": "No graceful stop within 40s.",
        "force_q": "Force kill? The final report may not be assembled",
        "pf_strix": "strix", "pf_docker": "docker", "pf_sandbox": "sandbox image",
        "pf_model": "model", "pf_key": "api key", "pf_disk": "free disk",
        "pf_notfound": "not found - see README",
        "pf_responds": "daemon responds",
        "pf_noresponds": "NOT responding; Strix cannot run",
        "pf_present": "present",
        "pf_willpull": "will be pulled on first run (~4 GB)",
        "pf_nomodel": "STRIX_LLM is not set",
        "pf_keyset": "set, never passed on the command line",
        "pf_nokey": "LLM_API_KEY is not set",
        "col_sev": "severity", "col_cvss": "cvss", "col_conf": "conf",
        "col_cwe": "cwe", "col_title": "title",
        "resume_note": "Strix picks up the root agent and live subagents.",
        "new_cap": "New spending cap, USD", "resume_q": "Resume this run?",
    },
    "ru": {
        "title": "usestrix", "subtitle": "интерактивная обёртка над Strix",
        "menu": "Что делаем",
        "new": "Новый скан|мастер с заготовками",
        "resume": "Продолжить прогон|подхватывает историю агентов",
        "results": "Посмотреть находки|сводка по прогону",
        "viewer": "Веб-просмотрщик|открыть, дать ссылку или погасить",
        "stop": "Остановить идущий скан|мягко, найденное сохранится",
        "help": "Справка|что к чему и почему",
        "quit": "Выход|",
        "choice": "Выбор", "need_number": "  нужно число от 1 до %d",
        "eof": "\n(ввод закончился, выхожу)",
        "missing": "\nНе хватает обязательного. Запуск невозможен.",
        "target_q": "Что проверяем",
        "t_url": "Веб, домен или IP|https://app.example.com, example.com, 10.0.0.5",
        "t_code": "Локальный каталог|путь к исходникам на этой машине",
        "t_repo": "Репозиторий|https://github.com/user/repo",
        "t_api": "Спецификация плюс адрес|OpenAPI или Postman и живой URL",
        "t_list": "Список целей файлом|по одной в строке",
        "ask_url": "Адрес, домен или IP", "ask_dir": "Путь к каталогу",
        "ask_repo": "URL репозитория", "ask_spec": "Путь к OpenAPI/Swagger/Postman",
        "ask_base": "Живой базовый адрес API", "ask_list": "Путь к файлу со списком",
        "no_dir": "каталога нет", "no_file": "файла нет",
        "writable": ("\nКаталог монтируется С ПРАВОМ ЗАПИСИ. Strix запускает "
                     "приложение и оставит в нём файлы."),
        "is_copy": "Это копия или всё закоммичено?",
        "abort_copy": "Останавливаюсь. Сделай git worktree или коммит.",
        "preset": "Заготовка", "custom": "Своё|задать все параметры вручную",
        "basis": "основание", "mode_q": "Режим",
        "m_quick": "quick|минуты, для CI и первой проверки",
        "m_std": "standard|30-60 минут, обычная оценка",
        "m_deep": "deep|1-4 часа, дорого. Только осознанно",
        "budget_q": "Потолок расхода, USD", "turns_q": "Ходов на КАЖДОГО агента (не на прогон)",
        "name_q": "Имя работы", "notes_q": "Пожелания своими словами (Enter - пропустить)",
        "scope_q": "Охват кода", "s_full": "full|весь код целиком",
        "s_diff": "diff|только изменённые файлы",
        "plan": "План запуска", "trace": "следы",
        "targets": "цели", "mode": "режим", "cap": "потолок",
        "turns": "ходов на агента", "scope": "охват кода", "preset_row": "заготовка",
        "run_q": "\nЗапускать?", "cancelled": "Отменено. Команда сохранена:",
        "rc_note": "\nКод возврата 2 = НАЙДЕНЫ УЯЗВИМОСТИ, это не сбой. 1 = ошибка.",
        "ctrlc": "   Ctrl+C останавливает скан МЯГКО, найденное сохраняется.\n",
        "run_is": "прогон:", "watch": "СМОТРЕТЬ ХОД В БРАУЗЕРЕ:",
        "token_warn": "   в ссылке токен, никому не пересылать\n",
        "scanning": "идёт скан", "turn": "ход", "agent": "агент",
        "surfaces": "поверхностей", "sarif": "записей в SARIF", "spend": "расход",
        "stop_hint": "остановить", "stop_key": "Ctrl+C (мягко)",
        "stopping": "\n\nОстанавливаю мягко, Strix сохранит найденное...",
        "no_react": "не отреагировал за 60 с, снимаю принудительно", "result": "Итог",
        "clean": "Чисто: подтверждённых находок нет.",
        "found": "НАЙДЕНЫ уязвимости. Это штатный код, не сбой.",
        "err": "Ошибка выполнения, код", "traces": "следы обёртки:",
        "findings_at": "находки Strix:",
        "no_runs": "Прогонов пока нет.", "pick_run": "Какой прогон",
        "run_sum": "находок", "no_json": "файла находок нет",
        "viewer_up": "Просмотрщик работает, процессов:", "port": "порт",
        "kill_q": "Погасить?", "killed": "Погашен.",
        "open_browser": "\nОткрой в браузере:",
        "token_warn2": ("\nВ ссылке токен. Кто её получит, сможет управлять живым "
                        "сканом.\nНикому не пересылать, 0.0.0.0 не ставить."),
        "no_link": "Просмотрщик не отдал ссылку, смотри",
        "no_scans": "Идущих сканов нет.", "running": "Идёт сканов:",
        "stop_q": "Остановить? Найденное сохранится",
        "stopped_in": "Остановлен за", "no_graceful": "Не отреагировал за 40 с.",
        "force_q": "Снять принудительно? Итог может не собраться",
        "pf_strix": "strix", "pf_docker": "docker", "pf_sandbox": "образ песочницы",
        "pf_model": "модель", "pf_key": "ключ", "pf_disk": "диск",
        "pf_notfound": "не найден, смотри README",
        "pf_responds": "демон отвечает",
        "pf_noresponds": "НЕ отвечает, Strix не запустится",
        "pf_present": "скачан",
        "pf_willpull": "будет скачан при первом запуске (~4 ГБ)",
        "pf_nomodel": "STRIX_LLM не задан",
        "pf_keyset": "задан, в команду не попадает",
        "pf_nokey": "LLM_API_KEY не задан",
        "col_sev": "критичность", "col_cvss": "cvss", "col_conf": "увер.",
        "col_cwe": "cwe", "col_title": "находка",
        "resume_note": "Strix подхватит историю корневого агента и живых субагентов.",
        "new_cap": "Новый потолок расхода, USD", "resume_q": "Продолжить прогон?",
    },
}


def t(key: str) -> str:
    return T.get(LANG, T["en"]).get(key, T["en"].get(key, key))


# ---------------------------------------------------------------- output ---
def say(msg: str, style: str = "") -> None:
    if RICH:
        C.print(msg, style=style)
    else:
        print(re.sub(r"\[/?[a-z0-9 _]+\]", "", msg))


def head(title: str, sub: str = "") -> None:
    if RICH:
        C.print(Panel.fit(f"[bold]{title}[/bold]" + (f"\n[dim]{sub}[/dim]" if sub else ""),
                          border_style="cyan", box=box.ROUNDED))
    else:
        print(f"\n=== {title} ===\n{sub}")


def ask(label: str, default: str | None = None) -> str:
    try:
        if RICH:
            return Prompt.ask(f"[cyan]{label}[/cyan]", default=default) if default \
                else Prompt.ask(f"[cyan]{label}[/cyan]")
        v = input(f"{label}" + (f" [{default}]: " if default else ": ")).strip()
        return v or (default or "")
    except EOFError:
        raise SystemExit(0)


def ask_int(label: str, default: int) -> int:
    try:
        if RICH:
            return IntPrompt.ask(f"[cyan]{label}[/cyan]", default=default)
        v = input(f"{label} [{default}]: ").strip()
        return int(v) if v.isdigit() else default
    except EOFError:
        raise SystemExit(0)


def yes(label: str, default: bool = False) -> bool:
    try:
        if RICH:
            return Confirm.ask(f"[yellow]{label}[/yellow]", default=default)
        v = input(f"{label} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
        return default if not v else v in ("y", "yes", "д", "да")
    except EOFError:
        raise SystemExit(0)


def menu(title: str, items: list[tuple[str, str]]) -> str:
    """items: list of (key, "Name|description"). Returns the chosen key."""
    if RICH:
        tb = Table(box=box.SIMPLE, show_header=False, pad_edge=False)
        tb.add_column(style="bold cyan", width=4)
        tb.add_column(style="bold")
        tb.add_column(style="dim")
        for i, (_k, d) in enumerate(items, 1):
            name, _, desc = d.partition("|")
            tb.add_row(str(i), name, desc)
        C.print(f"\n[bold]{title}[/bold]")
        C.print(tb)
    else:
        print(f"\n{title}")
        for i, (_k, d) in enumerate(items, 1):
            print(f"  {i}) {d.replace('|', ' - ')}")
    while True:
        try:
            v = input(t("choice") + ": ").strip()
        except EOFError:
            say(t("eof"), "dim")
            raise SystemExit(0)
        if v.isdigit() and 1 <= int(v) <= len(items):
            return items[int(v) - 1][0]
        say(t("need_number") % len(items), "red")


# ------------------------------------------------------------- preflight ---
def read_strix_env() -> dict:
    """Model and key: environment first, then ~/.strix/env, then cli-config.json."""
    env = {}
    envf = STRIX_DIR / "env"
    if envf.exists():
        for line in envf.read_text(encoding="utf-8").splitlines():
            m = re.match(r"(?:export\s+)?(\w+)=(.*)", line.strip())
            if m:
                env[m.group(1)] = m.group(2).strip('"\'')
    cfg = STRIX_DIR / "cli-config.json"
    if cfg.exists():
        try:
            block = json.loads(cfg.read_text(encoding="utf-8")).get("env", {})
            for k, v in block.items():
                env.setdefault(k, str(v))
        except Exception:
            pass
    for k in ("STRIX_LLM", "LLM_API_KEY", "LLM_API_BASE"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    return env


def preflight() -> dict:
    st: dict = {"strix": bool(STRIX), "version": ""}
    if STRIX:
        try:
            r = subprocess.run([STRIX, "--version"], capture_output=True, text=True, timeout=60)
            out = (r.stdout or r.stderr).strip()
            st["version"] = out.splitlines()[0] if out else ""
        except Exception:
            pass
    try:
        st["docker"] = subprocess.run(["docker", "info"], capture_output=True,
                                      text=True, timeout=60).returncode == 0
    except Exception:
        st["docker"] = False
    try:
        st["sandbox"] = "strix-sandbox" in subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}"],
            capture_output=True, text=True, timeout=60).stdout
    except Exception:
        st["sandbox"] = False
    env = read_strix_env()
    st["model"] = env.get("STRIX_LLM", "")
    st["key"] = bool(env.get("LLM_API_KEY"))
    st["env"] = env
    try:
        st["free_gb"] = shutil.disk_usage(str(WORK.parent if WORK.parent.exists() else HOME)).free // 2**30
    except Exception:
        st["free_gb"] = 0
    return st


def show_preflight(st: dict) -> bool:
    rows = [
        (st["strix"], t("pf_strix"), st["version"] or t("pf_notfound")),
        (st["docker"], t("pf_docker"),
         t("pf_responds") if st["docker"] else t("pf_noresponds")),
        (st["sandbox"], t("pf_sandbox"),
         t("pf_present") if st["sandbox"] else t("pf_willpull")),
        (bool(st["model"]), t("pf_model"), st["model"] or t("pf_nomodel")),
        (st["key"], t("pf_key"), t("pf_keyset") if st["key"] else t("pf_nokey")),
        (st["free_gb"] > 5, t("pf_disk"), f"{st['free_gb']} GB"),
    ]
    if RICH:
        tb = Table(box=box.SIMPLE, show_header=False)
        tb.add_column(width=4); tb.add_column(width=16); tb.add_column(style="dim")
        for ok, name, val in rows:
            tb.add_row("[green]OK[/green]" if ok else "[red]--[/red]", name, str(val))
        C.print(tb)
    else:
        for ok, name, val in rows:
            print(f"  {'OK' if ok else '--'}  {name}: {val}")
    ok_all = st["strix"] and st["docker"] and st["model"] and st["key"]
    if not ok_all:
        say(t("missing"), "bold red")
    return ok_all


# --------------------------------------------------------------- presets ---
PRESETS = {
    "triage": dict(
        en=("Quick triage", "First look, CI, smoke check"),
        ru=("Быстрый triage", "Первый взгляд, CI, проверка что живо"),
        mode="quick", budget=3.0, turns=100,
        focus=("Prioritize critical and high severity issues: RCE, command and SQL injection, "
               "authentication bypass, SSRF. Do not spend turns on informational findings, "
               "missing headers, or best-practice advice without a demonstrated impact path."),
        why_en="quick is built for minutes; $3 is generous for a first pass",
        why_ru="quick рассчитан на минуты; $3 хватает с запасом"),
    "web": dict(
        en=("Web application", "Routine assessment of a live app"),
        ru=("Веб-приложение", "Рабочая оценка живого приложения"),
        mode="standard", budget=20.0, turns=250,
        focus=("Authorized web application assessment. Prioritize broken access control, "
               "authentication and session handling, injection with demonstrable impact, "
               "SSRF and business logic flaws. Validate with a minimal proof of concept."),
        why_en="standard is designed for 30-60 minutes",
        why_ru="standard рассчитан на 30-60 минут"),
    "api": dict(
        en=("API from a spec", "OpenAPI or Postman plus a live URL"),
        ru=("API по спецификации", "OpenAPI или Postman плюс живой адрес"),
        mode="standard", budget=25.0, turns=300,
        focus=("Authorized API assessment. Use the supplied specification as the endpoint "
               "contract. Prioritize BOLA/IDOR across tenants, function level authorization, "
               "mass assignment, JWT and session handling. Compare access to the same object "
               "across roles. Validate impact with the smallest possible sample; never "
               "enumerate whole datasets."),
        why_en="the spec gives the contract, the URL gives something to verify against",
        why_ru="спецификация даёт контракт, живой адрес даёт что проверять"),
    "code": dict(
        en=("Source code", "Local directory or repository"),
        ru=("Исходный код", "Локальный каталог или репозиторий"),
        mode="standard", budget=15.0, turns=250,
        focus=("Authorized white-box review. Map trust boundaries, authorization middleware, "
               "route registration, deserialization, file handling and third-party "
               "integrations. Treat static candidates as hypotheses until runtime behaviour "
               "is validated. Do not modify source files, dependencies, CI configuration or "
               "git history."),
        why_en="white-box is cheaper: reading code beats probing endpoints",
        why_ru="white-box дешевле: читать код быстрее, чем перебирать запросы"),
    "release": dict(
        en=("Release audit", "Deep, long, expensive. Before shipping"),
        ru=("Релизный аудит", "Глубоко, долго, дорого. Перед выпуском"),
        mode="deep", budget=80.0, turns=400,
        focus=("Thorough pre-release security review. Cover the full attack surface: "
               "authentication, authorization, injection, SSRF, file handling, secrets, "
               "supply chain and business logic. Report coverage gaps explicitly."),
        why_en="deep runs 1-4 hours and adds Semgrep, AST search and dependency checks",
        why_ru="deep идёт 1-4 часа, включает Semgrep, AST-поиск и проверку зависимостей"),
}


def choose_preset() -> dict:
    items = []
    for k, v in PRESETS.items():
        name, desc = v[LANG] if LANG in v else v["en"]
        items.append((k, f"{name}|{desc}"))
    items.append(("custom", t("custom")))
    k = menu(t("preset"), items)
    if k == "custom":
        return dict(title=t("custom").split("|")[0], mode="", budget=0.0, turns=0,
                    focus="", why="")
    p = PRESETS[k]
    why = p.get(f"why_{LANG}", p["why_en"])
    say(f"\n  [dim]{t('basis')}: {why}[/dim]", "dim")
    return dict(title=(p[LANG] if LANG in p else p["en"])[0], mode=p["mode"],
                budget=p["budget"], turns=p["turns"], focus=p["focus"], why=why)


# ---------------------------------------------------------------- target ---
def target_kind() -> tuple[str, list[str]]:
    k = menu(t("target_q"), [("url", t("t_url")), ("code", t("t_code")),
                             ("repo", t("t_repo")), ("api", t("t_api")),
                             ("list", t("t_list"))])
    if k == "url":
        return k, [ask(t("ask_url"))]
    if k == "code":
        p = ask(t("ask_dir"))
        if not Path(p).expanduser().is_dir():
            say(f"{t('no_dir')}: {p}", "red"); sys.exit(1)
        say(t("writable"), "yellow")
        if not yes(t("is_copy"), True):
            say(t("abort_copy"), "red"); sys.exit(1)
        return k, [str(Path(p).expanduser())]
    if k == "repo":
        return k, [ask(t("ask_repo"))]
    if k == "api":
        spec = ask(t("ask_spec"))
        if not Path(spec).expanduser().is_file():
            say(f"{t('no_file')}: {spec}", "red"); sys.exit(1)
        return k, [str(Path(spec).expanduser()), ask(t("ask_base"))]
    f = ask(t("ask_list"))
    if not Path(f).expanduser().is_file():
        say(f"{t('no_file')}: {f}", "red"); sys.exit(1)
    return k, [str(Path(f).expanduser())]


def slug(s: str) -> str:
    s = re.sub(r"https?://", "", s)
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_")
    return s[:60] or "engagement"


# ------------------------------------------------------- live monitoring ---
def _port_busy(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.4)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _newest_run_after(t0: float, timeout: int = 90) -> Path | None:
    end = time.time() + timeout
    while time.time() < end:
        if RUNS.is_dir():
            for d in RUNS.iterdir():
                if d.is_dir() and d.stat().st_mtime >= t0 - 2:
                    return d
        time.sleep(2)
    return None


def _scan_state(run: Path) -> dict:
    s = {"turn": "-", "agent": "-", "found": 0, "surfaces": 0, "cost": "-"}
    log = run / "strix.log"
    if log.exists():
        try:
            tail = log.read_text(encoding="utf-8", errors="replace")[-40000:]
            m = None
            for m in re.finditer(r"Starting turn (\d+), current_agent=([^\n]+)", tail):
                pass
            if m:
                s["turn"], s["agent"] = m.group(1), m.group(2).strip()[:38]
        except Exception:
            pass
    for name, key, path in (("findings.sarif", "found", ("runs", 0, "results")),
                            ("coverage.json", "surfaces", ("summary", "surfaces_reviewed"))):
        f = run / name
        if not f.exists():
            continue
        try:
            d = json.loads(f.read_text(encoding="utf-8"))
            if name == "findings.sarif":
                s["found"] = len(d.get("runs", [{}])[0].get("results", []))
            else:
                s["surfaces"] = d.get("summary", {}).get("surfaces_reviewed", 0)
        except Exception:
            pass
    rj = run / "run.json"
    if rj.exists():
        try:
            d = json.loads(rj.read_text(encoding="utf-8"))
            c = d.get("cost") or d.get("total_cost") or (d.get("usage") or {}).get("cost")
            if c is not None:
                s["cost"] = f"${float(c):.4f}"
        except Exception:
            pass
    return s


def start_viewer_for(run_name: str, port: int = VIEWER_PORT) -> str:
    while _port_busy(port) and port < VIEWER_PORT + 20:
        port += 1
    logf = WORK / f"_viewer_{port}.log"
    env = dict(os.environ, **read_strix_env())
    with open(logf, "w") as lf:
        subprocess.Popen([STRIX, "view", run_name, "--host", "127.0.0.1",
                          "--port", str(port), "--no-open"],
                         cwd=str(WORK), env=env, stdout=lf, stderr=subprocess.STDOUT)
    for _ in range(12):
        time.sleep(1)
        m = re.search(r"(http://127\.0\.0\.1:\d+/\?token=\S+)",
                      logf.read_text(encoding="utf-8", errors="replace"))
        if m:
            return m.group(1)
    return ""


def _scan_pids() -> list[str]:
    r = subprocess.run(["pgrep", "-f", "strix -n --target"], capture_output=True, text=True)
    return r.stdout.split()


def stop_running_scan() -> None:
    pids = _scan_pids()
    if not pids:
        say(t("no_scans"), "yellow"); return
    say(f"{t('running')} {len(pids)}", "cyan")
    if not yes(t("stop_q"), False):
        return
    for p in pids:
        subprocess.run(["kill", "-TERM", p])
    for i in range(20):
        time.sleep(2)
        if not _scan_pids():
            say(f"{t('stopped_in')} {i * 2}s. {RUNS}", "green"); return
    say(t("no_graceful"), "red")
    if yes(t("force_q"), False):
        for p in pids:
            subprocess.run(["kill", "-9", p])



def run_scan(cmd: list[str], eng: Path | None = None, resume_run: Path | None = None) -> int:
    """Запуск Strix с живой панелью и веб-просмотрщиком.

    Общая для нового скана и для продолжения: раньше resume шёл мимо панели
    и мимо ссылки на просмотрщик, потому что был отдельной веткой кода.
    """
    say(t("rc_note"), "yellow")
    say(t("ctrlc"), "yellow")

    log = (eng / "strix.log") if eng else (WORK / "_resume.log")
    env = dict(os.environ, **read_strix_env())
    t0 = time.time()
    lf = open(log, "a", encoding="utf-8")
    pr = subprocess.Popen(cmd, cwd=str(WORK), env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)

    def _pump() -> None:
        for line in pr.stdout:
            lf.write(line)
            lf.flush()

    threading.Thread(target=_pump, daemon=True).start()

    # при resume прогон уже известен, ждать появления каталога не нужно
    run = resume_run if resume_run is not None else _newest_run_after(t0)
    if run:
        link = start_viewer_for(run.name)
        say(f"{t('run_is')} [bold]{run.name}[/bold]", "cyan")
        if link:
            say(t("watch"), "green")
            say(f"   {link}", "bold cyan")
            say(t("token_warn"), "yellow")
            if eng:
                (eng / "viewer-url.txt").write_text(link + "\n", encoding="utf-8")

    rc = None
    try:
        if RICH and run:
            from rich.live import Live
            with Live(refresh_per_second=2, console=C) as live:
                while pr.poll() is None:
                    s = _scan_state(run)
                    el = round(time.time() - t0)
                    tb = Table(box=box.ROUNDED, show_header=False,
                               title=f"[bold]{t('scanning')}[/bold]  {el // 60}m {el % 60}s")
                    tb.add_column(style="bold", width=18); tb.add_column()
                    tb.add_row(t("turn"), s["turn"])
                    tb.add_row(t("agent"), s["agent"])
                    tb.add_row(t("surfaces"), str(s["surfaces"]))
                    tb.add_row(t("sarif"), str(s["found"]))
                    tb.add_row(t("spend"), s["cost"])
                    tb.add_row(t("stop_hint"), t("stop_key"))
                    live.update(tb)
                    time.sleep(2)
        else:
            while pr.poll() is None:
                s = _scan_state(run) if run else {}
                print(f"\r  {t('turn')} {s.get('turn', '-')} | "
                      f"{str(s.get('agent', '-'))[:30]} | {round(time.time() - t0)}s   ",
                      end="", flush=True)
                time.sleep(3)
            print()
        rc = pr.wait()
    except KeyboardInterrupt:
        say(t("stopping"), "yellow")
        pr.terminate()
        try:
            rc = pr.wait(timeout=60)
        except subprocess.TimeoutExpired:
            say(t("no_react"), "red")
            pr.kill()
            rc = pr.wait()
    finally:
        lf.close()

    dt = round(time.time() - t0)
    if eng:
        (eng / "status.txt").write_text(
            f"exit_code={rc}\nseconds={dt}\n"
            f"finished={datetime.now().isoformat(timespec='seconds')}\n", encoding="utf-8")
    head(t("result"), f"{dt}s, exit code {rc}")
    if rc == 0:
        say(t("clean"), "green")
    elif rc == 2:
        say(t("found"), "yellow")
        if run:
            summarize(run)
        else:
            summarize_latest()
    else:
        say(f"{t('err')} {rc}. {log}", "red")
    if run:
        say(f"\n{t('findings_at')} {run}", "dim")
    return rc or 0


# ---------------------------------------------------------------- launch ---
def build_and_run() -> int:
    kind, targets = target_kind()
    p = choose_preset()

    if not p["mode"]:
        p["mode"] = menu(t("mode_q"), [("quick", t("m_quick")), ("standard", t("m_std")),
                                       ("deep", t("m_deep"))])
        p["budget"] = float(ask(t("budget_q"), "15"))
        p["turns"] = ask_int(t("turns_q"), 250)

    name = ask(t("name_q"), slug(targets[0]))
    extra = ask(t("notes_q"), "")
    scope_mode = "full"
    if kind in ("code", "repo"):
        scope_mode = menu(t("scope_q"), [("full", t("s_full")), ("diff", t("s_diff"))])

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    eng = ENGAGEMENTS / f"{ts}_{name}"
    eng.mkdir(parents=True, exist_ok=True)

    body = [p["focus"]]
    if extra:
        body.append("\nOperator notes: " + extra)
    body += ["", "Operational constraints:",
             "- Test only the targets supplied above; do not pivot to discovered hosts.",
             "- No denial of service, destructive payloads, data deletion, or persistence.",
             "- Use test accounts only; extract the minimum needed to show impact.",
             "- Report a finding only with a reproducible PoC and a concrete impact path.",
             "- Mark unproven hypotheses separately; do not inflate severity.",
             "- Report coverage gaps and blocked paths explicitly."]
    instr = eng / "instruction.md"
    instr.write_text("\n".join(body) + "\n", encoding="utf-8")

    cmd = [STRIX, "-n"]
    if kind == "list":
        cmd += ["--target-list", targets[0]]
    else:
        for tg in targets:
            cmd += ["--target", tg]
    cmd += ["--scan-mode", p["mode"], "--scope-mode", scope_mode,
            "--max-budget", str(p["budget"]), "--max-turns", str(p["turns"]),
            "--instruction-file", str(instr)]

    (eng / "command.txt").write_text(" ".join(shlex.quote(c) for c in cmd) + "\n",
                                     encoding="utf-8")
    (eng / "scope.md").write_text(
        f"# {name}\n\ncreated: {datetime.now().isoformat(timespec='seconds')}\n"
        f"mode: {p['mode']}\ncap: ${p['budget']}\nturns per agent: {p['turns']}\n"
        f"code scope: {scope_mode}\n\ntargets:\n"
        + "".join(f"- {x}\n" for x in targets)
        + f"\npreset: {p['title']}\nbasis: {p.get('why', '')}\n", encoding="utf-8")

    head(t("plan"), f"{t('trace')}: {eng}")
    if RICH:
        tb = Table(box=box.SIMPLE, show_header=False)
        tb.add_column(style="bold", width=18); tb.add_column()
        for k_, v_ in ((t("targets"), ", ".join(targets)), (t("mode"), p["mode"]),
                       (t("cap"), f"${p['budget']}"), (t("turns"), str(p["turns"])),
                       (t("scope"), scope_mode), (t("preset_row"), p["title"])):
            tb.add_row(k_, v_)
        C.print(tb)
        C.print(f"\n[dim]{' '.join(shlex.quote(c) for c in cmd)}[/dim]")
    else:
        print(" ".join(shlex.quote(c) for c in cmd))

    if not yes(t("run_q"), True):
        say(f"{t('cancelled')} {eng}/command.txt", "yellow")
        return 0

    rc = run_scan(cmd, eng=eng)
    say(f"\n{t('traces')} {eng}", "dim")
    return rc


# --------------------------------------------------------------- results ---
def list_runs() -> list[Path]:
    if not RUNS.is_dir():
        return []
    return sorted([d for d in RUNS.iterdir() if d.is_dir()],
                  key=lambda d: d.stat().st_mtime, reverse=True)


def summarize(run: Path) -> None:
    j = run / "vulnerabilities.json"
    if not j.exists():
        say(f"  {run.name}: {t('no_json')}", "dim"); return
    try:
        d = json.loads(j.read_text(encoding="utf-8"))
        v = d if isinstance(d, list) else d.get("vulnerabilities", [])
    except Exception as e:
        say(f"  {e}", "red"); return
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    v.sort(key=lambda x: (order.get(str(x.get("severity")).lower(), 9),
                          -float(x.get("cvss") or 0)))
    if RICH:
        tb = Table(title=run.name, box=box.SIMPLE)
        for key in ("col_sev", "col_cvss", "col_conf", "col_cwe", "col_title"):
            tb.add_column(t(key), style="bold" if key == "col_sev" else "")
        colors = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "dim"}
        for x in v:
            s = str(x.get("severity", "?")).lower()
            tb.add_row(f"[{colors.get(s, 'white')}]{s}[/]", str(x.get("cvss", "")),
                       str(x.get("confidence", "")), str(x.get("cwe", "")),
                       str(x.get("title", ""))[:64])
        C.print(tb)
    else:
        for x in v:
            print(f"  {x.get('severity')} {x.get('cvss')} {x.get('title')}")


def summarize_latest() -> None:
    r = list_runs()
    if r:
        summarize(r[0])


def pick_run(title: str) -> Path | None:
    runs = list_runs()
    if not runs:
        say(t("no_runs"), "yellow"); return None
    items = []
    for d in runs[:15]:
        when = datetime.fromtimestamp(d.stat().st_mtime).strftime("%d.%m %H:%M")
        n = 0
        j = d / "vulnerabilities.json"
        if j.exists():
            try:
                x = json.loads(j.read_text(encoding="utf-8"))
                n = len(x if isinstance(x, list) else x.get("vulnerabilities", []))
            except Exception:
                pass
        items.append((d.name, f"{d.name}|{when}, {t('run_sum')} {n}"))
    return RUNS / menu(title, items)


def do_resume() -> int:
    run = pick_run(t("pick_run"))
    if not run:
        return 0
    say(f"\n[dim]{t('resume_note')}[/dim]", "dim")
    b = ask(t("new_cap"), "15")
    cmd = [STRIX, "-n", "--resume", run.name, "--max-budget", b]
    say("  " + " ".join(shlex.quote(c) for c in cmd), "dim")
    if not yes(t("resume_q"), True):
        return 0
    # ⛔ раньше здесь был простой subprocess.run: ни панели, ни ссылки на
    # просмотрщик, ни мягкой остановки. Теперь тот же путь, что у нового скана.
    return run_scan(cmd, resume_run=run)


def viewer_menu() -> None:
    r = subprocess.run(["pgrep", "-f", "strix view"], capture_output=True, text=True)
    pids = r.stdout.split()
    if pids:
        say(f"{t('viewer_up')} {len(pids)}", "green")
        if yes(t("kill_q"), False):
            for p in pids:
                subprocess.run(["kill", p])
            say(t("killed"), "green")
        return
    run = pick_run(t("pick_run"))
    if not run:
        return
    link = start_viewer_for(run.name)
    if link:
        say(t("open_browser"), "green")
        say("  " + link, "cyan")
        say(t("token_warn2"), "yellow")
    else:
        say(f"{t('no_link')} {WORK}", "red")


HELP_EN = """
[bold]What this wrapper does[/bold]

  Builds correct strix commands and keeps a record of every run.

[bold]Why it is needed[/bold]

  • Strix defaults to [red]deep[/red]: forget the flag, get hours and tens of dollars
  • [yellow]--max-turns[/yellow] is PER AGENT, and a scan spawns several
  • [yellow]--max-budget[/yellow] is checked AFTER a model reply, small overshoot happens;
    subagents wind down near 90% so the root agent can write the report
  • exit code [green]2[/green] means "vulnerabilities found", not a failure
  • a local directory is mounted [red]writable[/red]: Strix runs the app and leaves files

[bold]Where things live[/bold]

  run records     $USESTRIX_HOME/engagements/<stamp>_<name>/
                  command.txt, scope.md, instruction.md, strix.log, status.txt
  Strix findings  $USESTRIX_HOME/strix_runs/<run>/
                  vulnerabilities.json, report .md, .csv, .sarif, coverage.json

[bold]Useful fields in a finding[/bold]

  severity, cvss, confidence, cwe, poc_script_code, fix_pr_body,
  counterevidence (what was tested AGAINST the finding), severity_change_conditions
"""

HELP_RU = """
[bold]Что делает обёртка[/bold]

  Собирает команду strix без ошибок и хранит след каждого запуска.

[bold]Почему это нужно[/bold]

  • у strix режим по умолчанию [red]deep[/red]: забыл флаг - получил часы работы
    и десятки долларов
  • [yellow]--max-turns[/yellow] считается НА КАЖДОГО агента, а их бывает несколько
  • [yellow]--max-budget[/yellow] проверяется ПОСЛЕ ответа модели, небольшой
    перерасход возможен; субагенты сворачиваются около 90%
  • код возврата [green]2[/green] означает «найдены уязвимости», а не сбой
  • локальный каталог монтируется [red]с правом записи[/red]: Strix запускает
    приложение, в каталоге появятся чужие файлы

[bold]Где что лежит[/bold]

  следы запусков   $USESTRIX_HOME/engagements/<метка>_<имя>/
                   command.txt, scope.md, instruction.md, strix.log, status.txt
  находки Strix    $USESTRIX_HOME/strix_runs/<прогон>/
                   vulnerabilities.json, отчёт .md, .csv, .sarif, coverage.json

[bold]Полезные поля находки[/bold]

  severity, cvss, confidence, cwe, poc_script_code, fix_pr_body,
  counterevidence (что проверяли ПРОТИВ находки), severity_change_conditions
"""


def main() -> int:
    if "--version" in sys.argv or "-V" in sys.argv:
        print(f"usestrix {__version__}")
        return 0
    WORK.mkdir(parents=True, exist_ok=True)
    ENGAGEMENTS.mkdir(parents=True, exist_ok=True)
    head(t("title"), f"{t('subtitle')}  ·  v{__version__}")
    st = preflight()
    if not show_preflight(st):
        return 1
    while True:
        k = menu(t("menu"), [("new", t("new")), ("resume", t("resume")),
                             ("results", t("results")), ("viewer", t("viewer")),
                             ("stop", t("stop")), ("help", t("help")),
                             ("quit", t("quit"))])
        if k == "new":
            build_and_run()
        elif k == "resume":
            do_resume()
        elif k == "results":
            r = pick_run(t("pick_run"))
            if r:
                summarize(r)
        elif k == "viewer":
            viewer_menu()
        elif k == "stop":
            stop_running_scan()
        elif k == "help":
            txt = HELP_RU if LANG == "ru" else HELP_EN
            C.print(Panel(txt, border_style="cyan", box=box.ROUNDED)) if RICH else print(txt)
        else:
            return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
    except EOFError:
        sys.exit(0)
