from __future__ import annotations

import json
import html
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator

from modules.Validation.approval import approve_plan
from modules.Validation.sandbox import execute_plan
from .demo import DEMO_TARGET, create_demo_output
from .progress import scan_progress
from .store import WebStore


SCAN_MODULES = {"recon", "surface", "cve", "plan", "infra", "auth", "business",
                "injection", "ssrf", "xss", "all"}


def _target(value: str) -> str:
    candidate = value if "://" in value else "http://" + value
    parsed = urllib.parse.urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("invalid HTTP(S) target")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("target credentials, query and fragment are not allowed")
    return parsed.geturl().rstrip("/")


class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    target: str
    authorized: bool

    @field_validator("target")
    @classmethod
    def target_is_valid(cls, value):
        return _target(value)


class ScanCreate(BaseModel):
    module: str = "all"
    profile: str = "safe"
    threads: int = Field(default=10, ge=1, le=50)
    rate: float = Field(default=5, gt=0, le=100)
    timeout: float = Field(default=10, gt=0, le=60)
    recursive: bool = False
    max_depth: int = Field(default=2, ge=1, le=5)
    skip_deps: bool = False


class ApprovalCreate(BaseModel):
    item_ids: list[str] = Field(min_length=1, max_length=100)
    approved_by: str = Field(min_length=1, max_length=100)
    ttl: int = Field(default=3600, ge=60, le=86400)


class ExecutionCreate(BaseModel):
    confirmed: bool


class ScanLauncher:
    def __init__(self, root: Path):
        self.root = root
        self.entrypoint = root / "Buggy.py"
        self._processes: dict[int, subprocess.Popen] = {}
        self._exit_codes: dict[int, int] = {}
        self._lock = threading.Lock()

    def launch(self, project: dict, request: ScanCreate, output_dir: Path) -> int:
        if request.module not in SCAN_MODULES or request.profile not in {"safe", "standard"}:
            raise ValueError("unsupported scan module or profile")
        output_dir.mkdir(parents=True, exist_ok=False)
        settings = request.model_dump()
        settings["requests_per_minute"] = round(request.rate * 60)
        (output_dir / "webui-scan.json").write_text(
            json.dumps(settings, indent=2), encoding="utf-8"
        )
        log = open(output_dir / "webui-process.log", "ab", buffering=0)
        command = [
            sys.executable, "-u", str(self.entrypoint), "-t", project["target"],
            "-m", request.module, "-o", str(output_dir), "--profile", request.profile,
            "--threads", str(request.threads), "--rate", str(request.rate),
            "--timeout", str(request.timeout), "--no-banner",
        ]
        if request.skip_deps:
            command.append("--skip-deps")
        if request.recursive:
            command.extend(["--recursive", "--max-depth", str(request.max_depth)])
        process = subprocess.Popen(command, cwd=self.root, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True, close_fds=True)
        log.close()
        with self._lock:
            self._processes[process.pid] = process
        return process.pid

    def state(self, pid: int | None) -> str:
        if not pid:
            return "failed"
        with self._lock:
            process = self._processes.get(pid)
            if process is not None:
                code = process.poll()
                if code is None:
                    return "running"
                self._exit_codes[pid] = code
                return "completed" if code == 0 else "failed"
            if pid in self._exit_codes:
                return "completed" if self._exit_codes[pid] == 0 else "failed"
        try:
            os.kill(pid, 0)
            return "running"
        except PermissionError:
            return "running"
        except ProcessLookupError:
            # A process launched before a UI restart is no longer present. Its
            # exact exit code is unavailable, so completed is the honest state.
            return "completed"

    def cancel(self, pid: int | None) -> bool:
        if not pid:
            return False
        with self._lock:
            process = self._processes.get(pid)
            if process is None or process.poll() is not None:
                return False
        try:
            if os.name == "posix":
                os.killpg(pid, signal.SIGTERM)
            else:
                process.terminate()
        except ProcessLookupError:
            return False
        with self._lock:
            self._exit_codes[pid] = -int(signal.SIGTERM)
        return True


def _read_json(path: Path):
    if not path.is_file() or path.stat().st_size > 10 * 1024 * 1024:
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def create_app(workspace: str | Path | None = None) -> FastAPI:
    root = Path(workspace or Path(__file__).resolve().parents[2]).resolve()
    output_root = root / "output"
    output_root.mkdir(parents=True, exist_ok=True)
    store = WebStore(output_root / ".buggy-ui.db")
    launcher = ScanLauncher(root)
    app = FastAPI(title="Buggy Local API", version="0.1.0",
                  description="Local-only orchestration API for authorized scans")
    app.state.store, app.state.output_root, app.state.launcher = store, output_root, launcher
    web_root = Path(__file__).parent
    templates = Jinja2Templates(directory=web_root / "templates")
    app.mount("/static", StaticFiles(directory=web_root / "static"), name="static")
    app.state.csrf_token = secrets.token_urlsafe(32)

    def refresh_scan(scan: dict) -> tuple[dict, bool]:
        if scan["status"] != "running":
            return scan, False
        status = launcher.state(scan.get("pid"))
        if status == "running":
            return scan, False
        return store.update_scan_status(scan["id"], status) or scan, True

    def refresh_scans(scans: list[dict]) -> list[dict]:
        return [refresh_scan(scan)[0] for scan in scans]

    def project_names() -> dict[str, str]:
        return {project["id"]: project["name"] for project in store.projects()}

    def read_log_tail(path: Path) -> str:
        log_path = path / "webui-process.log"
        if not log_path.is_file():
            return ""
        with log_path.open("rb") as stream:
            stream.seek(max(0, log_path.stat().st_size - 65536))
            return stream.read().decode("utf-8", errors="replace")

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; "
            "style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
        )
        return response

    def csrf_ok(request: Request, token: str) -> bool:
        cookie = request.cookies.get("buggy_csrf", "")
        return bool(token and secrets.compare_digest(token, app.state.csrf_token)
                    and secrets.compare_digest(cookie, app.state.csrf_token))

    @app.get("/api/health")
    async def health():
        return {"status": "ok", "bind_policy": "localhost-only"}

    @app.get("/api/projects")
    async def projects():
        return store.projects()

    @app.post("/api/projects", status_code=201)
    async def create_project(request: ProjectCreate):
        if request.authorized is not True:
            raise HTTPException(400, "explicit authorization confirmation is required")
        return store.create_project(request.name.strip(), request.target)

    @app.get("/api/projects/{project_id}/scans")
    async def scans(project_id: str):
        if not store.project(project_id):
            raise HTTPException(404, "project not found")
        return refresh_scans(store.scans(project_id))

    @app.post("/api/projects/{project_id}/scans", status_code=202)
    async def create_scan(project_id: str, request: ScanCreate):
        project = store.project(project_id)
        if not project:
            raise HTTPException(404, "project not found")
        if request.module not in SCAN_MODULES or request.profile not in {"safe", "standard"}:
            raise HTTPException(400, "unsupported module or profile")
        slug = re.sub(r"[^a-zA-Z0-9_.-]", "_", project["name"])[:40] or "project"
        output = output_root / f"ui_{slug}_{int(time.time() * 1000)}"
        try:
            pid = launcher.launch(project, request, output)
        except (OSError, ValueError) as exc:
            raise HTTPException(500, str(exc)) from exc
        return store.create_scan(project_id, request.module, request.profile, str(output), pid)

    def scan_or_404(scan_id: str) -> tuple[dict, Path]:
        scan = store.scan(scan_id)
        if not scan:
            raise HTTPException(404, "scan not found")
        scan = refresh_scan(scan)[0]
        path = Path(scan["output_dir"]).resolve()
        if output_root not in path.parents:
            raise HTTPException(400, "invalid scan path")
        return scan, path

    @app.get("/api/scans/{scan_id}")
    async def scan_detail(scan_id: str):
        scan, path = scan_or_404(scan_id)
        return {**scan, "surface": _read_json(path / "surface" / "summary.json"),
                "intelligence": _read_json(path / "intelligence" / "cves.json").get("summary", {}),
                "plan": _read_json(path / "validation" / "plan.json").get("summary", {}),
                "validation": _read_json(path / "validation" / "execution.json")}

    @app.get("/api/scans/{scan_id}/cves")
    async def scan_cves(scan_id: str):
        _, path = scan_or_404(scan_id)
        return _read_json(path / "intelligence" / "cves.json")

    @app.get("/api/scans/{scan_id}/plan")
    async def scan_plan(scan_id: str):
        _, path = scan_or_404(scan_id)
        return _read_json(path / "validation" / "plan.json")

    @app.post("/api/scans/{scan_id}/approve")
    async def scan_approve(scan_id: str, request: ApprovalCreate):
        scan, path = scan_or_404(scan_id)
        if scan["module"] == "demo":
            raise HTTPException(400, "demo scans are read-only")
        try:
            return approve_plan(str(path), request.item_ids, request.approved_by, request.ttl)
        except (OSError, ValueError, KeyError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.post("/api/scans/{scan_id}/execute")
    async def scan_execute(scan_id: str, request: ExecutionCreate):
        if request.confirmed is not True:
            raise HTTPException(400, "explicit execution confirmation is required")
        scan, path = scan_or_404(scan_id)
        if scan["module"] == "demo":
            raise HTTPException(400, "demo scans are read-only")
        try:
            return execute_plan(str(path), lab_mode=False)
        except (OSError, ValueError, KeyError) as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/", response_class=HTMLResponse)
    async def dashboard(request: Request):
        projects = store.projects()
        names = {project["id"]: project["name"] for project in projects}
        response = templates.TemplateResponse(request, "dashboard.html", {
            "projects": projects, "scans": refresh_scans(store.scans()),
            "project_names": names,
            "csrf": app.state.csrf_token, "demo_target": DEMO_TARGET,
        })
        response.set_cookie("buggy_csrf", app.state.csrf_token, httponly=True,
                            samesite="strict", secure=False)
        return response

    @app.get("/ui/scans/recent", response_class=HTMLResponse)
    async def ui_recent_scans(request: Request):
        return templates.TemplateResponse(request, "recent_scans.html", {
            "scans": refresh_scans(store.scans()), "project_names": project_names(),
        })

    @app.post("/ui/projects")
    async def ui_create_project(request: Request, name: str = Form(...),
                                target: str = Form(...), authorized: str = Form(""),
                                csrf: str = Form(...)):
        if not csrf_ok(request, csrf):
            raise HTTPException(403, "invalid CSRF token")
        if authorized != "yes":
            raise HTTPException(400, "authorization confirmation is required")
        try:
            store.create_project(name.strip(), _target(target))
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        return RedirectResponse("/", status_code=303)

    @app.post("/ui/demo")
    async def ui_demo(request: Request, csrf: str = Form(...)):
        if not csrf_ok(request, csrf):
            raise HTTPException(403, "invalid CSRF token")
        try:
            output = create_demo_output(output_root)
            project = store.create_project("Buggy Demo", DEMO_TARGET)
            scan = store.create_scan(
                project["id"], "demo", "safe", str(output), None, status="completed"
            )
        except (OSError, ValueError) as exc:
            raise HTTPException(500, f"could not create demo: {exc}") from exc
        return RedirectResponse(f"/ui/scans/{scan['id']}?onboarding=1", status_code=303)

    @app.post("/ui/projects/{project_id}/scans")
    async def ui_create_scan(request: Request, project_id: str,
                             module: str = Form("all"), profile: str = Form("safe"),
                             threads: int = Form(10),
                             requests_per_minute: int = Form(300),
                             timeout: float = Form(10),
                             recursive: str = Form(""),
                             max_depth: int = Form(2),
                             skip_deps: str = Form(""),
                             csrf: str = Form(...)):
        if not csrf_ok(request, csrf):
            raise HTTPException(403, "invalid CSRF token")
        project = store.project(project_id)
        if not project:
            raise HTTPException(404, "project not found")
        if not 60 <= requests_per_minute <= 6000:
            raise HTTPException(400, "requests per minute must be between 60 and 6000")
        try:
            scan_request = ScanCreate(
                module=module,
                profile=profile,
                threads=threads,
                rate=requests_per_minute / 60,
                timeout=timeout,
                recursive=recursive == "yes",
                max_depth=max_depth,
                skip_deps=skip_deps == "yes",
            )
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        slug = re.sub(r"[^a-zA-Z0-9_.-]", "_", project["name"])[:40] or "project"
        output = output_root / f"ui_{slug}_{int(time.time() * 1000)}"
        pid = launcher.launch(project, scan_request, output)
        scan = store.create_scan(project_id, module, profile, str(output), pid)
        return RedirectResponse(f"/ui/scans/{scan['id']}", status_code=303)

    @app.get("/ui/scans/{scan_id}", response_class=HTMLResponse)
    async def ui_scan(request: Request, scan_id: str):
        scan, path = scan_or_404(scan_id)
        intelligence = _read_json(path / "intelligence" / "cves.json")
        surface = _read_json(path / "surface" / "summary.json")
        surface_full = _read_json(path / "surface" / "surface_mapping.json")
        attack = _read_json(path / "surface" / "attack_surface.json")
        finding_keys = (
            "scored_findings", "infra_findings", "auth_findings",
            "business_findings", "injection_findings", "xss_findings", "ssrf_findings",
        )
        findings, seen_findings = [], set()
        for key in finding_keys:
            for finding in attack.get(key, []):
                marker = json.dumps(finding, sort_keys=True, default=str)
                if marker not in seen_findings:
                    seen_findings.add(marker)
                    findings.append(finding)
        findings.sort(key=lambda item: item.get("cvss_score", 0), reverse=True)
        plan = _read_json(path / "validation" / "plan.json")
        execution = _read_json(path / "validation" / "execution.json")
        demo = _read_json(path / "demo.json")
        settings = _read_json(path / "webui-scan.json")
        response = templates.TemplateResponse(request, "scan.html", {
            "scan": scan, "cves": intelligence.get("cves", []),
            "surface": surface.get("summary", surface), "surface_full": surface_full,
            "findings": findings, "plan": plan,
            "execution": execution, "demo": demo, "settings": settings,
            "report_available": (path / "reports" / "report.html").is_file(),
            "csrf": app.state.csrf_token, "log_tail": read_log_tail(path),
            "progress": scan_progress(scan["module"], read_log_tail(path), scan["status"]),
            "waiting_message": (
                f"Processo PID {scan.get('pid')} ativo; aguardando a primeira saída…"
                if scan["status"] == "running"
                else "O scanner terminou sem produzir saída de console."
            ),
        })
        response.set_cookie("buggy_csrf", app.state.csrf_token, httponly=True,
                            samesite="strict", secure=False)
        return response

    @app.get("/ui/scans/{scan_id}/report")
    async def ui_scan_report(scan_id: str):
        scan, path = scan_or_404(scan_id)
        report = path / "reports" / "report.html"
        if scan["module"] == "demo" or not report.is_file():
            raise HTTPException(404, "report not found")
        if report.stat().st_size > 20 * 1024 * 1024:
            raise HTTPException(413, "report is too large")
        return HTMLResponse(report.read_text(encoding="utf-8"))

    @app.get("/ui/scans/{scan_id}/status", response_class=HTMLResponse)
    async def ui_scan_status(request: Request, scan_id: str):
        previous = store.scan(scan_id)
        if not previous:
            raise HTTPException(404, "scan not found")
        scan, path = scan_or_404(scan_id)
        log_tail = read_log_tail(path)
        response = templates.TemplateResponse(request, "scan_status.html", {
            "scan": scan, "log_tail": log_tail, "csrf": app.state.csrf_token,
            "progress": scan_progress(scan["module"], log_tail, scan["status"]),
            "waiting_message": (
                f"Processo PID {scan.get('pid')} ativo há "
                f"{max(0, int(time.time() - scan['created_at']))}s; aguardando a primeira saída…"
                if scan["status"] == "running"
                else "O scanner terminou sem produzir saída de console."
            ),
        })
        if previous["status"] == "running" and scan["status"] != "running":
            response.headers["HX-Refresh"] = "true"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/ui/scans/{scan_id}/cancel")
    async def ui_cancel_scan(request: Request, scan_id: str, csrf: str = Form(...)):
        if not csrf_ok(request, csrf):
            raise HTTPException(403, "invalid CSRF token")
        scan, path = scan_or_404(scan_id)
        if scan["module"] == "demo":
            raise HTTPException(400, "demo scans are read-only")
        if scan["status"] != "running":
            raise HTTPException(409, "scan is not running")
        if not launcher.cancel(scan.get("pid")):
            raise HTTPException(409, "process is no longer managed by this UI instance")
        store.update_scan_status(scan_id, "cancelled")
        with (path / "webui-process.log").open("a", encoding="utf-8") as stream:
            stream.write("\n[ui] Cancelamento solicitado pelo usuário.\n")
        return RedirectResponse(f"/ui/scans/{scan_id}", status_code=303)

    @app.post("/ui/scans/{scan_id}/approve")
    async def ui_approve(request: Request, scan_id: str,
                         item_id: list[str] = Form(...), approved_by: str = Form(...),
                         csrf: str = Form(...)):
        if not csrf_ok(request, csrf):
            raise HTTPException(403, "invalid CSRF token")
        scan, path = scan_or_404(scan_id)
        if scan["module"] == "demo":
            raise HTTPException(400, "demo scans are read-only")
        approve_plan(str(path), item_id, approved_by, 3600)
        return RedirectResponse(f"/ui/scans/{scan_id}", status_code=303)

    @app.post("/ui/scans/{scan_id}/execute")
    async def ui_execute(request: Request, scan_id: str, csrf: str = Form(...)):
        if not csrf_ok(request, csrf):
            raise HTTPException(403, "invalid CSRF token")
        scan, path = scan_or_404(scan_id)
        if scan["module"] == "demo":
            raise HTTPException(400, "demo scans are read-only")
        try:
            execute_plan(str(path), lab_mode=False)
        except (OSError, ValueError, KeyError) as exc:
            raise HTTPException(400, str(exc)) from exc
        return RedirectResponse(f"/ui/scans/{scan_id}", status_code=303)

    @app.get("/ui/scans/{scan_id}/logs")
    async def ui_logs(scan_id: str):
        _, path = scan_or_404(scan_id)
        log_path = path / "webui-process.log"

        async def events():
            content = ""
            if log_path.is_file():
                with log_path.open("rb") as stream:
                    stream.seek(max(0, log_path.stat().st_size - 65536))
                    content = stream.read().decode("utf-8", errors="replace")
            yield "event: log\ndata: " + json.dumps(content) + "\n\n"
            yield "event: end\ndata: done\n\n"

        return StreamingResponse(events(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-store"})

    @app.get("/ui/scans/{scan_id}/logs/snapshot", response_class=HTMLResponse)
    async def ui_log_snapshot(scan_id: str):
        _, path = scan_or_404(scan_id)
        log_path = path / "webui-process.log"
        content = ""
        if log_path.is_file():
            with log_path.open("rb") as stream:
                stream.seek(max(0, log_path.stat().st_size - 65536))
                content = stream.read().decode("utf-8", errors="replace")
        return HTMLResponse("<pre>" + html.escape(content) + "</pre>")

    return app
