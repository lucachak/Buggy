import json
from pathlib import Path

import httpx
import pytest

from modules.Validation.planner import save_registry_and_plan
from modules.WebUI.api import ScanCreate, ScanLauncher, create_app
from modules.WebUI.progress import scan_progress


@pytest.fixture
def anyio_backend():
    return "asyncio"


def web_client(tmp_path):
    app = create_app(tmp_path)
    return app, httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    )


@pytest.mark.anyio
async def test_health_and_empty_projects(tmp_path):
    _, web = web_client(tmp_path)
    async with web:
        assert (await web.get("/api/health")).json() == {
            "status": "ok", "bind_policy": "localhost-only"
        }
        assert (await web.get("/api/projects")).json() == []


@pytest.mark.anyio
async def test_project_requires_explicit_authorization(tmp_path):
    _, web = web_client(tmp_path)
    async with web:
        payload = {"name": "Lab", "target": "localhost:8000", "authorized": False}
        assert (await web.post("/api/projects", json=payload)).status_code == 400
        payload["authorized"] = True
        response = await web.post("/api/projects", json=payload)
        assert response.status_code == 201
        assert response.json()["target"] == "http://localhost:8000"


@pytest.mark.anyio
async def test_project_rejects_credentials_and_non_http_targets(tmp_path):
    _, web = web_client(tmp_path)
    async with web:
        for target in ("ftp://example.com", "https://user:pass@example.com"):
            response = await web.post("/api/projects", json={
                "name": "Bad", "target": target, "authorized": True,
            })
            assert response.status_code == 422


@pytest.mark.anyio
async def test_scan_launch_uses_bounded_request_and_is_persisted(tmp_path):
    app, web = web_client(tmp_path)
    async with web:
        project = (await web.post("/api/projects", json={
            "name": "Local Lab", "target": "http://localhost:8000", "authorized": True,
        })).json()

        def fake_launch(project_data, request, output):
            output.mkdir(parents=True)
            return 4242

        app.state.launcher.launch = fake_launch
        response = await web.post(f"/api/projects/{project['id']}/scans", json={
            "module": "cve", "profile": "safe", "threads": 4, "rate": 3,
        })
        assert response.status_code == 202
        scan = response.json()
        assert scan["pid"] == 4242
        assert Path(scan["output_dir"]).is_dir()
        scans = (await web.get(f"/api/projects/{project['id']}/scans")).json()
        assert scans[0]["id"] == scan["id"]


@pytest.mark.anyio
async def test_scan_constraints_reject_unbounded_values(tmp_path):
    _, web = web_client(tmp_path)
    async with web:
        response = await web.post("/api/projects/missing/scans", json={
            "module": "all", "threads": 5000, "rate": 10000,
        })
        assert response.status_code == 422


@pytest.mark.anyio
async def test_dashboard_uses_local_polling_with_security_headers(tmp_path):
    _, web = web_client(tmp_path)
    async with web:
        response = await web.get("/")
        assert response.status_code == 200
        assert '<script src="/static/app.js" defer>' in response.text
        assert "cdn.jsdelivr.net" not in response.text
        assert 'data-poll-url="/ui/scans/recent"' in response.text
        assert 'data-poll-interval="3000"' in response.text
        assert response.headers["x-frame-options"] == "DENY"
        assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
        assert "cdn.jsdelivr.net" not in response.headers["content-security-policy"]


@pytest.mark.anyio
async def test_ui_exposes_and_validates_scan_tuning_controls(tmp_path):
    app, web = web_client(tmp_path)
    async with web:
        project = (await web.post("/api/projects", json={
            "name": "Tuned", "target": "localhost:3000", "authorized": True,
        })).json()
        dashboard = await web.get("/")
        assert 'name="requests_per_minute"' in dashboard.text
        assert 'name="threads"' in dashboard.text
        assert 'name="recursive"' in dashboard.text
        assert 'name="max_depth"' in dashboard.text

        observed = {}

        def fake_launch(project_data, scan_request, output):
            observed["request"] = scan_request
            output.mkdir(parents=True)
            return 5150

        app.state.launcher.launch = fake_launch
        response = await web.post(f"/ui/projects/{project['id']}/scans", data={
            "csrf": app.state.csrf_token,
            "module": "recon",
            "profile": "safe",
            "threads": "20",
            "requests_per_minute": "3000",
            "timeout": "5",
            "recursive": "yes",
            "max_depth": "3",
            "skip_deps": "yes",
        }, follow_redirects=False)
        assert response.status_code == 303
        scan_request = observed["request"]
        assert scan_request.threads == 20
        assert scan_request.rate == 50
        assert scan_request.recursive is True
        assert scan_request.max_depth == 3
        assert scan_request.skip_deps is True

        rejected = await web.post(f"/ui/projects/{project['id']}/scans", data={
            "csrf": app.state.csrf_token,
            "requests_per_minute": "12000",
        })
        assert rejected.status_code == 400


@pytest.mark.anyio
async def test_ui_mutations_require_csrf_cookie_and_token(tmp_path):
    app, web = web_client(tmp_path)
    async with web:
        denied = await web.post("/ui/projects", data={
            "name": "Lab", "target": "localhost", "authorized": "yes", "csrf": "bad",
        })
        assert denied.status_code == 403
        await web.get("/")
        accepted = await web.post("/ui/projects", data={
            "name": "Lab", "target": "localhost", "authorized": "yes",
            "csrf": app.state.csrf_token,
        }, follow_redirects=False)
        assert accepted.status_code == 303


@pytest.mark.anyio
async def test_log_snapshot_escapes_untrusted_output(tmp_path):
    app, web = web_client(tmp_path)
    async with web:
        project = (await web.post("/api/projects", json={
            "name": "Lab", "target": "localhost", "authorized": True,
        })).json()

        def fake_launch(project_data, request, output):
            output.mkdir(parents=True)
            (output / "webui-process.log").write_text("<script>alert(1)</script>")
            return 42

        app.state.launcher.launch = fake_launch
        scan = (await web.post(f"/api/projects/{project['id']}/scans", json={
            "module": "cve", "profile": "safe",
        })).json()
        response = await web.get(f"/ui/scans/{scan['id']}/logs/snapshot")
        assert "<script>" not in response.text
        assert "&lt;script&gt;" in response.text


@pytest.mark.anyio
async def test_ui_executes_safe_plan_with_csrf_and_renders_result(tmp_path):
    app, web = web_client(tmp_path)
    async with web:
        project = (await web.post("/api/projects", json={
            "name": "Lab", "target": "http://localhost:9", "authorized": True,
        })).json()

        def fake_launch(project_data, request, output):
            output.mkdir(parents=True)
            intelligence = output / "intelligence"
            intelligence.mkdir()
            (intelligence / "cves.json").write_text(
                '{"cves":[{"cve_id":"CVE-2021-41773","priority":"HIGH"}]}'
            )
            save_registry_and_plan(str(output), project_data["target"])
            return 42

        app.state.launcher.launch = fake_launch
        scan = (await web.post(f"/api/projects/{project['id']}/scans", json={
            "module": "plan", "profile": "safe",
        })).json()
        await web.get("/")
        denied = await web.post(f"/ui/scans/{scan['id']}/execute", data={"csrf": "bad"})
        assert denied.status_code == 403
        accepted = await web.post(f"/ui/scans/{scan['id']}/execute", data={
            "csrf": app.state.csrf_token,
        }, follow_redirects=False)
        assert accepted.status_code == 303
        detail = await web.get(f"/ui/scans/{scan['id']}")
        assert "CVE-2021-41773" in detail.text
        assert "inconclusive" in detail.text


@pytest.mark.anyio
async def test_onboarding_demo_is_offline_complete_and_read_only(tmp_path):
    app, web = web_client(tmp_path)
    async with web:
        dashboard = await web.get("/")
        assert "Conheça o Buggy em dois minutos" in dashboard.text
        assert 'action="/ui/demo"' in dashboard.text

        def must_not_launch(*args, **kwargs):
            raise AssertionError("the onboarding demo must not start a scanner")

        app.state.launcher.launch = must_not_launch
        denied = await web.post("/ui/demo", data={"csrf": "bad"})
        assert denied.status_code == 403
        created = await web.post("/ui/demo", data={
            "csrf": app.state.csrf_token,
        }, follow_redirects=False)
        assert created.status_code == 303
        assert created.headers["location"].endswith("?onboarding=1")

        scan = app.state.store.scans()[0]
        assert scan["module"] == "demo"
        assert scan["status"] == "completed"
        assert scan["pid"] is None
        output = Path(scan["output_dir"])
        assert (output / "demo.json").is_file()
        assert (output / "surface" / "summary.json").is_file()
        assert (output / "intelligence" / "cves.json").is_file()
        assert (output / "validation" / "plan.json").is_file()
        assert (output / "validation" / "execution.json").is_file()

        page = await web.get(created.headers["location"])
        assert "Primeiro scan guiado" in page.text
        assert "ETAPA 1 · DESCOBERTA" in page.text
        assert "ETAPA 4 · EVIDÊNCIA" in page.text
        assert "CVE-2021-41773" in page.text
        assert "CVE-2017-12615" in page.text
        assert f'/ui/scans/{scan["id"]}/execute' not in page.text

        api_write = await web.post(f'/api/scans/{scan["id"]}/execute', json={
            "confirmed": True,
        })
        assert api_write.status_code == 400
        assert api_write.json()["detail"] == "demo scans are read-only"


@pytest.mark.anyio
async def test_each_demo_has_an_isolated_output_directory(tmp_path):
    app, web = web_client(tmp_path)
    async with web:
        await web.get("/")
        for _ in range(2):
            response = await web.post("/ui/demo", data={"csrf": app.state.csrf_token})
            assert response.status_code == 303
        scans = app.state.store.scans()
        assert len(scans) == 2
        assert scans[0]["output_dir"] != scans[1]["output_dir"]


def test_launcher_uses_unbuffered_python_and_tracks_exit_status(tmp_path, monkeypatch):
    observed = {}

    class Process:
        pid = 1234
        return_code = None

        def poll(self):
            return self.return_code

    process = Process()

    def fake_popen(command, **kwargs):
        observed["command"] = command
        return process

    monkeypatch.setattr("modules.WebUI.api.subprocess.Popen", fake_popen)
    launcher = ScanLauncher(tmp_path)
    pid = launcher.launch(
        {"target": "http://localhost:3000"}, ScanCreate(module="surface"),
        tmp_path / "output" / "scan",
    )
    assert pid == 1234
    assert observed["command"][1] == "-u"
    assert launcher.state(pid) == "running"
    process.return_code = 0
    assert launcher.state(pid) == "completed"
    process.return_code = 2
    assert launcher.state(pid) == "failed"


def test_launcher_passes_recursive_performance_controls(tmp_path, monkeypatch):
    observed = {}

    class Process:
        pid = 4321
        def poll(self): return None

    def fake_popen(command, **kwargs):
        observed["command"] = command
        return Process()

    monkeypatch.setattr("modules.WebUI.api.subprocess.Popen", fake_popen)
    launcher = ScanLauncher(tmp_path)
    launcher.launch(
        {"target": "http://localhost:3000"},
        ScanCreate(
            module="recon", threads=24, rate=50, timeout=4,
            recursive=True, max_depth=3, skip_deps=True,
        ),
        tmp_path / "output" / "recursive",
    )
    command = observed["command"]
    assert command[command.index("--threads") + 1] == "24"
    assert command[command.index("--rate") + 1] == "50.0"
    assert command[command.index("--timeout") + 1] == "4.0"
    assert command[command.index("--max-depth") + 1] == "3"
    assert "--recursive" in command
    assert "--skip-deps" in command
    settings = __import__("json").loads(
        (tmp_path / "output" / "recursive" / "webui-scan.json").read_text()
    )
    assert settings["requests_per_minute"] == 3000
    assert settings["max_depth"] == 3


def test_launcher_cancels_only_a_managed_running_process(tmp_path, monkeypatch):
    launcher = ScanLauncher(tmp_path)

    class Process:
        pid = 321
        def poll(self): return None

    launcher._processes[321] = Process()
    killed = []
    monkeypatch.setattr("modules.WebUI.api.os.killpg", lambda pid, sig: killed.append((pid, sig)))
    assert launcher.cancel(321) is True
    assert killed[0][0] == 321
    assert launcher.cancel(999) is False


def test_progress_marks_previous_steps_and_terminal_state():
    running = scan_progress("surface", "[1/6] tech\n[2/6] endpoints", "running")
    assert running["steps"][0]["state"] == "completed"
    assert running["steps"][1]["state"] == "running"
    assert running["steps"][2]["state"] == "pending"
    cancelled = scan_progress("surface", "[1/6] tech\n[2/6] endpoints", "cancelled")
    assert cancelled["steps"][1]["state"] == "cancelled"


@pytest.mark.anyio
async def test_live_status_polls_escapes_logs_and_persists_completion(tmp_path):
    app, web = web_client(tmp_path)
    async with web:
        project = (await web.post("/api/projects", json={
            "name": "Live", "target": "localhost:3000", "authorized": True,
        })).json()

        def fake_launch(project_data, request, output):
            output.mkdir(parents=True)
            (output / "webui-process.log").write_text("<script>phase 1</script>")
            return 777

        app.state.launcher.launch = fake_launch
        app.state.launcher.state = lambda pid: "running"
        scan = (await web.post(f"/api/projects/{project['id']}/scans", json={
            "module": "surface", "profile": "safe",
        })).json()

        live = await web.get(f"/ui/scans/{scan['id']}/status")
        assert live.status_code == 200
        assert 'data-poll-interval="2000"' in live.text
        assert "<script>" not in live.text
        assert "&lt;script&gt;phase 1&lt;/script&gt;" in live.text

        app.state.launcher.state = lambda pid: "completed"
        finished = await web.get(f"/ui/scans/{scan['id']}/status")
        assert finished.headers["hx-refresh"] == "true"
        assert 'data-poll-url=' not in finished.text
        assert app.state.store.scan(scan["id"])["status"] == "completed"


@pytest.mark.anyio
async def test_ui_cancel_requires_csrf_updates_status_and_stops_polling(tmp_path):
    app, web = web_client(tmp_path)
    async with web:
        project = (await web.post("/api/projects", json={
            "name": "Cancel", "target": "localhost:3000", "authorized": True,
        })).json()

        def fake_launch(project_data, request, output):
            output.mkdir(parents=True)
            (output / "webui-process.log").write_text("[1/6] tech\n[2/6] endpoints\n")
            return 888

        app.state.launcher.launch = fake_launch
        app.state.launcher.state = lambda pid: "running"
        app.state.launcher.cancel = lambda pid: pid == 888
        scan = (await web.post(f"/api/projects/{project['id']}/scans", json={
            "module": "surface", "profile": "safe",
        })).json()
        await web.get("/")

        page = await web.get(f"/ui/scans/{scan['id']}")
        assert "Cancelar execução" in page.text
        assert "Tecnologias" in page.text
        assert "Endpoints" in page.text
        denied = await web.post(f"/ui/scans/{scan['id']}/cancel", data={"csrf": "bad"})
        assert denied.status_code == 403
        cancelled = await web.post(f"/ui/scans/{scan['id']}/cancel", data={
            "csrf": app.state.csrf_token,
        }, follow_redirects=False)
        assert cancelled.status_code == 303
        assert app.state.store.scan(scan["id"])["status"] == "cancelled"
        fragment = await web.get(f"/ui/scans/{scan['id']}/status")
        assert "Cancelar execução" not in fragment.text
        assert 'class="cancelled"' in fragment.text
        assert 'data-poll-url=' not in fragment.text


@pytest.mark.anyio
async def test_ui_shows_pipeline_coverage_findings_and_html_report(tmp_path):
    app, web = web_client(tmp_path)
    async with web:
        project = (await web.post("/api/projects", json={
            "name": "SPA Lab", "target": "localhost:3000", "authorized": True,
        })).json()

        def fake_launch(project_data, request, output):
            (output / "surface").mkdir(parents=True)
            (output / "reports").mkdir()
            (output / "surface" / "summary.json").write_text(json.dumps({
                "attack_surface": {"total_endpoints": 45, "total_apis": 44,
                                   "total_forms": 0, "js_secrets_found": 0},
            }))
            (output / "surface" / "surface_mapping.json").write_text(json.dumps({
                "js_secrets": {"summary": {"total_files": 15}},
            }))
            (output / "surface" / "attack_surface.json").write_text(json.dumps({
                "injection_findings": [{"type": "sqli", "subtype": "authentication_bypass",
                    "url": "http://localhost:3000/rest/user/login", "cvss_score": 9.8,
                    "cvss_severity": "CRITICAL", "evidence": "token returned"}],
            }))
            (output / "reports" / "report.html").write_text("<h1>Buggy report</h1>")
            return 9090

        app.state.launcher.launch = fake_launch
        app.state.launcher.state = lambda pid: "completed"
        scan = (await web.post(f"/api/projects/{project['id']}/scans", json={
            "module": "all", "profile": "standard",
        })).json()
        page = await web.get(f"/ui/scans/{scan['id']}")
        assert "44" in page.text and "APIs" in page.text
        assert "15" in page.text and "bundles JS" in page.text
        assert "authentication_bypass" in page.text
        assert "CRITICAL" in page.text
        assert f'/ui/scans/{scan["id"]}/report' in page.text
        report = await web.get(f"/ui/scans/{scan['id']}/report")
        assert report.status_code == 200
        assert "Buggy report" in report.text
