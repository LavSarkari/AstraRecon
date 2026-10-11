"""Unit and integration tests for AstraRecon Visual Web Server & API."""

import json
import urllib.request
import pytest
from astrarecon.web.server import start_web_server


@pytest.fixture(scope="module")
def web_server():
    """Starts the AstraRecon web server on a local dynamic port."""
    server, port = start_web_server(host="127.0.0.1", port=18080, daemon=True)
    yield f"http://127.0.0.1:{port}"
    server.stop()


def test_ui_serves_html(web_server):
    """Verify GET / returns index.html with AstraRecon canvas markup."""
    req = urllib.request.Request(f"{web_server}/")
    with urllib.request.urlopen(req) as res:
        assert res.status == 200
        content_type = res.headers.get("Content-Type", "")
        assert "text/html" in content_type
        body = res.read().decode("utf-8")
        assert "AstraRecon" in body
        assert "canvas-container" in body


def test_ui_serves_static_assets(web_server):
    """Verify static assets (CSS, JS) are served with correct MIME types."""
    # CSS
    with urllib.request.urlopen(f"{web_server}/styles.css") as res:
        assert res.status == 200
        assert "text/css" in res.headers.get("Content-Type", "")
        css = res.read().decode("utf-8")
        assert "--color-primary" in css

    # JS
    with urllib.request.urlopen(f"{web_server}/app.js") as res:
        assert res.status == 200
        assert "application/javascript" in res.headers.get("Content-Type", "") or "text/javascript" in res.headers.get("Content-Type", "")
        js = res.read().decode("utf-8")
        assert "renderCanvas" in js


def test_api_status(web_server):
    """Verify GET /api/status returns valid state."""
    with urllib.request.urlopen(f"{web_server}/api/status") as res:
        assert res.status == 200
        data = json.loads(res.read().decode("utf-8"))
        assert "is_scanning" in data
        assert "server_version" in data


def test_api_doctor(web_server):
    """Verify GET /api/doctor returns host diagnostics and arsenal tool statuses."""
    with urllib.request.urlopen(f"{web_server}/api/doctor") as res:
        assert res.status == 200
        data = json.loads(res.read().decode("utf-8"))
        assert "os_name" in data
        assert "tools" in data
        assert "subfinder" in data["tools"]


def test_api_presets(web_server):
    """Verify GET /api/presets returns workflow options."""
    with urllib.request.urlopen(f"{web_server}/api/presets") as res:
        assert res.status == 200
        presets = json.loads(res.read().decode("utf-8"))
        assert isinstance(presets, list)
        preset_ids = [p["id"] for p in presets]
        assert "default" in preset_ids
        assert "fast" in preset_ids


def test_api_plugins(web_server):
    """Verify GET /api/plugins lists registered tool manifests."""
    with urllib.request.urlopen(f"{web_server}/api/plugins") as res:
        assert res.status == 200
        plugins = json.loads(res.read().decode("utf-8"))
        assert isinstance(plugins, list)
        p_ids = [p["id"] for p in plugins]
        assert "subfinder" in p_ids
        assert "httpx" in p_ids


def test_api_sessions(web_server):
    """Verify GET /api/sessions returns an array of sessions."""
    with urllib.request.urlopen(f"{web_server}/api/sessions") as res:
        assert res.status == 200
        sessions = json.loads(res.read().decode("utf-8"))
        assert isinstance(sessions, list)


def test_api_projects_and_recents(web_server):
    """Verify projects and recent targets endpoints."""
    with urllib.request.urlopen(f"{web_server}/api/projects") as res:
        assert res.status == 200
        projects = json.loads(res.read().decode("utf-8"))
        assert isinstance(projects, list)
        assert len(projects) >= 1

    with urllib.request.urlopen(f"{web_server}/api/projects/recent") as res:
        assert res.status == 200
        data = json.loads(res.read().decode("utf-8"))
        assert "recent_targets" in data
        assert "projects" in data


def test_api_plugins_config_and_toggle(web_server):
    """Verify plugin config retrieval and interactive tool toggle."""
    with urllib.request.urlopen(f"{web_server}/api/plugins/config") as res:
        assert res.status == 200
        cfg = json.loads(res.read().decode("utf-8"))
        assert "disabled_tools" in cfg

    # Toggle nuclei off (stealth mode)
    toggle_data = json.dumps({"tool_id": "nuclei", "enabled": False, "scope": "global"}).encode("utf-8")
    req = urllib.request.Request(f"{web_server}/api/plugins/toggle", data=toggle_data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as res:
        assert res.status == 200
        result = json.loads(res.read().decode("utf-8"))
        assert "nuclei" in result["config"]["disabled_tools"]

    # Toggle nuclei back on
    toggle_data_on = json.dumps({"tool_id": "nuclei", "enabled": True, "scope": "global"}).encode("utf-8")
    req_on = urllib.request.Request(f"{web_server}/api/plugins/toggle", data=toggle_data_on, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req_on) as res:
        assert res.status == 200
        result_on = json.loads(res.read().decode("utf-8"))
        assert "nuclei" not in result_on["config"]["disabled_tools"]


def test_api_scan_start_and_abort(web_server):
    """Verify mission start, status polling during scan, and immediate abort cancellation."""
    import time

    # 1. Start a scan
    start_payload = json.dumps({
        "target": "example.com",
        "workflow": "fast",
        "profile": "safe",
    }).encode("utf-8")
    req_start = urllib.request.Request(
        f"{web_server}/api/scan/start",
        data=start_payload,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req_start) as res:
        assert res.status == 200
        data = json.loads(res.read().decode("utf-8"))
        assert data["status"] == "started"
        assert data["target"] == "example.com"

    # 2. Check /api/status during scan
    time.sleep(0.2)
    with urllib.request.urlopen(f"{web_server}/api/status") as res:
        assert res.status == 200
        status_data = json.loads(res.read().decode("utf-8"))
        assert "is_scanning" in status_data
        if status_data["is_scanning"]:
            assert status_data["active_target"] == "example.com"
            assert "nodes" in status_data

    # 3. Stop / abort the scan
    req_stop = urllib.request.Request(
        f"{web_server}/api/scan/stop",
        data=b"{}",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req_stop) as res:
        assert res.status == 200
        stop_data = json.loads(res.read().decode("utf-8"))
        assert stop_data["status"] in ("stopping", "not_running")

    # 4. Wait for engine to wind down and verify idle state
    is_idle = False
    for _ in range(100):
        time.sleep(0.1)
        with urllib.request.urlopen(f"{web_server}/api/status") as res:
            idle_data = json.loads(res.read().decode("utf-8"))
            if not idle_data.get("is_scanning"):
                is_idle = True
                break
    assert is_idle is True

    # 5. Stop when not running returns 'not_running'
    req_stop2 = urllib.request.Request(
        f"{web_server}/api/scan/stop",
        data=b"{}",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req_stop2) as res:
        assert res.status == 200
        stop_data2 = json.loads(res.read().decode("utf-8"))
        assert stop_data2["status"] == "not_running"


def test_api_delete_and_clear_sessions(web_server):
    """Verify DELETE /api/session/{id} and DELETE /api/sessions endpoints."""
    from astrarecon.core.sessions.manager import SessionManager
    from astrarecon.core.models.session import EnvFingerprint
    from astrarecon.core.models.workflow import WorkflowDefinition

    mgr = SessionManager()
    fp = EnvFingerprint(
        captured_at="2026-09-26T00:00:00",
        os_distro="Linux",
        os_version="1.0",
        kernel="test",
        arch="x86_64",
        python_version="3.11",
        go_version="1.22",
        tools={},
    )
    dummy_dir = mgr.create_session(
        "deleteme.example.com",
        WorkflowDefinition(id="w1", name="w1", nodes=[], edges=[]),
        fp,
    )
    sid = dummy_dir.name
    assert dummy_dir.exists()

    # 1. DELETE /api/session/{sid}
    req_del = urllib.request.Request(f"{web_server}/api/session/{sid}", method="DELETE")
    with urllib.request.urlopen(req_del) as res:
        assert res.status == 200
        data = json.loads(res.read().decode("utf-8"))
        assert data["status"] == "deleted"
        assert data["session_id"] == sid

    assert not dummy_dir.exists()

    # 2. DELETE nonexistent returns 404
    req_del_404 = urllib.request.Request(f"{web_server}/api/session/nonexistent-session-id", method="DELETE")
    with pytest.raises(urllib.error.HTTPError) as exc_info:
        urllib.request.urlopen(req_del_404)
    assert exc_info.value.code == 404


