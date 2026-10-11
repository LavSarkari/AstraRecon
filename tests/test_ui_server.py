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
