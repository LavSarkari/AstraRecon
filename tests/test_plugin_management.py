"""Unit tests for plugin management CLI and scan-time tool selection flags."""

import pytest
from pathlib import Path
from typer.testing import CliRunner

from astrarecon.cli.plugins import app as plugins_app
from astrarecon.cli.scan import build_workflow
from astrarecon.core.models.plugin import PluginManifest
from astrarecon.core.plugins.loader import PluginLoader


runner = CliRunner()


def test_build_workflow_skip_tools():
    """Verify --skip removes designated tools from DAG."""
    wf = build_workflow(
        target="example.com",
        preset="default",
        skip_tools=["amass", "subenum"],
    )
    node_ids = {n.id for n in wf.nodes}
    assert "amass" not in node_ids
    assert "subenum" not in node_ids
    assert "subfinder" in node_ids
    assert "httpx" in node_ids


def test_build_workflow_custom_tools_exact():
    """Verify --tools runs only the specified tools connected properly."""
    wf = build_workflow(
        target="example.com",
        preset="default",
        custom_tools=["subfinder", "dnsx", "httpx"],
    )
    node_ids = {n.id for n in wf.nodes}
    # Built-in pipeline nodes must be present
    assert "target_input" in node_ids
    assert "scope_guard" in node_ids
    # Requested tools present
    assert "subfinder" in node_ids
    assert "dnsx" in node_ids
    assert "httpx" in node_ids
    # Unrequested tools absent
    assert "assetfinder" not in node_ids
    assert "amass" not in node_ids
    assert "naabu" not in node_ids
    assert "katana" not in node_ids
    assert "nuclei" not in node_ids


def test_build_workflow_with_tools():
    """Verify --with connects additional tools dynamically based on stage."""
    # When an unknown tool is specified, it gracefully handles it
    wf = build_workflow(
        target="example.com",
        preset="default",
        with_tools=["subfinder"],  # already in default, shouldn't duplicate
    )
    node_ids = [n.id for n in wf.nodes]
    assert node_ids.count("subfinder") == 1


def test_plugins_add_and_remove_lifecycle(tmp_path, monkeypatch):
    """Test full lifecycle of adding a custom tool via CLI and removing it."""
    # Mock user plugin directory to tmp_path
    monkeypatch.setattr(PluginLoader, "get_user_plugin_dir", staticmethod(lambda: tmp_path))

    # 1. Add custom tool
    result = runner.invoke(
        plugins_app,
        [
            "add",
            "findomain",
            "--stage",
            "subdomains",
            "--cmd",
            "findomain -t {target} -u {output}",
            "--desc",
            "Fastest subdomain enumerator",
        ],
    )
    assert result.exit_code == 0
    assert "successfully registered" in result.stdout.lower()
    assert "findomain" in result.stdout.lower()

    # Verify YAML was created
    plugin_yaml = tmp_path / "findomain" / "plugin.yaml"
    assert plugin_yaml.exists()

    # Verify manifest loads correctly
    import yaml
    with open(plugin_yaml, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    manifest = PluginManifest(**data)
    assert manifest.id == "findomain"
    assert manifest.description == "Fastest subdomain enumerator"
    assert len(manifest.inputs) == 1
    assert manifest.inputs[0].name == "target"
    assert len(manifest.outputs) == 1
    assert manifest.outputs[0].name == "subdomains"

    # 2. Show plugin
    show_res = runner.invoke(plugins_app, ["show", "findomain"])
    assert show_res.exit_code == 0
    assert "findomain" in show_res.stdout.lower()

    rm_res = runner.invoke(plugins_app, ["remove", "findomain", "--force"])
    assert rm_res.exit_code == 0
    assert "successfully removed" in rm_res.stdout.lower()
    assert "findomain" in rm_res.stdout.lower()
    assert not plugin_yaml.exists()


def test_plugins_remove_builtin_protected():
    """Verify built-in plugins cannot be removed via CLI."""
    result = runner.invoke(plugins_app, ["remove", "subfinder", "--force"])
    assert "built-in" in result.stdout.lower()
