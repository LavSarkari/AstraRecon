"""Plugin Discovery, Loading, and Registry."""

from pathlib import Path
from typing import Optional
import yaml

from astrarecon.core.models.plugin import PluginManifest


class PluginRegistry:
    """In-memory registry of discovered and validated plugins."""

    def __init__(self):
        self._plugins: dict[str, PluginManifest] = {}

    def register(self, manifest: PluginManifest) -> None:
        self._plugins[manifest.id] = manifest

    def get(self, plugin_id: str) -> Optional[PluginManifest]:
        return self._plugins.get(plugin_id)

    def list_all(self) -> list[PluginManifest]:
        return list(self._plugins.values())

    def __contains__(self, plugin_id: str) -> bool:
        return plugin_id in self._plugins


class PluginLoader:
    """Discovers and parses plugin.yaml manifests from standard directories."""

    @classmethod
    def get_user_plugin_dir(cls) -> Path:
        return Path.home() / ".astrarecon" / "plugins"

    @classmethod
    def get_builtin_plugin_dir(cls) -> Path:
        return Path(__file__).parent.parent.parent / "default_plugins"

    @classmethod
    def load_manifest_from_file(cls, path: Path) -> PluginManifest:
        """Parses and validates a plugin.yaml file."""
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return PluginManifest.model_validate(data)

    @classmethod
    def load_all_plugins(cls) -> PluginRegistry:
        """Scans built-in and user plugin directories, returning a populated registry."""
        registry = PluginRegistry()

        # Load built-in default plugins first
        builtin_dir = cls.get_builtin_plugin_dir()
        if builtin_dir.exists():
            for manifest_file in builtin_dir.glob("*/plugin.yaml"):
                try:
                    manifest = cls.load_manifest_from_file(manifest_file)
                    registry.register(manifest)
                except Exception:
                    continue

        # Load user plugins from ~/.astrarecon/plugins/ (user plugins override builtins)
        user_dir = cls.get_user_plugin_dir()
        if user_dir.exists():
            for manifest_file in user_dir.glob("*/plugin.yaml"):
                try:
                    manifest = cls.load_manifest_from_file(manifest_file)
                    registry.register(manifest)
                except Exception:
                    continue

        return registry
