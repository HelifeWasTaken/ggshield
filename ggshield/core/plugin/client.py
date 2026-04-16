"""
Plugin API client - fetches available plugins from GitGuardian API.
"""

import logging
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple

import requests
from pygitguardian import GGClient

from ggshield.core.plugin.platform import PlatformInfo, get_platform_info


logger = logging.getLogger(__name__)


class PluginSourceType(Enum):
    """Types of plugin sources."""

    PLATFORM = "platform"  # GG platform API (old manifests may have "gitguardian_api")
    LOCAL_FILE = "local_file"
    URL = "url"
    GITHUB_RELEASE = "github_release"
    GITHUB_ARTIFACT = "github_artifact"

    @classmethod
    def _missing_(cls, value: object) -> Optional["PluginSourceType"]:
        """Accept legacy manifest value written by the PoC (< v1.50)."""
        if value == "gitguardian_api":
            return cls.PLATFORM
        return None


@dataclass
class PluginSource:
    """Information about where a plugin was installed from."""

    type: PluginSourceType
    url: Optional[str] = None
    github_repo: Optional[str] = None
    sha256: Optional[str] = None
    local_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        result: Dict[str, Any] = {"type": self.type.value}
        if self.url:
            result["url"] = self.url
        if self.github_repo:
            result["github_repo"] = self.github_repo
        if self.sha256:
            result["sha256"] = self.sha256
        if self.local_path:
            result["local_path"] = self.local_path
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PluginSource":
        """Create from dictionary."""
        return cls(
            type=PluginSourceType(data["type"]),
            url=data.get("url"),
            github_repo=data.get("github_repo"),
            sha256=data.get("sha256"),
            local_path=data.get("local_path"),
        )


@dataclass
class PluginInfo:
    """Information about an available plugin."""

    name: str
    display_name: str
    description: str
    available: bool
    latest_version: Optional[str]
    supported_platforms: List[str] = field(default_factory=list)
    reason: Optional[str] = None

    def is_platform_supported(self, platform: str, arch: str) -> bool:
        """Check if this plugin supports the given platform/arch."""
        if not self.supported_platforms:
            return True
        return (
            f"{platform}-{arch}" in self.supported_platforms
            or "any-any" in self.supported_platforms
        )


@dataclass
class PluginCatalog:
    """Catalog of available plugins for the account."""

    plugins: List[PluginInfo]


@dataclass
class PluginDownloadInfo:
    """Metadata about a plugin wheel received from the platform download endpoint."""

    filename: str    # from Content-Disposition header
    sha256: str      # from X-Plugin-SHA256 header
    version: str     # from X-Plugin-Version header
    size_bytes: int  # from Content-Length header


class PluginAPIError(Exception):
    """Error communicating with the plugin API."""

    pass


class PluginNotAvailableError(Exception):
    """Plugin is not available for this account."""

    def __init__(self, plugin_name: str, reason: Optional[str] = None):
        self.plugin_name = plugin_name
        self.reason = reason
        message = f"Plugin '{plugin_name}' is not available"
        if reason:
            message += f": {reason}"
        super().__init__(message)


class PluginsNotEnabledError(Exception):
    """Plugin system is not enabled on this workspace (feature-flag OFF)."""

    pass


class PluginAPIClient:
    """Client for GitGuardian plugin API."""

    API_VERSION = "v1"

    def __init__(self, client: GGClient):
        self.client = client
        self.base_url = client.base_uri.rstrip("/")

    def get_available_plugins(self) -> PluginCatalog:
        """Fetch available plugins for the authenticated account."""
        platform_info = get_platform_info()

        try:
            response = self.client.session.get(
                f"{self.base_url}/{self.API_VERSION}/endpoints/plugins",
                params={
                    "platform": platform_info.os,
                    "arch": platform_info.arch,
                },
                headers=self._get_headers(),
            )
            if response.status_code == 404:
                raise PluginsNotEnabledError()
            response.raise_for_status()
        except PluginsNotEnabledError:
            raise
        except requests.RequestException as e:
            raise PluginAPIError(f"Failed to fetch plugins: {e}") from e

        plugins_data = response.json()  # list, not a dict

        return PluginCatalog(
            plugins=[
                PluginInfo(
                    name=p["reference"],
                    display_name=p.get("display_name", p["reference"]),
                    description=p.get("description", ""),
                    available=p.get("available", False),
                    latest_version=(
                        p["releases"][0]["version"] if p.get("releases") else None
                    ),
                    supported_platforms=[],
                    reason=p.get("reason"),
                )
                for p in plugins_data
            ],
        )

    @contextmanager
    def download_plugin(
        self,
        reference: str,
        platform_info: Optional[PlatformInfo] = None,
        version: Optional[str] = None,
    ) -> Generator[Tuple[PluginDownloadInfo, Iterator[bytes]], None, None]:
        """Stream a plugin wheel from the platform.

        Usage::

            with client.download_plugin("tokenscanner") as (info, chunks):
                downloader.download_and_install(info, chunks, "tokenscanner")
        """
        resolved = platform_info if platform_info is not None else get_platform_info()
        params: Dict[str, str] = {
            "platform": resolved.os,
            "arch": resolved.arch,
            "python_abi": resolved.python_abi,
        }
        if version:
            params["version"] = version

        response = None
        try:
            response = self.client.session.get(
                f"{self.base_url}/{self.API_VERSION}/endpoints/plugins/{reference}/download",
                params=params,
                headers=self._get_headers(),
                stream=True,
            )
            if response.status_code == 403:
                raise PluginNotAvailableError(reference)
            if response.status_code == 404:
                raise PluginNotAvailableError(reference, "Plugin or version not found")
            response.raise_for_status()

            content_disposition = response.headers.get("Content-Disposition", "")
            match = re.search(r'filename="([^"]+)"', content_disposition)
            filename = match.group(1) if match else f"{reference}.whl"

            sha256 = response.headers.get("X-Plugin-SHA256")
            if not sha256:
                raise PluginAPIError(
                    f"Server response missing X-Plugin-SHA256 header for {reference}"
                )
            resolved_version = response.headers.get("X-Plugin-Version")
            if not resolved_version:
                raise PluginAPIError(
                    f"Server response missing X-Plugin-Version header for {reference}"
                )

            info = PluginDownloadInfo(
                filename=filename,
                sha256=sha256,
                version=resolved_version,
                size_bytes=int(response.headers.get("Content-Length", 0)),
            )
            yield info, response.iter_content(chunk_size=8192)
        except (PluginNotAvailableError, PluginAPIError):
            raise
        except requests.RequestException as e:
            raise PluginAPIError(f"Failed to download plugin: {e}") from e
        finally:
            if response is not None:
                response.close()

    def report_installation(
        self, reference: str, version: str, platform: str, arch: str
    ) -> None:
        """Report a successful plugin installation for analytics (best-effort).

        Never raises — a failure here must not fail the install.
        """
        try:
            response = self.client.session.post(
                f"{self.base_url}/{self.API_VERSION}/endpoints/plugins/{reference}/installed",
                json={"version": version, "platform": platform, "arch": arch},
                headers=self._get_headers(),
            )
            response.raise_for_status()
        except Exception:
            logger.warning(
                "Failed to report plugin installation for %s v%s",
                reference,
                version,
                exc_info=True,
            )

    def _get_headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Token {self.client.api_key}",
            "Content-Type": "application/json",
        }
