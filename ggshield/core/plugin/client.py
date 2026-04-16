"""
Plugin API client - fetches available plugins from GitGuardian API.
"""

import logging
import re
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from pathlib import PurePosixPath
from typing import Any, Dict, Generator, Iterator, List, Optional, Tuple
from urllib.parse import urlparse

import requests
from pygitguardian import GGClient

from ggshield.core.plugin.platform import PlatformInfo, get_platform_info


logger = logging.getLogger(__name__)


HTTP_TIMEOUT_SECONDS = 30
MAX_WHEEL_SIZE_BYTES = 256 * 1024 * 1024
MAX_BUNDLE_SIZE_BYTES = 1 * 1024 * 1024


def _assert_all_https(response: "requests.Response") -> None:
    """Reject a response whose redirect chain went through non-HTTPS."""
    for hop in list(response.history) + [response]:
        if not hop.url.startswith("https://"):
            raise PluginAPIError(
                f"Refusing insecure redirect through {hop.url!r}"
            )


def _sanitize_wheel_filename(raw: str) -> str:
    """Return a wheel filename safe to use as a single path segment.

    Strips any path components the server may have included and rejects
    values that would resolve outside the plugin directory (``..``, empty
    segment, embedded NUL, trailing ``.whl`` missing).
    """
    name = PurePosixPath(raw).name
    if not name or name in {".", ".."} or "\x00" in name or "\\" in name:
        raise PluginAPIError(f"Server returned unsafe filename: {raw!r}")
    return name


def _iter_with_size_cap(
    chunks: Iterator[bytes], max_bytes: int
) -> Generator[bytes, None, None]:
    """Yield chunks from ``chunks`` until ``max_bytes`` is exceeded."""
    written = 0
    for chunk in chunks:
        written += len(chunk)
        if written > max_bytes:
            raise PluginAPIError(
                f"Response body exceeded maximum size of {max_bytes} bytes"
            )
        yield chunk


class PluginSourceType(Enum):
    """Types of plugin sources."""

    PLATFORM = "platform"
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
    # Absolute URL of the sigstore bundle, from the X-Plugin-Signature-URL
    # response header. None when the platform has no bundle for this
    # artifact — STRICT verification then fails fast (as it should).
    signature_url: Optional[str] = None


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


def _extract_server_detail(response: "requests.Response") -> Optional[str]:
    """Return the server's ``detail`` field when available, else None.

    Falls back to None on empty bodies, non-JSON responses, or JSON
    shapes without a ``detail`` field — so callers can use their own
    default message in those cases.
    """
    try:
        body = response.json()
    except (ValueError, requests.RequestException):
        return None
    if isinstance(body, dict):
        detail = body.get("detail")
        if isinstance(detail, str) and detail:
            return detail
    return None


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
            )
            if response.status_code == 404:
                raise PluginsNotEnabledError()
            response.raise_for_status()
        except PluginsNotEnabledError:
            raise
        except requests.RequestException as e:
            raise PluginAPIError(f"Failed to fetch plugins: {e}") from e

        plugins_data = response.json()

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
                stream=True,
                timeout=HTTP_TIMEOUT_SECONDS,
            )
            _assert_all_https(response)
            if response.status_code in (403, 404):
                # Surface the server's `detail` (e.g. "No active release
                # found for 'satori-python' version v0.32.0. Available
                # versions: 0.32.0, …") rather than a hardcoded message.
                # The server knows what went wrong and what's available;
                # clients typically don't. Fall back to the previous
                # generic strings when the body isn't JSON or lacks a
                # detail field (defensive — shouldn't happen against a
                # current backend).
                detail = _extract_server_detail(response)
                if not detail:
                    detail = (
                        "Plugin or version not found"
                        if response.status_code == 404
                        else None
                    )
                raise PluginNotAvailableError(reference, detail)
            response.raise_for_status()

            content_disposition = response.headers.get("Content-Disposition", "")
            match = re.search(r'filename="([^"]+)"', content_disposition)
            raw_filename = match.group(1) if match else f"{reference}.whl"
            filename = _sanitize_wheel_filename(raw_filename)

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

            size_bytes = int(response.headers.get("Content-Length", 0))
            if size_bytes > MAX_WHEEL_SIZE_BYTES:
                raise PluginAPIError(
                    f"Plugin wheel size {size_bytes} exceeds maximum "
                    f"of {MAX_WHEEL_SIZE_BYTES} bytes"
                )

            info = PluginDownloadInfo(
                filename=filename,
                sha256=sha256,
                version=resolved_version,
                size_bytes=size_bytes,
                signature_url=response.headers.get("X-Plugin-Signature-URL") or None,
            )
            yield info, _iter_with_size_cap(
                response.iter_content(chunk_size=65536), MAX_WHEEL_SIZE_BYTES
            )
        except (PluginNotAvailableError, PluginAPIError):
            raise
        except requests.RequestException as e:
            raise PluginAPIError(f"Failed to download plugin: {e}") from e
        finally:
            if response is not None:
                response.close()

    def download_signature_bundle(self, signature_url: str) -> bytes:
        """Fetch a sigstore bundle using the authenticated session.

        The platform's ``X-Plugin-Signature-URL`` header points at our own
        ``/download/signature`` proxy (the upstream mirror URL is kept
        server-side), and that proxy requires the same Token auth as
        ``/download`` — hence using ``self.client.session`` rather than a
        bare ``requests.get``. We require the URL to share the platform's
        origin so a compromised or misconfigured backend can't coerce us
        into sending our Token to a third-party host.
        """
        base = urlparse(self.base_url)
        target = urlparse(signature_url)
        if (target.scheme, target.hostname, target.port) != (
            base.scheme,
            base.hostname,
            base.port,
        ):
            raise PluginAPIError(
                f"Refusing to fetch signature bundle from foreign origin "
                f"{target.scheme}://{target.hostname}"
            )

        try:
            response = self.client.session.get(
                signature_url, timeout=HTTP_TIMEOUT_SECONDS, stream=True
            )
            _assert_all_https(response)
            response.raise_for_status()

            size_bytes = int(response.headers.get("Content-Length", 0))
            if size_bytes > MAX_BUNDLE_SIZE_BYTES:
                raise PluginAPIError(
                    f"Signature bundle size {size_bytes} exceeds maximum "
                    f"of {MAX_BUNDLE_SIZE_BYTES} bytes"
                )

            buffer = bytearray()
            for chunk in response.iter_content(chunk_size=65536):
                buffer.extend(chunk)
                if len(buffer) > MAX_BUNDLE_SIZE_BYTES:
                    raise PluginAPIError(
                        f"Signature bundle exceeded maximum size of "
                        f"{MAX_BUNDLE_SIZE_BYTES} bytes"
                    )
            return bytes(buffer)
        except PluginAPIError:
            raise
        except requests.RequestException as e:
            raise PluginAPIError(
                f"Failed to download signature bundle from {signature_url}: {e}"
            ) from e

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
            )
            response.raise_for_status()
        except Exception:
            logger.warning(
                "Failed to report plugin installation for %s v%s",
                reference,
                version,
                exc_info=True,
            )
