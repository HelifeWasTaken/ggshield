"""
Plugin downloader - downloads and installs plugin wheels.
"""

import hashlib
import json
import logging
import os
import re
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterator, Optional, Tuple

import requests

from ggshield.core.dirs import get_plugins_dir
from ggshield.core.plugin.client import (
    PluginDownloadInfo,
    PluginSource,
    PluginSourceType,
)
from ggshield.core.plugin.signature import (
    SignatureInfo,
    SignatureStatus,
    SignatureVerificationError,
    SignatureVerificationMode,
    verify_wheel_signature,
)
from ggshield.core.plugin.trust import PluginTrustStore, compute_file_sha256
from ggshield.core.plugin.wheel_utils import WheelError, extract_wheel_metadata


logger = logging.getLogger(__name__)


HTTP_TIMEOUT_SECONDS = 30
MAX_WHEEL_SIZE_BYTES = 256 * 1024 * 1024
MAX_BUNDLE_SIZE_BYTES = 1 * 1024 * 1024


def _assert_all_https(response: "requests.Response") -> None:
    """Reject a response whose redirect chain went through non-HTTPS.

    Protects against a trusted HTTPS origin redirecting through ``http://``
    (a downgrade attack). ``requests`` follows redirects transparently, so
    we inspect ``response.history`` + the final URL after the fact.
    """
    for hop in list(response.history) + [response]:
        if not hop.url.startswith("https://"):
            raise InsecureSourceError(
                f"Refusing insecure redirect through {hop.url!r}"
            )


def _stream_to_file(
    response: "requests.Response",
    dest: Path,
    max_bytes: int,
    *,
    hash_bytes: bool = False,
) -> Optional[str]:
    """Stream an HTTP response body to ``dest`` with a hard size cap.

    When ``hash_bytes`` is True, also computes SHA256 in a single pass and
    returns the hex digest; otherwise returns None. Raises ``DownloadError``
    if the response body exceeds ``max_bytes``; the partial file is then
    removed before the exception propagates.
    """
    sha256_hash = hashlib.sha256() if hash_bytes else None
    written = 0
    try:
        with open(dest, "wb") as f:
            for chunk in response.iter_content(chunk_size=65536):
                if not chunk:
                    continue
                written += len(chunk)
                if written > max_bytes:
                    raise DownloadError(
                        f"Response body exceeded maximum size of {max_bytes} bytes"
                    )
                f.write(chunk)
                if sha256_hash is not None:
                    sha256_hash.update(chunk)
    except BaseException:
        if dest.exists():
            dest.unlink()
        raise
    return sha256_hash.hexdigest() if sha256_hash is not None else None


def get_signature_label(
    manifest: Dict[str, Any],
    *,
    trusted_unsigned: bool = False,
) -> Optional[str]:
    """Get a human-readable signature status label from a manifest."""
    sig_info = manifest.get("signature")
    if not sig_info:
        return None

    status = sig_info.get("status", "unknown")
    identity = sig_info.get("identity")

    if status == SignatureStatus.VALID.value:
        if identity:
            return f"signed ({identity})"
        return "signed"

    if trusted_unsigned:
        return "unsigned (trusted)"

    if identity:
        return f"{status} ({identity})"
    return status


class DownloadError(Exception):
    """Error downloading or installing a plugin."""

    pass


class ChecksumMismatchError(DownloadError):
    """Downloaded file checksum doesn't match expected value."""

    def __init__(self, expected: str, actual: str):
        self.expected = expected
        self.actual = actual
        super().__init__(
            f"Checksum mismatch: expected {expected[:16]}..., got {actual[:16]}..."
        )


class InsecureSourceError(DownloadError):
    """Plugin source is not secure (e.g., HTTP instead of HTTPS)."""

    pass


class GitHubArtifactError(DownloadError):
    """Error downloading GitHub artifact."""

    pass


class PluginDownloader:
    """Downloads and installs plugin wheels."""

    def __init__(self) -> None:
        self.plugins_dir = get_plugins_dir(create=True)
        self.trust_store = PluginTrustStore(plugins_dir=self.plugins_dir)

    def download_and_install(
        self,
        download_info: PluginDownloadInfo,
        chunks: Iterator[bytes],
        plugin_name: str,
        source: Optional[PluginSource] = None,
        signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
        bundle_bytes: Optional[bytes] = None,
    ) -> Path:
        """Install a plugin wheel from a byte stream.

        Args:
            download_info: Filename, SHA256, version from the platform response headers.
            chunks: Iterator of raw bytes (from streaming HTTP response or test fixture).
            plugin_name: Name used for the local plugin directory.
            source: Manifest source record. Defaults to PluginSourceType.PLATFORM.
            signature_mode: Sigstore verification mode.
            bundle_bytes: Optional sigstore bundle bytes fetched by the
                caller (typically via ``PluginAPIClient.download_signature_bundle``
                using the ``X-Plugin-Signature-URL`` header). Written next
                to the wheel before verification runs, so STRICT mode
                succeeds when the platform exposes a signature.

        Returns:
            Path to the installed wheel file.

        Raises:
            ChecksumMismatchError: SHA256 of received bytes does not match download_info.sha256.
            DownloadError: File system error during installation.
            SignatureVerificationError: In STRICT mode when signature is invalid.
        """
        self._validate_plugin_name(plugin_name)

        plugin_dir = self.plugins_dir / plugin_name
        plugin_dir.mkdir(parents=True, exist_ok=True)

        wheel_path = plugin_dir / download_info.filename
        temp_path = plugin_dir / f"{download_info.filename}.tmp"

        try:
            logger.info("Installing %s...", download_info.filename)
            sha256_hash = hashlib.sha256()
            with open(temp_path, "wb") as f:
                for chunk in chunks:
                    f.write(chunk)
                    sha256_hash.update(chunk)

            computed_hash = sha256_hash.hexdigest()
            if computed_hash.lower() != download_info.sha256.lower():
                raise ChecksumMismatchError(download_info.sha256, computed_hash)

            # Remove any stale bundle sidecars before moving the new wheel
            # into place, then drop the fresh one (if provided) so
            # `verify_wheel_signature` below can find it.
            self._remove_bundle_files(wheel_path)
            temp_path.rename(wheel_path)
            if bundle_bytes is not None:
                bundle_path = wheel_path.parent / (wheel_path.name + ".sigstore")
                bundle_path.write_bytes(bundle_bytes)

            sig_info = verify_wheel_signature(wheel_path, signature_mode)

            if source is None:
                source = PluginSource(type=PluginSourceType.PLATFORM)

            # Sync trust record before writing the manifest so a trust failure
            # cannot leave an orphaned manifest pointing at a wheel we remove
            # during cleanup.
            self._sync_trust_record(plugin_name, download_info.sha256, sig_info)
            self._write_manifest(
                plugin_dir=plugin_dir,
                plugin_name=plugin_name,
                version=download_info.version,
                wheel_filename=download_info.filename,
                sha256=download_info.sha256,
                source=source,
                signature_info=sig_info,
            )

            logger.info("Installed %s v%s", plugin_name, download_info.version)
            return wheel_path

        except SignatureVerificationError:
            self._cleanup_failed_install(wheel_path)
            raise
        except Exception:
            self._cleanup_failed_install(wheel_path)
            raise
        finally:
            if temp_path.exists():
                temp_path.unlink()

    def install_from_wheel(
        self,
        wheel_path: Path,
        signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
    ) -> Tuple[str, str, Path]:
        """
        Install a plugin from a local wheel file.

        Args:
            wheel_path: Path to the wheel file.
            signature_mode: Signature verification mode.

        Returns:
            Tuple of (plugin_name, version, installed_wheel_path).

        Raises:
            WheelError: If the wheel file is invalid.
            DownloadError: If installation fails.
            SignatureVerificationError: In STRICT mode when signature is invalid.
        """
        try:
            metadata = extract_wheel_metadata(wheel_path)
        except WheelError as e:
            raise DownloadError(f"Invalid wheel file: {e}") from e

        plugin_name = metadata.name
        version = metadata.version
        self._validate_plugin_name(plugin_name)

        # Verify on the caller-provided wheel path — the bundle (if any)
        # lives alongside the source wheel. Copying first would leave a
        # rejected wheel under plugins/<name>/ on STRICT failure.
        sig_info = verify_wheel_signature(wheel_path, signature_mode)

        sha256 = compute_file_sha256(wheel_path)

        plugin_dir = self.plugins_dir / plugin_name
        plugin_dir.mkdir(parents=True, exist_ok=True)

        dest_wheel_path = plugin_dir / wheel_path.name
        self._remove_bundle_files(dest_wheel_path)
        shutil.copy2(wheel_path, dest_wheel_path)

        from ggshield.core.plugin.signature import get_bundle_path

        bundle_path = get_bundle_path(wheel_path)
        if bundle_path is not None:
            shutil.copy2(bundle_path, plugin_dir / bundle_path.name)

        # Create source tracking
        source = PluginSource(
            type=PluginSourceType.LOCAL_FILE,
            local_path=str(wheel_path.resolve()),
            sha256=sha256,
        )

        self._sync_trust_record(plugin_name, sha256, sig_info)
        self._write_manifest(
            plugin_dir=plugin_dir,
            plugin_name=plugin_name,
            version=version,
            wheel_filename=wheel_path.name,
            sha256=sha256,
            source=source,
            signature_info=sig_info,
        )

        logger.info("Installed %s v%s from local wheel", plugin_name, version)

        return plugin_name, version, dest_wheel_path

    def download_from_url(
        self,
        url: str,
        sha256: Optional[str] = None,
        signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
    ) -> Tuple[str, str, Path]:
        """
        Download and install a plugin from a URL.

        Args:
            url: URL to download the wheel from.
            sha256: Expected SHA256 checksum (optional but recommended).
            signature_mode: Signature verification mode.

        Returns:
            Tuple of (plugin_name, version, installed_wheel_path).

        Raises:
            InsecureSourceError: If URL uses HTTP instead of HTTPS.
            ChecksumMismatchError: If checksum doesn't match.
            DownloadError: If download or installation fails.
            SignatureVerificationError: In STRICT mode when signature is invalid.
        """
        # Security check: require HTTPS
        if url.startswith("http://"):
            raise InsecureSourceError(
                "HTTP URLs are not allowed for security reasons. Use HTTPS instead."
            )

        if not url.startswith("https://"):
            raise DownloadError(f"Invalid URL scheme: {url}")

        with tempfile.TemporaryDirectory() as temp_dir:
            raw_filename = url.split("/")[-1].split("?")[0]
            filename = PurePosixPath(raw_filename).name
            if not filename or filename in {".", ".."} or not filename.endswith(".whl"):
                filename = "plugin.whl"

            temp_wheel_path = Path(temp_dir) / filename

            try:
                logger.info("Downloading from %s...", url)
                response = requests.get(
                    url, stream=True, timeout=HTTP_TIMEOUT_SECONDS
                )
                _assert_all_https(response)
                response.raise_for_status()

                computed_hash = _stream_to_file(
                    response, temp_wheel_path, MAX_WHEEL_SIZE_BYTES, hash_bytes=True
                )
                assert computed_hash is not None

                if sha256 and computed_hash.lower() != sha256.lower():
                    raise ChecksumMismatchError(sha256, computed_hash)

            except requests.RequestException as e:
                raise DownloadError(f"Failed to download from URL: {e}") from e

            try:
                metadata = extract_wheel_metadata(temp_wheel_path)
            except WheelError as e:
                raise DownloadError(f"Downloaded file is not a valid wheel: {e}") from e

            plugin_name = metadata.name
            version = metadata.version
            self._validate_plugin_name(plugin_name)

            # Fetch sigstore bundle alongside the wheel in the temp dir so
            # verification runs before we touch the final plugin directory.
            self._download_url_bundle(url, temp_wheel_path)

            # Verify before we place anything in the final destination so a
            # STRICT-mode signature failure can't leave a rejected wheel on
            # disk under plugins/<name>/.
            sig_info = verify_wheel_signature(temp_wheel_path, signature_mode)

            plugin_dir = self.plugins_dir / plugin_name
            plugin_dir.mkdir(parents=True, exist_ok=True)

            dest_wheel_path = plugin_dir / temp_wheel_path.name
            self._remove_bundle_files(dest_wheel_path)
            shutil.copy2(temp_wheel_path, dest_wheel_path)

            # Copy the bundle too if one was fetched.
            for ext in (".sigstore", ".sigstore.json"):
                bundle_src = temp_wheel_path.parent / (temp_wheel_path.name + ext)
                if bundle_src.exists():
                    shutil.copy2(bundle_src, plugin_dir / bundle_src.name)
                    break

        source = PluginSource(
            type=PluginSourceType.URL,
            url=url,
            sha256=computed_hash,
        )

        self._sync_trust_record(plugin_name, computed_hash, sig_info)
        self._write_manifest(
            plugin_dir=plugin_dir,
            plugin_name=plugin_name,
            version=version,
            wheel_filename=dest_wheel_path.name,
            sha256=computed_hash,
            source=source,
            signature_info=sig_info,
        )

        logger.info("Installed %s v%s from URL", plugin_name, version)

        return plugin_name, version, dest_wheel_path

    def download_from_github_release(
        self,
        url: str,
        sha256: Optional[str] = None,
        signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
    ) -> Tuple[str, str, Path]:
        """
        Download and install a plugin from a GitHub release asset.

        Args:
            url: GitHub release asset URL.
            sha256: Expected SHA256 checksum (optional).
            signature_mode: Signature verification mode.

        Returns:
            Tuple of (plugin_name, version, installed_wheel_path).
        """
        github_repo = self._extract_github_repo(url)

        plugin_name, version, wheel_path = self.download_from_url(
            url, sha256, signature_mode=signature_mode
        )

        # Upgrade the provenance record from "url" to "github_release". Use
        # the same tmp+replace path as _write_manifest so a crash mid-write
        # can't corrupt the manifest.
        manifest_path = self.plugins_dir / plugin_name / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["source"] = PluginSource(
            type=PluginSourceType.GITHUB_RELEASE,
            url=url,
            github_repo=github_repo,
            sha256=manifest.get("sha256"),
        ).to_dict()

        tmp_path = manifest_path.with_suffix(".json.tmp")
        try:
            tmp_path.write_text(json.dumps(manifest, indent=2))
            tmp_path.replace(manifest_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

        return plugin_name, version, wheel_path

    def download_from_github_artifact(
        self,
        url: str,
        signature_mode: SignatureVerificationMode = SignatureVerificationMode.STRICT,
    ) -> Tuple[str, str, Path]:
        """
        Download and install a plugin from a GitHub Actions artifact.

        GitHub artifacts are ZIP files containing wheel(s). This method:
        1. Downloads the artifact ZIP
        2. Extracts the wheel file
        3. Installs the wheel

        Args:
            url: GitHub artifact URL (browser URL or API URL).
            signature_mode: Signature verification mode.

        Returns:
            Tuple of (plugin_name, version, installed_wheel_path).

        Raises:
            GitHubArtifactError: If artifact cannot be downloaded or processed.
            DownloadError: If installation fails.
            SignatureVerificationError: In STRICT mode when signature is invalid.
        """
        # Parse artifact URL to get API endpoint
        artifact_info = self._parse_github_artifact_url(url)
        if not artifact_info:
            raise GitHubArtifactError(f"Invalid GitHub artifact URL: {url}")

        owner, repo, artifact_id = artifact_info

        # Get GitHub token from environment
        github_token = os.environ.get("GITHUB_TOKEN")
        if not github_token:
            # Try gh CLI as fallback
            github_token = self._get_gh_token()

        if not github_token:
            raise GitHubArtifactError(
                "GitHub authentication required. Set GITHUB_TOKEN environment variable "
                "or install and authenticate with GitHub CLI (gh auth login)."
            )

        # Download artifact ZIP
        api_url = f"https://api.github.com/repos/{owner}/{repo}/actions/artifacts/{artifact_id}/zip"

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_dir_path = Path(temp_dir)
            artifact_zip_path = temp_dir_path / "artifact.zip"

            try:
                logger.info("Downloading GitHub artifact...")
                response = requests.get(
                    api_url,
                    headers={
                        "Authorization": f"Bearer {github_token}",
                        "Accept": "application/vnd.github+json",
                        "X-GitHub-Api-Version": "2022-11-28",
                    },
                    stream=True,
                    timeout=HTTP_TIMEOUT_SECONDS,
                )
                _assert_all_https(response)
                response.raise_for_status()

                _stream_to_file(
                    response, artifact_zip_path, MAX_WHEEL_SIZE_BYTES
                )

            except requests.RequestException as e:
                raise GitHubArtifactError(f"Failed to download artifact: {e}") from e

            # Extract ZIP and find wheel
            extract_dir = temp_dir_path / "extracted"

            try:
                from ggshield.utils.archive import safe_unpack

                safe_unpack(artifact_zip_path, extract_dir)
            except Exception as e:
                raise GitHubArtifactError(f"Failed to extract artifact: {e}") from e

            # Sort to ensure deterministic wheel selection when multiple
            # wheels are shipped in the same artifact — without this, the
            # order depends on filesystem traversal and an attacker-shaped
            # artifact could cause different machines to pick different
            # wheels.
            wheel_files = sorted(extract_dir.glob("**/*.whl"))
            if not wheel_files:
                raise GitHubArtifactError("No wheel file found in artifact")

            if len(wheel_files) > 1:
                logger.warning(
                    "Multiple wheel files found in artifact, using first "
                    "(alphabetical): %s",
                    wheel_files[0].name,
                )

            temp_wheel_path = wheel_files[0]

            try:
                metadata = extract_wheel_metadata(temp_wheel_path)
            except WheelError as e:
                raise DownloadError(f"Invalid wheel in artifact: {e}") from e

            plugin_name = metadata.name
            version = metadata.version
            self._validate_plugin_name(plugin_name)

            # Verify on the temp path before we touch plugin_dir — a STRICT
            # signature failure must not leave a rejected wheel on disk.
            sig_info = verify_wheel_signature(temp_wheel_path, signature_mode)

            sha256 = compute_file_sha256(temp_wheel_path)

            plugin_dir = self.plugins_dir / plugin_name
            plugin_dir.mkdir(parents=True, exist_ok=True)

            dest_wheel_path = plugin_dir / temp_wheel_path.name
            self._remove_bundle_files(dest_wheel_path)
            shutil.copy2(temp_wheel_path, dest_wheel_path)

            for ext in (".sigstore", ".sigstore.json"):
                bundle_src = temp_wheel_path.parent / (temp_wheel_path.name + ext)
                if bundle_src.exists():
                    shutil.copy2(bundle_src, plugin_dir / bundle_src.name)
                    break

        source = PluginSource(
            type=PluginSourceType.GITHUB_ARTIFACT,
            url=url,
            github_repo=f"{owner}/{repo}",
            sha256=sha256,
        )

        self._sync_trust_record(plugin_name, sha256, sig_info)
        self._write_manifest(
            plugin_dir=plugin_dir,
            plugin_name=plugin_name,
            version=version,
            wheel_filename=dest_wheel_path.name,
            sha256=sha256,
            source=source,
            signature_info=sig_info,
        )

        logger.info("Installed %s v%s from GitHub artifact", plugin_name, version)

        return plugin_name, version, dest_wheel_path

    def uninstall(self, plugin_name: str) -> bool:
        """Uninstall a plugin (by package name or entry point name)."""
        if not self._is_valid_plugin_name(plugin_name):
            logger.warning("Invalid plugin name: %s", plugin_name)
            return False

        plugin_dir = self._resolve_plugin_dir(plugin_name)
        if plugin_dir is None:
            return False

        self.trust_store.revoke_plugin(plugin_dir.name)
        shutil.rmtree(plugin_dir)

        logger.info("Uninstalled plugin: %s", plugin_name)
        return True

    def get_installed_version(self, plugin_name: str) -> Optional[str]:
        """Get the installed version of a plugin (by package name or entry point name)."""
        manifest = self.get_manifest(plugin_name)
        if not manifest:
            return None
        return manifest.get("version")

    def is_installed(self, plugin_name: str) -> bool:
        """Check if a plugin is installed (by package name or entry point name)."""
        return self.get_installed_version(plugin_name) is not None

    def _resolve_plugin_dir(self, plugin_name: str) -> Optional[Path]:
        """Resolve a plugin directory from a package or entry point name."""
        plugin_dir = self.plugins_dir / plugin_name
        if plugin_dir.exists():
            return plugin_dir
        return self._find_plugin_dir_by_entry_point(plugin_name)

    def _get_manifest_path(self, plugin_name: str) -> Optional[Path]:
        """Return the manifest path for a plugin installed by package or entry point."""
        if not self._is_valid_plugin_name(plugin_name):
            logger.warning("Invalid plugin name: %s", plugin_name)
            return None

        plugin_dir = self._resolve_plugin_dir(plugin_name)
        if plugin_dir is None:
            return None

        manifest_path = plugin_dir / "manifest.json"
        if not manifest_path.exists():
            return None
        return manifest_path

    def _find_plugin_dir_by_entry_point(self, entry_point_name: str) -> Optional[Path]:
        """Find a plugin directory by its entry point name."""
        if not self.plugins_dir.exists():
            return None

        for plugin_dir in self.plugins_dir.iterdir():
            if not plugin_dir.is_dir():
                continue

            manifest_path = plugin_dir / "manifest.json"
            if not manifest_path.exists():
                continue

            try:
                manifest = json.loads(manifest_path.read_text())
                wheel_filename = manifest.get("wheel_filename", "")
                wheel_path = plugin_dir / wheel_filename

                if wheel_path.exists():
                    # Read entry point name from wheel
                    ep_name = self._read_entry_point_name_from_wheel(wheel_path)
                    if ep_name == entry_point_name:
                        return plugin_dir
            except (json.JSONDecodeError, KeyError):
                continue

        return None

    def _read_entry_point_name_from_wheel(self, wheel_path: Path) -> Optional[str]:
        """Read the entry point name from a wheel file."""
        from ggshield.core.plugin.loader import read_entry_point_from_wheel

        result = read_entry_point_from_wheel(wheel_path)
        return result[0] if result else None

    def get_wheel_path(self, plugin_name: str) -> Optional[Path]:
        """Get the path to an installed plugin's wheel file."""
        manifest_path = self._get_manifest_path(plugin_name)
        if manifest_path is None:
            return None

        try:
            manifest = json.loads(manifest_path.read_text())
            wheel_filename = manifest.get("wheel_filename")
            if wheel_filename:
                wheel_path = manifest_path.parent / wheel_filename
                if wheel_path.exists():
                    return wheel_path
        except (json.JSONDecodeError, KeyError):
            pass

        return None

    def get_manifest(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get the full manifest for an installed plugin."""
        manifest_path = self._get_manifest_path(plugin_name)
        if manifest_path is None:
            return None

        try:
            return json.loads(manifest_path.read_text())
        except json.JSONDecodeError:
            return None

    def get_installed_signature_label(self, plugin_name: str) -> Optional[str]:
        """Return the display label for an installed plugin's signature state."""
        manifest = self.get_manifest(plugin_name)
        if not manifest:
            return None

        trusted_unsigned = False
        stored_sha256 = manifest.get("sha256")
        plugin_dir = self._resolve_plugin_dir(plugin_name)
        if stored_sha256 and plugin_dir is not None:
            trusted_unsigned = self.trust_store.is_trusted(
                plugin_dir.name, stored_sha256
            )

        return get_signature_label(manifest, trusted_unsigned=trusted_unsigned)

    def get_plugin_source(self, plugin_name: str) -> Optional[PluginSource]:
        """Get the source information for an installed plugin."""
        manifest = self.get_manifest(plugin_name)
        if not manifest:
            return None

        source_data = manifest.get("source")
        if not source_data:
            # Legacy manifest without source tracking - assume GitGuardian API
            return PluginSource(type=PluginSourceType.PLATFORM)

        try:
            return PluginSource.from_dict(source_data)
        except (KeyError, ValueError):
            return None

    @staticmethod
    def _is_valid_plugin_name(plugin_name: str) -> bool:
        """Check if plugin name is safe to use as a path segment."""
        if not plugin_name or plugin_name in {".", ".."}:
            return False
        if "/" in plugin_name or "\\" in plugin_name:
            return False
        if "\x00" in plugin_name:
            return False
        return True

    def _validate_plugin_name(self, plugin_name: str) -> None:
        """Validate plugin name and raise on unsafe values."""
        if not self._is_valid_plugin_name(plugin_name):
            raise DownloadError(f"Invalid plugin name: {plugin_name!r}")

    def _write_manifest(
        self,
        plugin_dir: Path,
        plugin_name: str,
        version: str,
        wheel_filename: str,
        sha256: str,
        source: PluginSource,
        signature_info: Optional[SignatureInfo] = None,
    ) -> None:
        """Write the plugin manifest file."""
        manifest: Dict[str, Any] = {
            "plugin_name": plugin_name,
            "version": version,
            "wheel_filename": wheel_filename,
            "sha256": sha256,
            "source": source.to_dict(),
            "installed_at": datetime.now(timezone.utc).isoformat(),
        }
        if signature_info is not None:
            sig_data: Dict[str, Any] = {"status": signature_info.status.value}
            if signature_info.identity:
                sig_data["identity"] = signature_info.identity
            if signature_info.message:
                sig_data["message"] = signature_info.message
            manifest["signature"] = sig_data

        manifest_path = plugin_dir / "manifest.json"
        tmp_path = manifest_path.with_suffix(".json.tmp")
        try:
            tmp_path.write_text(json.dumps(manifest, indent=2))
            tmp_path.replace(manifest_path)
        finally:
            if tmp_path.exists():
                tmp_path.unlink()

    def _sync_trust_record(
        self,
        plugin_name: str,
        sha256: str,
        signature_info: SignatureInfo,
    ) -> None:
        """Persist or revoke trust for a plugin based on install-time verification.

        When a plugin is installed with a VALID signature we remove any stale
        trust exception (from a previous unsigned install). Otherwise we record
        the new hash — ``trust_plugin`` overwrites the existing entry so we do
        not need to revoke first.
        """
        if signature_info.status == SignatureStatus.VALID:
            self.trust_store.revoke_plugin(plugin_name)
            return

        self.trust_store.trust_plugin(
            plugin_name,
            sha256,
            signature_info.status.value,
        )

    def _download_url_bundle(
        self, wheel_url: str, dest_wheel_path: Path
    ) -> Optional[Path]:
        """Try downloading a sigstore bundle from URL conventions.

        Tries {wheel_url}.sigstore first, then {wheel_url}.sigstore.json.
        """
        for ext in (".sigstore", ".sigstore.json"):
            bundle_url = wheel_url + ext
            bundle_path = dest_wheel_path.parent / (dest_wheel_path.name + ext)
            try:
                response = requests.get(
                    bundle_url, stream=True, timeout=HTTP_TIMEOUT_SECONDS
                )
                _assert_all_https(response)
                response.raise_for_status()

                _stream_to_file(response, bundle_path, MAX_BUNDLE_SIZE_BYTES)

                logger.info("Downloaded signature bundle from %s", bundle_url)
                return bundle_path
            except (requests.RequestException, InsecureSourceError, DownloadError):
                continue

        logger.debug("No signature bundle found at URL conventions for %s", wheel_url)
        return None

    def _remove_bundle_files(self, wheel_path: Path) -> None:
        """Remove any bundle sidecars associated with a wheel path."""
        for ext in (".sigstore", ".sigstore.json"):
            bundle = wheel_path.parent / (wheel_path.name + ext)
            if bundle.exists():
                bundle.unlink()

    def _cleanup_failed_install(self, wheel_path: Path) -> None:
        """Remove wheel and bundle files after a failed install."""
        if wheel_path.exists():
            wheel_path.unlink()

        self._remove_bundle_files(wheel_path)

    def _extract_github_repo(self, url: str) -> Optional[str]:
        """Extract owner/repo from a GitHub URL."""
        match = re.match(r"https://github\.com/([^/]+)/([^/]+)", url)
        if not match:
            return None
        owner, repo = match.group(1), match.group(2)
        if repo.endswith(".git"):
            repo = repo[: -len(".git")]
        # Reject path-traversal-like segments; the repo value is later
        # interpolated into api.github.com URLs and stored in manifests.
        if owner in {"", ".", ".."} or repo in {"", ".", ".."}:
            return None
        if "/" in owner or "/" in repo or "\\" in owner or "\\" in repo:
            return None
        return f"{owner}/{repo}"

    def _parse_github_artifact_url(self, url: str) -> Optional[Tuple[str, str, str]]:
        """
        Parse GitHub artifact URL to extract owner, repo, and artifact ID.

        Supports URLs like:
        - https://github.com/{owner}/{repo}/actions/runs/{run_id}/artifacts/{artifact_id}
        """
        pattern = (
            r"https://github\.com/([^/]+)/([^/]+)/actions/runs/\d+/artifacts/(\d+)"
        )
        match = re.match(pattern, url)
        if match:
            return match.group(1), match.group(2), match.group(3)
        return None

    def _get_gh_token(self) -> Optional[str]:
        """Try to get GitHub token from gh CLI."""
        import subprocess

        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return None
