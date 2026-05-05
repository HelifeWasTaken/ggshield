"""Tests for plugin API client."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from ggshield.core.plugin.client import (
    PluginAPIClient,
    PluginAPIError,
    PluginCatalog,
    PluginInfo,
    PluginNotAvailableError,
    PluginsNotEnabledError,
    PluginSourceType,
)
from ggshield.core.plugin.platform import PlatformInfo


class TestPluginSourceType:
    """Tests for PluginSourceType enum."""

    def test_platform_value(self) -> None:
        """PLATFORM enum has value 'platform'."""
        assert PluginSourceType.PLATFORM.value == "platform"

    def test_backward_compat_gitguardian_api(self) -> None:
        """Legacy manifest value 'gitguardian_api' maps to PLATFORM."""
        assert PluginSourceType("gitguardian_api") == PluginSourceType.PLATFORM


class TestPluginInfo:
    """Tests for PluginInfo dataclass."""

    def test_is_platform_supported_no_restrictions(self) -> None:
        """Test platform support with no restrictions."""
        info = PluginInfo(
            name="test",
            display_name="Test",
            description="Test plugin",
            available=True,
            latest_version="1.0.0",
            supported_platforms=[],
        )
        assert info.is_platform_supported("linux", "x86_64") is True
        assert info.is_platform_supported("macosx", "arm64") is True

    def test_is_platform_supported_exact_match(self) -> None:
        """Test platform support with exact match."""
        info = PluginInfo(
            name="test",
            display_name="Test",
            description="Test plugin",
            available=True,
            latest_version="1.0.0",
            supported_platforms=["linux-x86_64", "macosx-arm64"],
        )
        assert info.is_platform_supported("linux", "x86_64") is True
        assert info.is_platform_supported("macosx", "arm64") is True
        assert info.is_platform_supported("win", "amd64") is False

    def test_is_platform_supported_any_any(self) -> None:
        """Test platform support with any-any wildcard."""
        info = PluginInfo(
            name="test",
            display_name="Test",
            description="Test plugin",
            available=True,
            latest_version="1.0.0",
            supported_platforms=["any-any"],
        )
        assert info.is_platform_supported("linux", "x86_64") is True
        assert info.is_platform_supported("win", "amd64") is True


class TestPluginNotAvailableError:
    """Tests for PluginNotAvailableError."""

    def test_error_without_reason(self) -> None:
        """Test error message without reason."""
        error = PluginNotAvailableError("testplugin")
        assert error.plugin_name == "testplugin"
        assert error.reason is None
        assert str(error) == "Plugin 'testplugin' is not available"

    def test_error_with_reason(self) -> None:
        """Test error message with reason."""
        error = PluginNotAvailableError("testplugin", "Requires enterprise plan")
        assert error.plugin_name == "testplugin"
        assert error.reason == "Requires enterprise plan"
        assert (
            str(error)
            == "Plugin 'testplugin' is not available: Requires enterprise plan"
        )


class TestPluginAPIClient:
    """Tests for PluginAPIClient."""

    @pytest.fixture
    def mock_gg_client(self) -> MagicMock:
        """Create a mock GGClient."""
        client = MagicMock()
        client.base_uri = "https://api.gitguardian.com/"
        client.api_key = "test-api-key"
        client.session = MagicMock()
        return client

    def test_init(self, mock_gg_client: MagicMock) -> None:
        """Test client initialization."""
        client = PluginAPIClient(mock_gg_client)
        assert client.base_url == "https://api.gitguardian.com"
        assert client.client == mock_gg_client

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_get_available_plugins_success(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """Test successful plugin list fetch returns PluginCatalog with plugins."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "reference": "tokenscanner",
                "display_name": "Token Scanner",
                "description": "Local scanning",
                "available": True,
                "reason": None,
                "releases": [{"version": "1.0.0"}],
            }
        ]
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        catalog = client.get_available_plugins()

        assert isinstance(catalog, PluginCatalog)
        assert len(catalog.plugins) == 1
        assert catalog.plugins[0].name == "tokenscanner"
        assert catalog.plugins[0].latest_version == "1.0.0"

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_get_available_plugins_request_error(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """Test plugin list fetch with request error."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )

        mock_gg_client.session.get.side_effect = requests.RequestException(
            "Connection failed"
        )

        client = PluginAPIClient(mock_gg_client)

        with pytest.raises(PluginAPIError) as exc_info:
            client.get_available_plugins()

        assert "Failed to fetch plugins" in str(exc_info.value)

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_get_available_plugins_new_endpoint(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """get_available_plugins calls /v1/endpoints/plugins and parses the list."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = [
            {
                "reference": "tokenscanner",
                "display_name": "Token Scanner",
                "description": "Local scanning",
                "available": True,
                "reason": None,
                "releases": [{"version": "2.0.0"}, {"version": "1.0.0"}],
            }
        ]
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        catalog = client.get_available_plugins()

        url_called = mock_gg_client.session.get.call_args[0][0]
        assert "/v1/endpoints/plugins" in url_called
        assert len(catalog.plugins) == 1
        assert catalog.plugins[0].name == "tokenscanner"
        assert catalog.plugins[0].latest_version == "2.0.0"
        assert catalog.plugins[0].available is True

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_get_available_plugins_raises_plugins_not_enabled_on_404(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """get_available_plugins raises PluginsNotEnabledError on 404."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)

        with pytest.raises(PluginsNotEnabledError):
            client.get_available_plugins()

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_download_plugin_yields_info_and_chunks(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """download_plugin yields PluginDownloadInfo and chunk iterator."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Content-Disposition": 'attachment; filename="tokenscanner-1.0.0.whl"',
            "X-Plugin-SHA256": "abc123def456",
            "X-Plugin-Version": "1.0.0",
            "Content-Length": "12345",
        }
        mock_response.iter_content.return_value = iter([b"chunk1", b"chunk2"])
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        with client.download_plugin("tokenscanner") as (info, chunks):
            assert info.filename == "tokenscanner-1.0.0.whl"
            assert info.sha256 == "abc123def456"
            assert info.version == "1.0.0"
            assert info.size_bytes == 12345
            data = list(chunks)

        assert data == [b"chunk1", b"chunk2"]
        mock_response.close.assert_called_once()

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_download_plugin_raises_on_403(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """download_plugin raises PluginNotAvailableError on 403."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        with pytest.raises(PluginNotAvailableError) as exc_info:
            with client.download_plugin("tokenscanner"):
                pass

        assert exc_info.value.plugin_name == "tokenscanner"
        mock_response.close.assert_called_once()

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_download_plugin_raises_on_404(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """download_plugin raises PluginNotAvailableError on 404."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        with pytest.raises(PluginNotAvailableError) as exc_info:
            with client.download_plugin("tokenscanner"):
                pass

        assert "not found" in exc_info.value.reason.lower()
        mock_response.close.assert_called_once()

    @patch("ggshield.core.plugin.client.get_platform_info")
    def test_download_plugin_closes_response_on_mid_stream_error(
        self, mock_platform: MagicMock, mock_gg_client: MagicMock
    ) -> None:
        """download_plugin closes the response even when caller raises inside the with block."""
        mock_platform.return_value = PlatformInfo(
            os="linux", arch="x86_64", python_abi="cp311"
        )
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Content-Disposition": 'attachment; filename="tokenscanner-1.0.0.whl"',
            "X-Plugin-SHA256": "abc123",
            "X-Plugin-Version": "1.0.0",
            "Content-Length": "100",
        }
        mock_response.iter_content.return_value = iter([b"data"])
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        with pytest.raises(RuntimeError):
            with client.download_plugin("tokenscanner"):
                raise RuntimeError("mid-stream failure")

        mock_response.close.assert_called_once()

    def test_report_installation_posts_correct_body(
        self, mock_gg_client: MagicMock
    ) -> None:
        """report_installation POSTs to /installed with version, platform, arch."""
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_gg_client.session.post.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        client.report_installation("tokenscanner", "1.0.0", "linux", "x86_64")

        mock_gg_client.session.post.assert_called_once()
        call_args = mock_gg_client.session.post.call_args
        url = call_args[0][0]
        body = call_args[1]["json"]
        assert "/endpoints/plugins/tokenscanner/installed" in url
        assert body == {"version": "1.0.0", "platform": "linux", "arch": "x86_64"}

    def test_report_installation_swallows_network_error(
        self, mock_gg_client: MagicMock
    ) -> None:
        """report_installation does not raise when the network call fails."""
        mock_gg_client.session.post.side_effect = Exception("network failure")

        client = PluginAPIClient(mock_gg_client)
        # Must not raise
        client.report_installation("tokenscanner", "1.0.0", "linux", "x86_64")


class TestDownloadSignatureBundle:
    """Tests for PluginAPIClient.download_signature_bundle."""

    @pytest.fixture
    def mock_gg_client(self) -> MagicMock:
        client = MagicMock()
        client.base_uri = "https://api.gitguardian.com/"
        client.api_key = "test-api-key"
        client.session = MagicMock()
        return client

    def test_returns_bundle_bytes(self, mock_gg_client: MagicMock) -> None:
        """A normal HTTPS bundle download returns the body bytes."""
        body = b"sigstore bundle bytes"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.history = []
        mock_response.url = (
            "https://api.gitguardian.com/v1/endpoints/plugins/p/signature"
        )
        mock_response.headers = {"Content-Length": str(len(body))}
        mock_response.iter_content.return_value = iter([body])
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        result = client.download_signature_bundle(
            "https://api.gitguardian.com/v1/endpoints/plugins/p/signature"
        )

        assert result == body

    def test_rejects_foreign_origin(self, mock_gg_client: MagicMock) -> None:
        """A signature URL on a different origin is rejected before sending the request."""
        client = PluginAPIClient(mock_gg_client)
        with pytest.raises(PluginAPIError, match="foreign origin"):
            client.download_signature_bundle("https://evil.example.com/bundle.sigstore")
        mock_gg_client.session.get.assert_not_called()

    def test_rejects_oversize_bundle_via_content_length(
        self, mock_gg_client: MagicMock
    ) -> None:
        """A Content-Length above the cap is rejected before reading the body."""
        from ggshield.core.plugin.client import MAX_BUNDLE_SIZE_BYTES

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.history = []
        mock_response.url = (
            "https://api.gitguardian.com/v1/endpoints/plugins/p/signature"
        )
        mock_response.headers = {"Content-Length": str(MAX_BUNDLE_SIZE_BYTES + 1)}
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        with pytest.raises(PluginAPIError, match="exceeds maximum"):
            client.download_signature_bundle(
                "https://api.gitguardian.com/v1/endpoints/plugins/p/signature"
            )

    def test_rejects_oversize_streaming_body(self, mock_gg_client: MagicMock) -> None:
        """If Content-Length lies, the streaming-read cap still kicks in."""
        from ggshield.core.plugin.client import MAX_BUNDLE_SIZE_BYTES

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.history = []
        mock_response.url = (
            "https://api.gitguardian.com/v1/endpoints/plugins/p/signature"
        )
        mock_response.headers = {"Content-Length": "0"}  # lie about size
        # Stream more bytes than the cap allows.
        mock_response.iter_content.return_value = iter(
            [b"x" * (MAX_BUNDLE_SIZE_BYTES + 1)]
        )
        mock_gg_client.session.get.return_value = mock_response

        client = PluginAPIClient(mock_gg_client)
        with pytest.raises(PluginAPIError, match="exceeded maximum"):
            client.download_signature_bundle(
                "https://api.gitguardian.com/v1/endpoints/plugins/p/signature"
            )

    def test_wraps_network_error(self, mock_gg_client: MagicMock) -> None:
        """A requests exception is re-raised as PluginAPIError."""
        mock_gg_client.session.get.side_effect = requests.RequestException("boom")

        client = PluginAPIClient(mock_gg_client)
        with pytest.raises(PluginAPIError, match="Failed to download signature bundle"):
            client.download_signature_bundle(
                "https://api.gitguardian.com/v1/endpoints/plugins/p/signature"
            )


class TestExtractServerDetail:
    """Tests for the ``_extract_server_detail`` helper used to surface DRF
    error-detail strings to the user."""

    def test_returns_detail_when_present(self) -> None:
        from ggshield.core.plugin.client import _extract_server_detail

        response = MagicMock()
        response.json.return_value = {"detail": "Plugin disabled"}
        assert _extract_server_detail(response) == "Plugin disabled"

    def test_returns_none_for_non_json_body(self) -> None:
        from ggshield.core.plugin.client import _extract_server_detail

        response = MagicMock()
        response.json.side_effect = ValueError("not json")
        assert _extract_server_detail(response) is None

    def test_returns_none_for_request_exception(self) -> None:
        from ggshield.core.plugin.client import _extract_server_detail

        response = MagicMock()
        response.json.side_effect = requests.RequestException("network")
        assert _extract_server_detail(response) is None

    def test_returns_none_when_detail_missing_or_non_string(self) -> None:
        from ggshield.core.plugin.client import _extract_server_detail

        response = MagicMock()
        response.json.return_value = {"detail": 42}  # non-string
        assert _extract_server_detail(response) is None

        response.json.return_value = {"other": "field"}
        assert _extract_server_detail(response) is None

        response.json.return_value = ["just", "a", "list"]
        assert _extract_server_detail(response) is None


class TestDownloadPluginErrorPaths:
    """Tests for ``PluginAPIClient.download_plugin``'s validation branches."""

    @pytest.fixture
    def mock_gg_client(self) -> MagicMock:
        client = MagicMock()
        client.base_uri = "https://api.gitguardian.com/"
        client.api_key = "test-api-key"
        client.session = MagicMock()
        return client

    def _make_response(self, headers: dict, status_code: int = 200) -> MagicMock:
        response = MagicMock()
        response.status_code = status_code
        response.history = []
        response.url = "https://api.gitguardian.com/v1/endpoints/plugins/p/download"
        response.headers = headers
        response.iter_content.return_value = iter([b"wheel-bytes"])
        return response

    def test_raises_on_missing_sha256_header(self, mock_gg_client: MagicMock) -> None:
        """Server response without X-Plugin-SHA256 yields a PluginAPIError."""
        mock_gg_client.session.get.return_value = self._make_response(
            {
                "Content-Disposition": 'attachment; filename="p-1.0.0.whl"',
                "X-Plugin-Version": "1.0.0",
                "Content-Length": "10",
            }
        )

        client = PluginAPIClient(mock_gg_client)
        from ggshield.core.plugin.platform import PlatformInfo

        with pytest.raises(PluginAPIError, match="X-Plugin-SHA256"):
            with client.download_plugin(
                "p", platform_info=PlatformInfo("linux", "x86_64", "cp311")
            ):
                pass

    def test_raises_on_missing_version_header(self, mock_gg_client: MagicMock) -> None:
        """Server response without X-Plugin-Version yields a PluginAPIError."""
        mock_gg_client.session.get.return_value = self._make_response(
            {
                "Content-Disposition": 'attachment; filename="p-1.0.0.whl"',
                "X-Plugin-SHA256": "a" * 64,
                "Content-Length": "10",
            }
        )

        client = PluginAPIClient(mock_gg_client)
        from ggshield.core.plugin.platform import PlatformInfo

        with pytest.raises(PluginAPIError, match="X-Plugin-Version"):
            with client.download_plugin(
                "p", platform_info=PlatformInfo("linux", "x86_64", "cp311")
            ):
                pass

    def test_raises_when_content_length_exceeds_cap(
        self, mock_gg_client: MagicMock
    ) -> None:
        """Content-Length above MAX_WHEEL_SIZE_BYTES is rejected upfront."""
        from ggshield.core.plugin.client import MAX_WHEEL_SIZE_BYTES

        mock_gg_client.session.get.return_value = self._make_response(
            {
                "Content-Disposition": 'attachment; filename="p-1.0.0.whl"',
                "X-Plugin-SHA256": "a" * 64,
                "X-Plugin-Version": "1.0.0",
                "Content-Length": str(MAX_WHEEL_SIZE_BYTES + 1),
            }
        )

        client = PluginAPIClient(mock_gg_client)
        from ggshield.core.plugin.platform import PlatformInfo

        with pytest.raises(PluginAPIError, match="exceeds maximum"):
            with client.download_plugin(
                "p", platform_info=PlatformInfo("linux", "x86_64", "cp311")
            ):
                pass

    def test_wraps_request_exception(self, mock_gg_client: MagicMock) -> None:
        """A requests.RequestException becomes a PluginAPIError."""
        mock_gg_client.session.get.side_effect = requests.RequestException("boom")

        client = PluginAPIClient(mock_gg_client)
        from ggshield.core.plugin.platform import PlatformInfo

        with pytest.raises(PluginAPIError, match="Failed to download plugin"):
            with client.download_plugin(
                "p", platform_info=PlatformInfo("linux", "x86_64", "cp311")
            ):
                pass

    def test_passes_version_in_query(self, mock_gg_client: MagicMock) -> None:
        """``version=`` argument is forwarded as a query param."""
        mock_gg_client.session.get.return_value = self._make_response(
            {
                "Content-Disposition": 'attachment; filename="p-0.5.0.whl"',
                "X-Plugin-SHA256": "a" * 64,
                "X-Plugin-Version": "0.5.0",
                "Content-Length": "10",
            }
        )

        client = PluginAPIClient(mock_gg_client)
        from ggshield.core.plugin.platform import PlatformInfo

        with client.download_plugin(
            "p", platform_info=PlatformInfo("linux", "x86_64", "cp311"), version="0.5.0"
        ):
            pass

        call = mock_gg_client.session.get.call_args
        params = call.kwargs.get("params") or {}
        assert params.get("version") == "0.5.0"


class TestSecurityHelpers:
    """Tests for module-level security helpers."""

    def test_assert_all_https_rejects_http_redirect(self) -> None:
        """A redirect chain through HTTP raises PluginAPIError."""
        from ggshield.core.plugin.client import _assert_all_https

        hop = MagicMock()
        hop.url = "http://example.com/insecure"
        response = MagicMock()
        response.history = [hop]
        response.url = "https://example.com/final"

        with pytest.raises(PluginAPIError, match="insecure redirect"):
            _assert_all_https(response)

    def test_sanitize_wheel_filename_rejects_dotdot(self) -> None:
        """A wheel filename equal to ``..`` is rejected before becoming a path."""
        from ggshield.core.plugin.client import _sanitize_wheel_filename

        with pytest.raises(PluginAPIError, match="unsafe filename"):
            _sanitize_wheel_filename("..")

    def test_sanitize_wheel_filename_rejects_embedded_null(self) -> None:
        """A filename with NUL bytes is rejected."""
        from ggshield.core.plugin.client import _sanitize_wheel_filename

        with pytest.raises(PluginAPIError, match="unsafe filename"):
            _sanitize_wheel_filename("ok\x00.whl")

    def test_sanitize_wheel_filename_rejects_backslash(self) -> None:
        """Backslash in filename is rejected (Windows path separator)."""
        from ggshield.core.plugin.client import _sanitize_wheel_filename

        with pytest.raises(PluginAPIError, match="unsafe filename"):
            _sanitize_wheel_filename("evil\\path.whl")

    def test_iter_with_size_cap_raises_on_overflow(self) -> None:
        """Total bytes exceeding the cap raise PluginAPIError mid-stream."""
        from ggshield.core.plugin.client import _iter_with_size_cap

        gen = _iter_with_size_cap(iter([b"a" * 100, b"b" * 100]), max_bytes=150)
        # First chunk fits.
        next(gen)
        # Second chunk pushes total past the cap.
        with pytest.raises(PluginAPIError, match="exceeded maximum"):
            next(gen)
