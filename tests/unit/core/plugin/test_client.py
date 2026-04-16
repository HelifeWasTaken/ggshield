"""Tests for plugin API client."""

from unittest.mock import MagicMock, patch

import pytest
import requests

from ggshield.core.plugin.client import (
    PluginAPIClient,
    PluginAPIError,
    PluginCatalog,
    PluginDownloadInfo,
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
