"""Unit tests for URLhausProvider."""
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from app.services.providers.urlhaus import URLhausProvider
from app.services.providers.base import ProviderVerdictResult


@pytest.mark.asyncio
async def test_urlhaus_provider_clean_result():
    provider = URLhausProvider(api_key="test-key")
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "no_results"
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        result: ProviderVerdictResult = await provider.check_url("https://example.com")

        assert result.provider_name == "URLhaus (abuse.ch)"
        assert result.is_malicious is False
        assert result.detection_count == 0
        assert result.provider_status == "SUCCESS"
        assert "Clean" in result.category


@pytest.mark.asyncio
async def test_urlhaus_provider_malicious_result():
    provider = URLhausProvider(api_key="test-key")
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "query_status": "ok",
        "threat": "malware_download",
        "url_status": "online",
        "tags": ["elf", "mirai"],
        "payloads": [{"filename": "sample.bin", "response_md5": "abc"}]
    }

    with patch("httpx.AsyncClient.post", new_callable=AsyncMock) as mock_post:
        mock_post.return_value = mock_resp
        result: ProviderVerdictResult = await provider.check_url("https://malware.test/bot.bin")

        assert result.provider_name == "URLhaus (abuse.ch)"
        assert result.is_malicious is True
        assert result.detection_count >= 1
        assert result.provider_status == "SUCCESS"
        assert "Malware" in result.category
        assert "mirai" in result.category


@pytest.mark.asyncio
async def test_urlhaus_provider_rate_limit():
    provider = URLhausProvider(api_key="test-key", daily_request_limit=1)
    # trigger 1 request
    provider._increment_counter()
    assert provider.is_limit_reached() is True

    result: ProviderVerdictResult = await provider.check_url("https://example.com")
    assert result.provider_status == "RATE_LIMITED"
    assert result.is_malicious is False
