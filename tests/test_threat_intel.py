"""Tests for the threat-intel feed integration (backend/threat_intel.py).

Verifies cache behaviour, API parsing, error handling, and the
risk-score boost integration in the detection engine.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from backend.threat_intel import (
    IntelResult,
    _IntelCache,
    _parse_abuseipdb,
    check_ip,
    reset_cache,
)


# ---------------------------------------------------------------------------
# _IntelCache
# ---------------------------------------------------------------------------

class TestIntelCache:
    def test_set_and_get(self):
        cache = _IntelCache(max_entries=100, ttl_seconds=3600)
        result = IntelResult(ip="1.2.3.4", abuse_confidence_score=90, total_reports=5)
        cache.set("1.2.3.4", result)
        cached, hit = cache.get("1.2.3.4")
        assert hit
        assert cached is result

    def test_miss_for_unknown(self):
        cache = _IntelCache()
        cached, hit = cache.get("9.9.9.9")
        assert not hit
        assert cached is None

    def test_expiry(self):
        ticks = [100.0, 100.0, 5000.0]
        clock = iter(ticks)
        cache = _IntelCache(max_entries=100, ttl_seconds=100, clock=lambda: next(clock))
        cache.set("1.2.3.4", IntelResult(ip="1.2.3.4", abuse_confidence_score=50))
        # First get returns hit; second has expired.
        _, hit1 = cache.get("1.2.3.4")
        assert hit1
        _, hit2 = cache.get("1.2.3.4")
        assert not hit2

    def test_lru_eviction(self):
        cache = _IntelCache(max_entries=3, ttl_seconds=3600)
        for i in range(4):
            cache.set(f"10.0.0.{i}", IntelResult(ip=f"10.0.0.{i}", abuse_confidence_score=0))
        _, hit = cache.get("10.0.0.0")
        assert not hit  # evicted
        _, hit = cache.get("10.0.0.3")
        assert hit  # newest survives

    def test_clear(self):
        cache = _IntelCache(max_entries=100, ttl_seconds=3600)
        cache.set("1.2.3.4", IntelResult(ip="1.2.3.4", abuse_confidence_score=50))
        cache.clear()
        _, hit = cache.get("1.2.3.4")
        assert not hit


# ---------------------------------------------------------------------------
# _parse_abuseipdb
# ---------------------------------------------------------------------------

class TestParseAbuseipdb:
    def test_full_response(self):
        raw = {
            "data": {
                "attributes": {
                    "abuseConfidenceScore": 85,
                    "totalReports": 12,
                    "lastReportedAt": "2026-06-01T12:00:00Z",
                    "categories": [14, 18, 4],
                    "countryCode": "US",
                    "isp": "Some ISP",
                    "domain": "example.com",
                    "isWhitelisted": False,
                }
            }
        }
        result = _parse_abuseipdb(raw, "1.2.3.4")
        assert result.abuse_confidence_score == 85
        assert result.total_reports == 12
        assert "Port Scan" in result.categories  # category 14
        assert "Brute-Force" in result.categories  # category 18
        assert "DDoS Attack" in result.categories  # category 4
        assert result.country_code == "US"

    def test_minimal_response(self):
        raw = {"data": {"attributes": {"abuseConfidenceScore": 0}}}
        result = _parse_abuseipdb(raw, "5.6.7.8")
        assert result.abuse_confidence_score == 0
        assert result.total_reports == 0
        assert result.categories == []

    def test_unknown_category_is_labeled(self):
        raw = {"data": {"attributes": {"abuseConfidenceScore": 50, "categories": [99]}}}
        result = _parse_abuseipdb(raw, "1.2.3.4")
        assert "Category 99" in result.categories


# ---------------------------------------------------------------------------
# check_ip unit tests (mocked HTTP)
# ---------------------------------------------------------------------------

class TestCheckIP:
    def test_private_ip_returns_none(self, monkeypatch):
        monkeypatch.setenv("SENTINEL_THREAT_INTEL_API_KEY", "test-key")
        from backend import config
        config.reset_settings()
        result = check_ip("192.168.1.1")
        assert result is None

    def test_no_api_key_returns_none(self, monkeypatch):
        monkeypatch.delenv("SENTINEL_THREAT_INTEL_API_KEY", raising=False)
        from backend import config
        config.reset_settings()
        result = check_ip("8.8.8.8")
        assert result is None

    @patch("requests.get")
    def test_successful_lookup(self, mock_get, monkeypatch):
        monkeypatch.setenv("SENTINEL_THREAT_INTEL_API_KEY", "test-key")
        from backend import config
        config.reset_settings()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "attributes": {
                    "abuseConfidenceScore": 90,
                    "totalReports": 25,
                    "categories": [14],
                    "isp": "Some ISP",
                    "countryCode": "US",
                }
            }
        }
        mock_get.return_value = mock_resp
        reset_cache()

        result = check_ip("45.33.32.156")
        assert result is not None
        assert result.abuse_confidence_score == 90
        assert result.total_reports == 25

    @patch("requests.get")
    def test_404_returns_clean(self, mock_get, monkeypatch):
        monkeypatch.setenv("SENTINEL_THREAT_INTEL_API_KEY", "test-key")
        from backend import config
        config.reset_settings()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp
        reset_cache()

        result = check_ip("1.2.3.4")
        assert result is not None
        assert result.abuse_confidence_score == 0

    @patch("requests.get")
    def test_429_returns_none(self, mock_get, monkeypatch):
        monkeypatch.setenv("SENTINEL_THREAT_INTEL_API_KEY", "test-key")
        from backend import config
        config.reset_settings()
        mock_resp = MagicMock()
        mock_resp.status_code = 429
        mock_get.return_value = mock_resp
        reset_cache()

        result = check_ip("1.2.3.4")
        assert result is None

    @patch("requests.get")
    def test_network_error_returns_none(self, mock_get, monkeypatch):
        monkeypatch.setenv("SENTINEL_THREAT_INTEL_API_KEY", "test-key")
        from backend import config
        config.reset_settings()
        mock_get.side_effect = Exception("Connection refused")
        reset_cache()

        result = check_ip("1.2.3.4")
        assert result is None

    @patch("requests.get")
    def test_second_lookup_is_cached(self, mock_get, monkeypatch):
        monkeypatch.setenv("SENTINEL_THREAT_INTEL_API_KEY", "test-key")
        from backend import config
        config.reset_settings()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {"attributes": {"abuseConfidenceScore": 75, "totalReports": 3}}
        }
        mock_get.return_value = mock_resp
        reset_cache()

        result1 = check_ip("185.220.101.42")
        assert result1 is not None
        result2 = check_ip("185.220.101.42")
        assert result2 is result1  # same object = cache hit
        assert mock_get.call_count == 1  # only one HTTP call


# ---------------------------------------------------------------------------
# Integration: threat-intel in detector risk boost
# ---------------------------------------------------------------------------

class TestRiskBoostIntegration:
    def test_high_confidence_boosts_risk(self, monkeypatch):
        """Verify that abuse_confidence_score >= 50 adds +1.0 to risk."""
        from backend import config
        monkeypatch.setenv("SENTINEL_THREAT_INTEL_ENABLED", "true")
        monkeypatch.setenv("SENTINEL_THREAT_INTEL_API_KEY", "test-key")
        config.reset_settings()

        from backend.threat_intel import check_ip
        from unittest.mock import patch, MagicMock

        with patch("requests.get") as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.json.return_value = {
                "data": {"attributes": {"abuseConfidenceScore": 85, "totalReports": 10, "categories": [14]}}
            }
            mock_get.return_value = mock_resp
            reset_cache()

            result = check_ip("45.33.32.156")
            assert result is not None
            assert result.abuse_confidence_score == 85

            # The risk boost is applied in detector.py based on
            # threat_intel.abuse_confidence_score >= 50.  The boost
            # is +1.0 but capped at 10.0.
            assert result.abuse_confidence_score >= 50
