"""Tests for the main entry point module."""

import os
import sys
import pytest
from unittest.mock import patch, MagicMock

# Add project root to path so we can import main
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import main


REQUIRED_VARS = {
    "TARGETS": "https://dns.google/dns-query",
    "TEST_DOMAINS": "example.com|93.184.216.34",
    "SMTP_HOST": "smtp.example.com",
    "SMTP_PORT": "587",
    "SMTP_USER": "user",
    "SMTP_PASS": "pass",
    "SMTP_FROM": "from@example.com",
    "SMTP_TO": "to@example.com",
}


@pytest.fixture(autouse=True)
def clean_env():
    """Remove all project env vars before and after each test."""
    for var in list(REQUIRED_VARS) + [
        "PROBE_INTERVAL", "FAILURE_THRESHOLD", "RECOVERY_THRESHOLD", "DNS_SERVER",
        "DOT_HOSTNAME", "DOT_VERIFY_HOSTNAME",
    ]:
        os.environ.pop(var, None)
    yield
    for var in list(REQUIRED_VARS) + [
        "PROBE_INTERVAL", "FAILURE_THRESHOLD", "RECOVERY_THRESHOLD", "DNS_SERVER",
        "DOT_HOSTNAME", "DOT_VERIFY_HOSTNAME",
    ]:
        os.environ.pop(var, None)


# ---------------------------------------------------------------------------
# _load_env tests
# ---------------------------------------------------------------------------


class TestLoadEnv:
    def test_missing_required_exits(self):
        """Missing required env var causes sys.exit(1)."""
        # No env vars set — should exit
        with pytest.raises(SystemExit) as exc_info:
            main._load_env()
        assert exc_info.value.code == 1

    def test_missing_single_var_exits(self, caplog):
        """Missing even one required var causes failure."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v
        # Remove one
        os.environ.pop("SMTP_PORT")
        with pytest.raises(SystemExit) as exc_info:
            main._load_env()
        assert exc_info.value.code == 1
        assert "SMTP_PORT" in caplog.text

    def test_all_required_returns_config(self):
        """With all required vars set, returns a config dict."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v

        cfg = main._load_env()
        assert cfg["targets"] == "https://dns.google/dns-query"
        assert cfg["smtp_host"] == "smtp.example.com"
        assert cfg["smtp_port"] == 587

    def test_optional_defaults(self):
        """Optional vars default when not set."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v

        cfg = main._load_env()
        assert cfg["probe_interval"] == 300
        assert cfg["failure_threshold"] == 5
        assert cfg["recovery_threshold"] == 3
        assert cfg["dns_server"] == "1.1.1.1"

    def test_optional_custom_values(self):
        """Optional vars respect custom values."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v
        os.environ["PROBE_INTERVAL"] = "60"
        os.environ["FAILURE_THRESHOLD"] = "10"
        os.environ["RECOVERY_THRESHOLD"] = "7"
        os.environ["DNS_SERVER"] = "8.8.8.8"

        cfg = main._load_env()
        assert cfg["probe_interval"] == 60
        assert cfg["failure_threshold"] == 10
        assert cfg["recovery_threshold"] == 7
        assert cfg["dns_server"] == "8.8.8.8"

    def test_empty_string_is_missing(self):
        """Empty string for required var counts as missing."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v
        os.environ["SMTP_USER"] = ""  # empty string

        with pytest.raises(SystemExit) as exc_info:
            main._load_env()
        assert exc_info.value.code == 1

    def test_invalid_port_exits(self):
        """Non-numeric SMTP_PORT causes ValueError during int() cast."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v
        os.environ["SMTP_PORT"] = "not-a-number"

        with pytest.raises((ValueError, SystemExit)):
            main._load_env()


# ---------------------------------------------------------------------------
# _setup_logging tests
# ---------------------------------------------------------------------------


class TestSetupLogging:
    def test_sets_root_handler(self):
        """Logging setup adds a stdout handler to the root logger."""
        import logging
        root = logging.getLogger()
        old_handlers = root.handlers[:]
        try:
            main._setup_logging()
            # Should have added at least one handler
            assert len(root.handlers) >= 1
            last_handler = root.handlers[-1]
            assert isinstance(last_handler, logging.StreamHandler)
        finally:
            # Restore
            root.handlers = old_handlers


# ---------------------------------------------------------------------------
# main() integration tests
# ---------------------------------------------------------------------------


class TestMainLoop:
    @patch("main.time.sleep")
    @patch("main.probe_doh")
    @patch("main.probe_dot")
    def test_single_doh_probe_success(self, mock_dot, mock_doh, mock_sleep):
        """Single DoH target + single domain = one probe_doh call, then sleep."""
        os.environ["TARGETS"] = "https://dns.google/dns-query"
        os.environ["TEST_DOMAINS"] = "example.com|93.184.216.34"
        for k, v in REQUIRED_VARS.items():
            os.environ.setdefault(k, v)

        mock_doh.return_value = {
            "success": True,
            "actual_ip": "93.184.216.34",
            "response_time_ms": 42.0,
            "error": None,
        }
        mock_sleep.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit) as exc_info:
            main.main()
        assert exc_info.value.code == 0

        mock_doh.assert_called_once_with(
            target_url="https://dns.google/dns-query",
            domain="example.com",
            expected_ip="93.184.216.34",
        )
        mock_dot.assert_not_called()

    @patch("main.time.sleep")
    @patch("main.probe_doh")
    @patch("main.probe_dot")
    def test_single_dot_probe_success(self, mock_dot, mock_doh, mock_sleep):
        """Single DoT target + single domain = one probe_dot call, then sleep."""
        os.environ["TARGETS"] = "1.1.1.1:853"
        os.environ["TEST_DOMAINS"] = "example.com|93.184.216.34"
        for k, v in REQUIRED_VARS.items():
            os.environ.setdefault(k, v)

        mock_dot.return_value = {
            "success": True,
            "actual_ip": "93.184.216.34",
            "response_time_ms": 38.0,
            "error": None,
        }
        mock_sleep.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit) as exc_info:
            main.main()
        assert exc_info.value.code == 0

        mock_dot.assert_called_once()
        mock_doh.assert_not_called()

    @patch("main.time.sleep")
    @patch("main.probe_doh")
    @patch("main.probe_dot")
    def test_multiple_targets_and_domains(self, mock_dot, mock_doh, mock_sleep):
        """Multiple targets × multiple domains = correct number of probes."""
        os.environ["TARGETS"] = "https://dns.google/dns-query,1.1.1.1:853"
        os.environ["TEST_DOMAINS"] = "example.com|1.2.3.4,google.com|8.8.8.8"
        for k, v in REQUIRED_VARS.items():
            os.environ.setdefault(k, v)

        mock_doh.return_value = {
            "success": True, "actual_ip": "1.2.3.4",
            "response_time_ms": 10.0, "error": None,
        }
        mock_dot.return_value = {
            "success": True, "actual_ip": "1.2.3.4",
            "response_time_ms": 15.0, "error": None,
        }
        mock_sleep.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit):
            main.main()

        # 2 targets × 2 domains = 4 calls each type once per combo
        assert mock_doh.call_count == 2  # doh target × 2 domains
        assert mock_dot.call_count == 2   # dot target × 2 domains

    @patch("main.time.sleep")
    @patch("main.probe_doh")
    @patch("main.probe_dot")
    def test_failure_result(self, mock_dot, mock_doh, mock_sleep):
        """Failed probe logs FAIL and records failure in probe_state."""
        os.environ["TARGETS"] = "https://dns.google/dns-query"
        os.environ["TEST_DOMAINS"] = "example.com|93.184.216.34"
        for k, v in REQUIRED_VARS.items():
            os.environ.setdefault(k, v)

        mock_doh.return_value = {
            "success": False,
            "actual_ip": None,
            "response_time_ms": 5000.0,
            "error": "Timeout",
        }
        mock_sleep.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit) as exc_info:
            main.main()
        assert exc_info.value.code == 0

    @patch("main.time.sleep")
    @patch("main.probe_doh")
    @patch("main.probe_dot")
    def test_graceful_ctrl_c(self, mock_dot, mock_doh, mock_sleep):
        """KeyboardInterrupt triggers clean exit with code 0."""
        os.environ["TARGETS"] = "https://dns.google/dns-query"
        os.environ["TEST_DOMAINS"] = "example.com|93.184.216.34"
        for k, v in REQUIRED_VARS.items():
            os.environ.setdefault(k, v)

        mock_doh.return_value = {
            "success": True, "actual_ip": "93.184.216.34",
            "response_time_ms": 10.0, "error": None,
        }
        mock_sleep.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit) as exc_info:
            main.main()
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_targets_string_exits(self):
        """TARGETS set but empty — parse_target fails."""
        os.environ["TARGETS"] = ""
        for k, v in REQUIRED_VARS.items():
            os.environ.setdefault(k, v)
        # Empty string is missing (truthy check), so should exit
        with pytest.raises(SystemExit) as exc_info:
            main._load_env()
        assert exc_info.value.code == 1

    @patch("main.time.sleep")
    @patch("main.probe_doh")
    @patch("main.probe_dot")
    def test_dot_host_default_port(self, mock_dot, mock_doh, mock_sleep):
        """DoT target without explicit port defaults to 853."""
        os.environ["TARGETS"] = "dns.google"
        os.environ["TEST_DOMAINS"] = "example.com|93.184.216.34"
        for k, v in REQUIRED_VARS.items():
            os.environ.setdefault(k, v)

        mock_dot.return_value = {
            "success": True, "actual_ip": "93.184.216.34",
            "response_time_ms": 20.0, "error": None,
        }
        mock_sleep.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit):
            main.main()

        mock_dot.assert_called_once()
        call_kwargs = mock_dot.call_args[1]
        assert call_kwargs["host"] == "dns.google"
        assert call_kwargs["port"] == 853

    @patch("main.time.sleep")
    @patch("main.probe_doh")
    @patch("main.probe_dot")
    def test_doh_failure_logs_timeout(self, mock_dot, mock_doh, mock_sleep):
        """DoH probe with error=None (timeout) logs TIMEOUT."""
        os.environ["TARGETS"] = "https://dns.google/dns-query"
        os.environ["TEST_DOMAINS"] = "example.com|93.184.216.34"
        for k, v in REQUIRED_VARS.items():
            os.environ.setdefault(k, v)

        mock_doh.return_value = {
            "success": False, "actual_ip": None,
            "response_time_ms": 0.0, "error": None,
        }
        mock_sleep.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit):
            main.main()

    @patch("main.time.sleep")
    @patch("main.probe_doh")
    @patch("main.probe_dot")
    def test_probe_interval_is_respected(self, mock_dot, mock_doh, mock_sleep):
        """Custom PROBE_INTERVAL is used for sleep duration."""
        os.environ["TARGETS"] = "https://dns.google/dns-query"
        os.environ["TEST_DOMAINS"] = "example.com|93.184.216.34"
        os.environ["PROBE_INTERVAL"] = "42"
        for k, v in REQUIRED_VARS.items():
            os.environ.setdefault(k, v)

        mock_doh.return_value = {
            "success": True, "actual_ip": "93.184.216.34",
            "response_time_ms": 5.0, "error": None,
        }
        mock_sleep.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit):
            main.main()

        # Sleep should have been called with the custom interval before being
        # interrupted
        mock_sleep.assert_called()
        first_call = mock_sleep.call_args_list[0]
        assert first_call[0][0] == 42


# ---------------------------------------------------------------------------
# DOT_HOSTNAME / DOT_VERIFY_HOSTNAME tests
# ---------------------------------------------------------------------------


class TestDotTlsConfig:
    def test_dot_hostname_defaults_to_none(self):
        """DOT_HOSTNAME not set defaults to None in config."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v
        cfg = main._load_env()
        assert cfg["dot_hostname"] is None

    def test_dot_hostname_custom_value(self):
        """DOT_HOSTNAME is loaded when set."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v
        os.environ["DOT_HOSTNAME"] = "dns1.example.com"
        cfg = main._load_env()
        assert cfg["dot_hostname"] == "dns1.example.com"

    def test_dot_hostname_empty_string_becomes_none(self):
        """DOT_HOSTNAME set to empty string resolves to None."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v
        os.environ["DOT_HOSTNAME"] = ""
        cfg = main._load_env()
        assert cfg["dot_hostname"] is None

    def test_dot_verify_hostname_defaults_to_true(self):
        """DOT_VERIFY_HOSTNAME not set defaults to True."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v
        cfg = main._load_env()
        assert cfg["dot_verify_hostname"] is True

    def test_dot_verify_hostname_false(self):
        """DOT_VERIFY_HOSTNAME=false results in False."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v
        os.environ["DOT_VERIFY_HOSTNAME"] = "false"
        cfg = main._load_env()
        assert cfg["dot_verify_hostname"] is False

    def test_dot_verify_hostname_case_insensitive(self):
        """DOT_VERIFY_HOSTNAME=False (uppercase) still results in False."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v
        os.environ["DOT_VERIFY_HOSTNAME"] = "False"
        cfg = main._load_env()
        assert cfg["dot_verify_hostname"] is False

    def test_dot_verify_hostname_true_explicit(self):
        """DOT_VERIFY_HOSTNAME=true explicitly is still True."""
        for k, v in REQUIRED_VARS.items():
            os.environ[k] = v
        os.environ["DOT_VERIFY_HOSTNAME"] = "true"
        cfg = main._load_env()
        assert cfg["dot_verify_hostname"] is True

    @patch("main.time.sleep")
    @patch("main.probe_doh")
    @patch("main.probe_dot")
    def test_dot_hostname_passed_to_probe_dot(self, mock_dot, mock_doh, mock_sleep):
        """DOT_HOSTNAME is passed through to probe_dot."""
        os.environ["TARGETS"] = "188.245.192.196:853"
        os.environ["TEST_DOMAINS"] = "example.com|93.184.216.34"
        os.environ["DOT_HOSTNAME"] = "dns1.example.com"
        for k, v in REQUIRED_VARS.items():
            os.environ.setdefault(k, v)

        mock_dot.return_value = {
            "success": True, "actual_ip": "93.184.216.34",
            "response_time_ms": 42.0, "error": None,
        }
        mock_sleep.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit):
            main.main()

        mock_dot.assert_called_once()
        call_kwargs = mock_dot.call_args[1]
        assert call_kwargs["dot_hostname"] == "dns1.example.com"
        assert call_kwargs["dot_verify_hostname"] is True

    @patch("main.time.sleep")
    @patch("main.probe_doh")
    @patch("main.probe_dot")
    def test_dot_verify_hostname_false_passed(self, mock_dot, mock_doh, mock_sleep):
        """DOT_VERIFY_HOSTNAME=false is passed through to probe_dot."""
        os.environ["TARGETS"] = "188.245.192.196:853"
        os.environ["TEST_DOMAINS"] = "example.com|93.184.216.34"
        os.environ["DOT_VERIFY_HOSTNAME"] = "false"
        for k, v in REQUIRED_VARS.items():
            os.environ.setdefault(k, v)

        mock_dot.return_value = {
            "success": True, "actual_ip": "93.184.216.34",
            "response_time_ms": 42.0, "error": None,
        }
        mock_sleep.side_effect = KeyboardInterrupt

        with pytest.raises(SystemExit):
            main.main()

        mock_dot.assert_called_once()
        call_kwargs = mock_dot.call_args[1]
        assert call_kwargs["dot_hostname"] is None
        assert call_kwargs["dot_verify_hostname"] is False
