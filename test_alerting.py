"""Tests for alerting module — covers AlertManager, ProbeState, and email templates."""

import logging
import smtplib
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, call

from alerting import (
    AlertManager,
    ProbeState,
    alert_subject,
    alert_body,
    consolidated_alert_subject,
    consolidated_alert_body,
    recovery_subject,
    recovery_body,
)


# ---------------------------------------------------------------------------
# Email template tests
# ---------------------------------------------------------------------------

class TestAlertSubject:
    def test_format(self):
        result = alert_subject("https://dns.google/dns-query")
        assert result == "[DOH-MONITOR] ALERT: https://dns.google/dns-query failing"

    def test_with_dot_target(self):
        result = alert_subject("1.1.1.1:853")
        assert result == "[DOH-MONITOR] ALERT: 1.1.1.1:853 failing"


class TestConsolidatedAlertSubject:
    def test_format_single(self):
        result = consolidated_alert_subject(1)
        assert result == "[DOH-MONITOR] ALERT: 1 target(s) failing"

    def test_format_multiple(self):
        result = consolidated_alert_subject(5)
        assert result == "[DOH-MONITOR] ALERT: 5 target(s) failing"


class TestAlertBody:
    def test_contains_all_fields(self):
        since = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
        body = alert_body(
            target="https://dns.google/dns-query",
            domain="example.com",
            expected_ip="93.184.216.34",
            actual_info="TIMEOUT",
            consecutive_failures=7,
            since=since,
        )
        assert "https://dns.google/dns-query" in body
        assert "example.com" in body
        assert "93.184.216.34" in body
        assert "TIMEOUT" in body
        assert "7" in body
        assert "2026-06-19 12:00:00 UTC" in body

    def test_with_actual_ip(self):
        since = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
        body = alert_body(
            target="1.1.1.1:853",
            domain="example.com",
            expected_ip="93.184.216.34",
            actual_info="1.2.3.4",
            consecutive_failures=5,
            since=since,
        )
        assert "1.2.3.4" in body
        assert "TIMEOUT" not in body


class TestConsolidatedAlertBody:
    def test_single_target(self):
        since = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
        alerts = [
            {
                "target": "https://dns.google/dns-query",
                "domain": "example.com",
                "expected_ip": "93.184.216.34",
                "actual_info": "TIMEOUT",
                "consecutive_failures": 5,
                "since": since,
            },
        ]
        body = consolidated_alert_body(alerts)
        assert "1 target(s) failing" in body
        assert "https://dns.google/dns-query" in body
        assert "example.com" in body
        assert "93.184.216.34" in body
        assert "TIMEOUT" in body
        assert "5" in body
        assert "2026-06-19 12:00:00 UTC" in body

    def test_multiple_targets(self):
        since = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
        alerts = [
            {
                "target": "https://dns.google/dns-query",
                "domain": "example.com",
                "expected_ip": "93.184.216.34",
                "actual_info": "TIMEOUT",
                "consecutive_failures": 5,
                "since": since,
            },
            {
                "target": "1.1.1.1:853",
                "domain": "other.com",
                "expected_ip": "5.6.7.8",
                "actual_info": "1.2.3.4",
                "consecutive_failures": 3,
                "since": since,
            },
        ]
        body = consolidated_alert_body(alerts)
        assert "2 target(s) failing" in body
        assert "https://dns.google/dns-query" in body
        assert "1.1.1.1:853" in body
        assert "example.com" in body
        assert "other.com" in body

    def test_format_matches_spec(self):
        """Verify the exact format matches the task specification."""
        since = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
        alerts = [
            {
                "target": "https://dns.google/dns-query",
                "domain": "example.com",
                "expected_ip": "93.184.216.34",
                "actual_info": "TIMEOUT",
                "consecutive_failures": 5,
                "since": since,
            },
        ]
        body = consolidated_alert_body(alerts)
        # Verify the per-target format: Domain: ... | Expected: ... | Got: ...
        assert "Domain: example.com | Expected: 93.184.216.34 | Got: TIMEOUT" in body
        # Verify footer format
        assert "Consecutive Failures: 5 | Since: 2026-06-19 12:00:00 UTC" in body


class TestRecoverySubject:
    def test_format(self):
        result = recovery_subject("https://dns.google/dns-query")
        assert result == "[DOH-MONITOR] RECOVERED: https://dns.google/dns-query"

    def test_with_dot_target(self):
        result = recovery_subject("1.1.1.1:853")
        assert result == "[DOH-MONITOR] RECOVERED: 1.1.1.1:853"


class TestRecoveryBody:
    def test_contains_all_fields(self):
        body = recovery_body(
            target="https://dns.google/dns-query",
            domain="example.com",
            expected_ip="93.184.216.34",
            actual_ip="93.184.216.34",
            consecutive_successes=3,
        )
        assert "https://dns.google/dns-query" in body
        assert "example.com" in body
        assert "93.184.216.34" in body
        assert "3" in body


# ---------------------------------------------------------------------------
# AlertManager tests
# ---------------------------------------------------------------------------

class TestAlertManagerInit:
    def test_defaults(self):
        am = AlertManager(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
        )
        assert am.smtp_host == "smtp.example.com"
        assert am.smtp_port == 587
        assert am.failure_threshold == 5
        assert am.recovery_threshold == 3

    def test_custom_thresholds(self):
        am = AlertManager(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
            failure_threshold=10,
            recovery_threshold=5,
        )
        assert am.failure_threshold == 10
        assert am.recovery_threshold == 5


class TestAlertManagerSendEmail:
    @patch("alerting.smtplib.SMTP")
    def test_successful_send(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = AlertManager(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
        )

        result = am._send_email("Test Subject", "Test Body")
        assert result is True
        mock_server.ehlo.assert_called()
        mock_server.starttls.assert_called()
        mock_server.login.assert_called_with("user", "pass")
        mock_server.sendmail.assert_called_once()

    @patch("alerting.smtplib.SMTP")
    def test_smtp_error_returns_false(self, MockSMTP):
        mock_server = MagicMock()
        mock_server.sendmail.side_effect = smtplib.SMTPException("send failed")
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = AlertManager(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
        )

        result = am._send_email("Test Subject", "Test Body")
        assert result is False

    @patch("alerting.smtplib.SMTP")
    def test_connection_error_returns_false(self, MockSMTP):
        MockSMTP.side_effect = OSError("Connection refused")

        am = AlertManager(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
        )

        result = am._send_email("Test Subject", "Test Body")
        assert result is False

    @patch("alerting.smtplib.SMTP")
    def test_unexpected_exception_returns_false(self, MockSMTP):
        MockSMTP.side_effect = RuntimeError("something weird")

        am = AlertManager(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
        )

        result = am._send_email("Test Subject", "Test Body")
        assert result is False


class TestAlertManagerSendAlert:
    @patch("alerting.smtplib.SMTP")
    def test_send_alert(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = AlertManager(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
        )

        since = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
        result = am.send_alert(
            target="https://dns.google/dns-query",
            domain="example.com",
            expected_ip="93.184.216.34",
            actual_info="TIMEOUT",
            consecutive_failures=5,
            since=since,
        )
        assert result is True
        # Verify the email was sent with correct subject
        sendmail_args = mock_server.sendmail.call_args
        assert "[DOH-MONITOR] ALERT" in sendmail_args[0][2]


class TestAlertManagerSendConsolidatedAlert:
    @patch("alerting.smtplib.SMTP")
    def test_send_single_target(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = AlertManager(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
        )

        since = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
        alerts = [
            {
                "target": "https://dns.google/dns-query",
                "domain": "example.com",
                "expected_ip": "93.184.216.34",
                "actual_info": "TIMEOUT",
                "consecutive_failures": 5,
                "since": since,
            },
        ]
        result = am.send_consolidated_alert(alerts)
        assert result is True
        sendmail_args = mock_server.sendmail.call_args
        assert "[DOH-MONITOR] ALERT: 1 target(s) failing" in sendmail_args[0][2]

    @patch("alerting.smtplib.SMTP")
    def test_send_multiple_targets(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = AlertManager(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
        )

        since = datetime(2026, 6, 19, 12, 0, 0, tzinfo=timezone.utc)
        alerts = [
            {
                "target": "target1",
                "domain": "example.com",
                "expected_ip": "1.2.3.4",
                "actual_info": "TIMEOUT",
                "consecutive_failures": 5,
                "since": since,
            },
            {
                "target": "target2",
                "domain": "other.com",
                "expected_ip": "5.6.7.8",
                "actual_info": "TIMEOUT",
                "consecutive_failures": 3,
                "since": since,
            },
        ]
        result = am.send_consolidated_alert(alerts)
        assert result is True
        sendmail_args = mock_server.sendmail.call_args
        assert "[DOH-MONITOR] ALERT: 2 target(s) failing" in sendmail_args[0][2]
        # Both targets should be in the email body
        assert "target1" in sendmail_args[0][2]
        assert "target2" in sendmail_args[0][2]

    @patch("alerting.smtplib.SMTP")
    def test_send_empty_alerts_returns_true(self, MockSMTP):
        am = AlertManager(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
        )
        result = am.send_consolidated_alert([])
        assert result is True
        # No email should be sent
        MockSMTP.assert_not_called()


class TestAlertManagerSendRecovery:
    @patch("alerting.smtplib.SMTP")
    def test_send_recovery(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = AlertManager(
            smtp_host="smtp.example.com",
            smtp_port=587,
            smtp_user="user",
            smtp_pass="pass",
            smtp_from="from@example.com",
            smtp_to="to@example.com",
        )

        result = am.send_recovery(
            target="https://dns.google/dns-query",
            domain="example.com",
            expected_ip="93.184.216.34",
            actual_ip="93.184.216.34",
            consecutive_successes=3,
        )
        assert result is True
        sendmail_args = mock_server.sendmail.call_args
        assert "[DOH-MONITOR] RECOVERED" in sendmail_args[0][2]


# ---------------------------------------------------------------------------
# ProbeState tests
# ---------------------------------------------------------------------------

def _make_alert_manager(failure_threshold=5, recovery_threshold=3):
    """Create a real AlertManager with mocked SMTP for testing."""
    am = AlertManager(
        smtp_host="smtp.example.com",
        smtp_port=587,
        smtp_user="user",
        smtp_pass="pass",
        smtp_from="from@example.com",
        smtp_to="to@example.com",
        failure_threshold=failure_threshold,
        recovery_threshold=recovery_threshold,
    )
    return am


class TestProbeStateRecordFailure:
    @patch("alerting.smtplib.SMTP")
    def test_increments_consecutive_failures(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=5)
        ps = ProbeState(am)

        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        state = ps.get_state("target1", "example.com")
        assert state["consecutive_failures"] == 1
        assert state["consecutive_successes"] == 0

    @patch("alerting.smtplib.SMTP")
    def test_resets_success_counter(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=5, recovery_threshold=3)
        ps = ProbeState(am)

        # Build up some successes first
        ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")
        ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")
        state = ps.get_state("target1", "example.com")
        assert state["consecutive_successes"] == 2

        # Now fail — should reset success counter
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        state = ps.get_state("target1", "example.com")
        assert state["consecutive_successes"] == 0
        assert state["consecutive_failures"] == 1

    @patch("alerting.smtplib.SMTP")
    def test_queues_alert_at_threshold(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=3, recovery_threshold=3)
        ps = ProbeState(am)

        # 2 failures — no alert yet
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.record_failure("target1", "example.com", "1.2.3.4", "1.2.3.5")
        assert mock_server.sendmail.call_count == 0
        assert len(ps._pending_alerts) == 0

        # 3rd failure — alert should be queued
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        assert len(ps._pending_alerts) == 1
        state = ps.get_state("target1", "example.com")
        assert state["alert_sent"] is True

    @patch("alerting.smtplib.SMTP")
    def test_does_not_queue_alert_before_threshold(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=5, recovery_threshold=3)
        ps = ProbeState(am)

        for i in range(4):
            ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")

        assert len(ps._pending_alerts) == 0

    @patch("alerting.smtplib.SMTP")
    def test_does_not_queue_alert_twice(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=3, recovery_threshold=3)
        ps = ProbeState(am)

        # Reach threshold
        for i in range(3):
            ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        assert len(ps._pending_alerts) == 1

        # More failures — should NOT queue another alert
        for i in range(3):
            ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        assert len(ps._pending_alerts) == 1

    @patch("alerting.smtplib.SMTP")
    def test_sets_last_failure_time(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager()
        ps = ProbeState(am)

        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        state = ps.get_state("target1", "example.com")
        assert state["last_failure_time"] is not None
        assert isinstance(state["last_failure_time"], datetime)

    @patch("alerting.smtplib.SMTP")
    def test_stores_actual_info(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager()
        ps = ProbeState(am)

        ps.record_failure("target1", "example.com", "1.2.3.4", "1.2.3.5")
        state = ps.get_state("target1", "example.com")
        assert state["last_actual_ip"] == "1.2.3.5"

    @patch("alerting.smtplib.SMTP")
    def test_sets_last_alert_time_on_threshold(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=3)
        ps = ProbeState(am)

        # Before threshold — no last_alert_time
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        state = ps.get_state("target1", "example.com")
        assert state["last_alert_time"] is None

        # At threshold — last_alert_time should be set
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        state = ps.get_state("target1", "example.com")
        assert state["last_alert_time"] is not None
        assert isinstance(state["last_alert_time"], datetime)

    @patch("alerting.smtplib.SMTP")
    def test_debug_logging_on_every_failure(self, MockSMTP, caplog):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=3, recovery_threshold=3)
        ps = ProbeState(am)

        with caplog.at_level(logging.DEBUG, logger="doh-healthchecker"):
            ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
            ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
            ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")

        # Should have 3 debug log entries
        debug_msgs = [r for r in caplog.records if r.levelno == logging.DEBUG]
        assert len(debug_msgs) == 3

        # First log should show consecutive_failures=1
        assert "consecutive_failures=1" in debug_msgs[0].message
        assert "alert_sent=False" in debug_msgs[0].message
        assert "failure_threshold=3" in debug_msgs[0].message

        # Third log (at threshold) should show alert_sent switching
        assert "consecutive_failures=3" in debug_msgs[2].message


class TestProbeStateRecordSuccess:
    @patch("alerting.smtplib.SMTP")
    def test_increments_consecutive_successes(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager()
        ps = ProbeState(am)

        ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")
        state = ps.get_state("target1", "example.com")
        assert state["consecutive_successes"] == 1
        assert state["consecutive_failures"] == 0

    @patch("alerting.smtplib.SMTP")
    def test_resets_failure_counter(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=5, recovery_threshold=3)
        ps = ProbeState(am)

        # Build up failures
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        state = ps.get_state("target1", "example.com")
        assert state["consecutive_failures"] == 2

        # Now succeed — should reset failure counter
        ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")
        state = ps.get_state("target1", "example.com")
        assert state["consecutive_failures"] == 0
        assert state["consecutive_successes"] == 1

    @patch("alerting.smtplib.SMTP")
    def test_sends_recovery_at_threshold_after_alert(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=2)
        ps = ProbeState(am)

        # Fail twice to trigger alert
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        # Flush the consolidated alert
        ps.flush_pending_alerts()
        state = ps.get_state("target1", "example.com")
        assert state["alert_sent"] is True

        # 1 success — no recovery yet
        ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")
        assert mock_server.sendmail.call_count == 1  # only the alert

        # 2nd success — recovery should fire
        ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")
        assert mock_server.sendmail.call_count == 2

        # Verify recovery email was sent
        state = ps.get_state("target1", "example.com")
        assert state["alert_sent"] is False
        assert state["consecutive_failures"] == 0
        assert state["consecutive_successes"] == 0

    @patch("alerting.smtplib.SMTP")
    def test_does_not_send_recovery_without_prior_alert(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=5, recovery_threshold=3)
        ps = ProbeState(am)

        # Multiple successes but no alert was sent
        for i in range(5):
            ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")

        # No emails should have been sent at all
        assert mock_server.sendmail.call_count == 0

    @patch("alerting.smtplib.SMTP")
    def test_stores_actual_ip(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager()
        ps = ProbeState(am)

        ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")
        state = ps.get_state("target1", "example.com")
        assert state["last_actual_ip"] == "1.2.3.4"
        assert state["expected_ip"] == "1.2.3.4"


class TestProbeStateMultipleTargets:
    @patch("alerting.smtplib.SMTP")
    def test_independent_state_per_target(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=3, recovery_threshold=3)
        ps = ProbeState(am)

        # Fail target1 twice
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")

        # Fail target2 once
        ps.record_failure("target2", "example.com", "5.6.7.8", "TIMEOUT")

        # Verify independent counts
        s1 = ps.get_state("target1", "example.com")
        s2 = ps.get_state("target2", "example.com")
        assert s1["consecutive_failures"] == 2
        assert s2["consecutive_failures"] == 1

    @patch("alerting.smtplib.SMTP")
    def test_independent_state_per_domain(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=3, recovery_threshold=3)
        ps = ProbeState(am)

        # Same target, different domains
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.record_failure("target1", "other.com", "5.6.7.8", "TIMEOUT")

        s1 = ps.get_state("target1", "example.com")
        s2 = ps.get_state("target1", "other.com")
        assert s1["consecutive_failures"] == 1
        assert s2["consecutive_failures"] == 1

    @patch("alerting.smtplib.SMTP")
    def test_alert_only_for_threshold_target(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=3, recovery_threshold=3)
        ps = ProbeState(am)

        # Target1 reaches threshold
        for i in range(3):
            ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")

        # Target2 has 2 failures (below threshold)
        ps.record_failure("target2", "example.com", "5.6.7.8", "TIMEOUT")
        ps.record_failure("target2", "example.com", "5.6.7.8", "TIMEOUT")

        # Only 1 pending alert (for target1)
        assert len(ps._pending_alerts) == 1

        # Target2 alert_sent should be False
        s2 = ps.get_state("target2", "example.com")
        assert s2["alert_sent"] is False


class TestProbeStateConsolidatedAlerts:
    @patch("alerting.smtplib.SMTP")
    def test_multiple_targets_in_one_cycle(self, MockSMTP):
        """Multiple targets reaching threshold in one cycle produce one email."""
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=3)
        ps = ProbeState(am)

        # Both targets reach threshold in the same "cycle"
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.record_failure("target2", "example.com", "5.6.7.8", "TIMEOUT")
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.record_failure("target2", "example.com", "5.6.7.8", "TIMEOUT")

        # Both should be queued
        assert len(ps._pending_alerts) == 2

        # Flush should send ONE consolidated email
        ps.flush_pending_alerts()
        assert mock_server.sendmail.call_count == 1

        # Verify the email subject mentions both targets
        sendmail_args = mock_server.sendmail.call_args
        assert "2 target(s) failing" in sendmail_args[0][2]
        assert "target1" in sendmail_args[0][2]
        assert "target2" in sendmail_args[0][2]

    @patch("alerting.smtplib.SMTP")
    def test_flush_clears_pending_queue(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=3)
        ps = ProbeState(am)

        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        assert len(ps._pending_alerts) == 1

        ps.flush_pending_alerts()
        assert len(ps._pending_alerts) == 0

    @patch("alerting.smtplib.SMTP")
    def test_flush_with_no_pending_alerts(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager()
        ps = ProbeState(am)

        # No failures recorded
        result = ps.flush_pending_alerts()
        assert result is True
        assert mock_server.sendmail.call_count == 0

    @patch("alerting.smtplib.SMTP")
    def test_reblocking_after_recovery_re_alerts(self, MockSMTP):
        """After recovery, new failures should trigger a new alert."""
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=2)
        ps = ProbeState(am)

        # First failure cycle
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.flush_pending_alerts()
        assert mock_server.sendmail.call_count == 1

        # Recovery
        ps.record_success("t", "d", "1.2.3.4", "1.2.3.4")
        ps.record_success("t", "d", "1.2.3.4", "1.2.3.4")
        assert mock_server.sendmail.call_count == 2

        # New failure cycle — should re-alert
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.flush_pending_alerts()
        assert mock_server.sendmail.call_count == 3

    @patch("alerting.smtplib.SMTP")
    def test_last_alert_time_cleared_on_recovery(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=2)
        ps = ProbeState(am)

        # Trigger alert
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.flush_pending_alerts()
        state = ps.get_state("t", "d")
        assert state["last_alert_time"] is not None

        # Recovery
        ps.record_success("t", "d", "1.2.3.4", "1.2.3.4")
        ps.record_success("t", "d", "1.2.3.4", "1.2.3.4")
        state = ps.get_state("t", "d")
        assert state["last_alert_time"] is None

    @patch("alerting.smtplib.SMTP")
    def test_alert_suppressed_logging(self, MockSMTP, caplog):
        """Verify ALERT_SUPPRESSED is logged when alert_sent is True."""
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=3)
        ps = ProbeState(am)

        # Reach threshold
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")

        with caplog.at_level(logging.INFO, logger="doh-healthchecker"):
            # More failures — should log ALERT SUPPRESSED
            ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")

        suppressed_msgs = [r for r in caplog.records
                          if "ALERT SUPPRESSED" in r.message]
        assert len(suppressed_msgs) == 1
        assert "target1" in suppressed_msgs[0].message


class TestProbeStateAlertRecoveryCycle:
    @patch("alerting.smtplib.SMTP")
    def test_full_cycle_alert_then_recovery(self, MockSMTP):
        """Test the complete cycle: failures -> alert -> recovery -> clean state."""
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=2)
        ps = ProbeState(am)

        # Phase 1: Build failures to trigger alert
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.flush_pending_alerts()
        assert mock_server.sendmail.call_count == 1

        state = ps.get_state("target1", "example.com")
        assert state["alert_sent"] is True
        assert state["consecutive_failures"] == 2

        # Phase 2: Build successes to trigger recovery
        ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")
        ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")
        assert mock_server.sendmail.call_count == 2

        state = ps.get_state("target1", "example.com")
        assert state["alert_sent"] is False
        assert state["consecutive_failures"] == 0
        assert state["consecutive_successes"] == 0
        assert state["last_failure_time"] is None

    @patch("alerting.smtplib.SMTP")
    def test_recovery_resets_counters_for_next_cycle(self, MockSMTP):
        """After recovery, a new failure streak should work independently."""
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=2)
        ps = ProbeState(am)

        # First cycle: alert + recovery
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.flush_pending_alerts()
        ps.record_success("t", "d", "1.2.3.4", "1.2.3.4")
        ps.record_success("t", "d", "1.2.3.4", "1.2.3.4")

        # Second cycle: new failures should trigger a new alert
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.flush_pending_alerts()

        # Should have sent 3 emails: 1 alert, 1 recovery, 1 new alert
        assert mock_server.sendmail.call_count == 3

    @patch("alerting.smtplib.SMTP")
    def test_failure_during_recovery_streak_resets_success(self, MockSMTP):
        """If a failure occurs during recovery streak, success counter resets."""
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=3)
        ps = ProbeState(am)

        # Trigger alert
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.flush_pending_alerts()

        # Start recovery but fail before threshold
        ps.record_success("t", "d", "1.2.3.4", "1.2.3.4")
        ps.record_success("t", "d", "1.2.3.4", "1.2.3.4")

        # Now fail — should reset success counter to 0
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")

        state = ps.get_state("t", "d")
        assert state["consecutive_successes"] == 0
        assert state["consecutive_failures"] == 1
        assert state["alert_sent"] is True  # still in alert state

    @patch("alerting.smtplib.SMTP")
    def test_success_resets_last_failure_time_on_recovery(self, MockSMTP):
        """Recovery should clear the last_failure_time."""
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=2)
        ps = ProbeState(am)

        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")

        state = ps.get_state("t", "d")
        assert state["last_failure_time"] is not None

        # Recovery
        ps.record_success("t", "d", "1.2.3.4", "1.2.3.4")
        ps.record_success("t", "d", "1.2.3.4", "1.2.3.4")

        state = ps.get_state("t", "d")
        assert state["last_failure_time"] is None


class TestProbeStateEdgeCases:
    @patch("alerting.smtplib.SMTP")
    def test_get_state_returns_copy(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager()
        ps = ProbeState(am)

        ps.record_failure("t", "d", "1.2.3.4", "TIMEOUT")
        state1 = ps.get_state("t", "d")
        state2 = ps.get_state("t", "d")

        # Modifying one should not affect the other
        state1["consecutive_failures"] = 999
        assert state2["consecutive_failures"] == 1

    @patch("alerting.smtplib.SMTP")
    def test_get_state_creates_entry_if_missing(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager()
        ps = ProbeState(am)

        state = ps.get_state("new_target", "new_domain")
        assert state["consecutive_failures"] == 0
        assert state["consecutive_successes"] == 0
        assert state["alert_sent"] is False
        assert state["last_failure_time"] is None
        assert "last_alert_time" in state
        assert state["last_alert_time"] is None

    @patch("alerting.smtplib.SMTP")
    def test_many_targets_coexist(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=2)
        ps = ProbeState(am)

        # Interleave operations across 5 targets
        for i in range(5):
            target = f"target_{i}"
            ps.record_failure(target, "example.com", f"1.2.3.{i}", "TIMEOUT")

        for i in range(5):
            state = ps.get_state(f"target_{i}", "example.com")
            assert state["consecutive_failures"] == 1

        # Now push some to threshold, others not
        ps.record_failure("target_0", "example.com", "1.2.3.0", "TIMEOUT")
        ps.record_failure("target_1", "example.com", "1.2.3.1", "TIMEOUT")

        # Only target_0 and target_1 should have been queued
        queued_targets = {a["target"] for a in ps._pending_alerts}
        assert queued_targets == {"target_0", "target_1"}

        # Flush — should send ONE consolidated email
        ps.flush_pending_alerts()
        assert mock_server.sendmail.call_count == 1
        sendmail_args = mock_server.sendmail.call_args
        assert "2 target(s) failing" in sendmail_args[0][2]


class TestProbeStateEmailContent:
    @patch("alerting.smtplib.SMTP")
    def test_consolidated_alert_email_contains_correct_info(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=2)
        ps = ProbeState(am)

        ps.record_failure("https://dns.google", "example.com", "93.184.216.34", "1.2.3.4")
        ps.record_failure("https://dns.google", "example.com", "93.184.216.34", "1.2.3.4")
        ps.flush_pending_alerts()

        # Get the email body from sendmail call
        email_body = mock_server.sendmail.call_args[0][2]
        assert "ALERT" in email_body
        assert "example.com" in email_body
        assert "93.184.216.34" in email_body
        assert "1.2.3.4" in email_body

    @patch("alerting.smtplib.SMTP")
    def test_recovery_email_contains_correct_info(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=2)
        ps = ProbeState(am)

        # Trigger alert
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.record_failure("target1", "example.com", "1.2.3.4", "TIMEOUT")
        ps.flush_pending_alerts()

        # Trigger recovery
        ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")
        ps.record_success("target1", "example.com", "1.2.3.4", "1.2.3.4")

        # Get the recovery email body
        recovery_call = mock_server.sendmail.call_args_list[1]
        email_body = recovery_call[0][2]
        assert "RECOVERED" in email_body
        assert "example.com" in email_body
        assert "1.2.3.4" in email_body

    @patch("alerting.smtplib.SMTP")
    def test_consolidated_email_subject_format(self, MockSMTP):
        mock_server = MagicMock()
        MockSMTP.return_value.__enter__ = MagicMock(return_value=mock_server)
        MockSMTP.return_value.__exit__ = MagicMock(return_value=False)

        am = _make_alert_manager(failure_threshold=2, recovery_threshold=3)
        ps = ProbeState(am)

        # Fail 3 targets
        for i in range(3):
            ps.record_failure(f"target_{i}", "example.com", f"1.2.3.{i}", "TIMEOUT")
            ps.record_failure(f"target_{i}", "example.com", f"1.2.3.{i}", "TIMEOUT")

        ps.flush_pending_alerts()

        # Verify subject format
        email_raw = mock_server.sendmail.call_args[0][2]
        assert "[DOH-MONITOR] ALERT: 3 target(s) failing" in email_raw

        # Verify all 3 targets appear in body
        for i in range(3):
            assert f"target_{i}" in email_raw


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
