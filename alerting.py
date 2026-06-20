"""Email alerting and per-target state management for DOH healthchecker."""

import logging
import smtplib
from datetime import datetime, timezone
from email.mime.text import MIMEText
from typing import List, Optional

logger = logging.getLogger("doh-healthchecker")


# ---------------------------------------------------------------------------
# Email templates
# ---------------------------------------------------------------------------

def alert_subject(target: str) -> str:
    """Return the subject line for a failure alert email."""
    return f"[DOH-MONITOR] ALERT: {target} failing"


def consolidated_alert_subject(target_count: int) -> str:
    """Return the subject line for a consolidated multi-target alert email."""
    return f"[DOH-MONITOR] ALERT: {target_count} target(s) failing"


def alert_body(target: str, domain: str, expected_ip: str, actual_info: str,
               consecutive_failures: int, since: datetime) -> str:
    """Return the body text for a failure alert email.

    Args:
        target: The DoH/DoT target being monitored.
        domain: The domain being resolved.
        expected_ip: The expected A record IP.
        actual_info: The actual IP received, or "TIMEOUT" / error description.
        consecutive_failures: Number of consecutive failures.
        since: Timestamp when the failure streak started.
    """
    since_str = since.strftime("%Y-%m-%d %H:%M:%S UTC")
    return (
        f"ALERT: DNS resolution failure detected\n"
        f"\n"
        f"Target:            {target}\n"
        f"Domain:            {domain}\n"
        f"Expected IP:       {expected_ip}\n"
        f"Actual IP/Status:  {actual_info}\n"
        f"Consecutive Failures: {consecutive_failures}\n"
        f"Since:             {since_str}\n"
    )


def consolidated_alert_body(alerts: List[dict]) -> str:
    """Return the body text for a consolidated multi-target alert email.

    Args:
        alerts: List of dicts, each with keys: target, domain, expected_ip,
                actual_info, consecutive_failures, since.
    """
    parts = [
        f"ALERT: {len(alerts)} target(s) failing\n",
        "",
    ]
    for a in alerts:
        since_str = a["since"].strftime("%Y-%m-%d %H:%M:%S UTC")
        parts.append(
            f"Target: {a['target']}\n"
            f"  Domain: {a['domain']} | Expected: {a['expected_ip']} "
            f"| Got: {a['actual_info']}\n"
            f"  Consecutive Failures: {a['consecutive_failures']} | Since: {since_str}\n"
        )
    return "\n".join(parts)


def recovery_subject(target: str) -> str:
    """Return the subject line for a recovery email."""
    return f"[DOH-MONITOR] RECOVERED: {target}"


def recovery_body(target: str, domain: str, expected_ip: str, actual_ip: str,
                  consecutive_successes: int) -> str:
    """Return the body text for a recovery email.

    Args:
        target: The DoH/DoT target that recovered.
        domain: The domain being resolved.
        expected_ip: The expected A record IP.
        actual_ip: The actual IP received on recovery.
        consecutive_successes: Number of consecutive successes.
    """
    return (
        f"RECOVERED: DNS resolution is healthy again\n"
        f"\n"
        f"Target:            {target}\n"
        f"Domain:            {domain}\n"
        f"Expected IP:       {expected_ip}\n"
        f"Actual IP:         {actual_ip}\n"
        f"Consecutive Successes: {consecutive_successes}\n"
    )


# ---------------------------------------------------------------------------
# AlertManager
# ---------------------------------------------------------------------------

class AlertManager:
    """Sends alert and recovery emails via SMTP with STARTTLS.

    All SMTP errors are caught and logged as warnings — the application
    never crashes due to email failures.
    """

    def __init__(
        self,
        smtp_host: str,
        smtp_port: int,
        smtp_user: str,
        smtp_pass: str,
        smtp_from: str,
        smtp_to: str,
        failure_threshold: int = 5,
        recovery_threshold: int = 3,
    ):
        """Initialise the alert manager.

        Args:
            smtp_host: SMTP server hostname.
            smtp_port: SMTP server port (typically 587 for STARTTLS).
            smtp_user: SMTP authentication username.
            smtp_pass: SMTP authentication password.
            smtp_from: Sender email address.
            smtp_to: Recipient email address(es), comma-separated.
            failure_threshold: Consecutive failures before sending an alert.
            recovery_threshold: Consecutive successes before sending recovery.
        """
        self.smtp_host = smtp_host
        self.smtp_port = smtp_port
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.smtp_from = smtp_from
        self.smtp_to = smtp_to
        self.failure_threshold = failure_threshold
        self.recovery_threshold = recovery_threshold

    def _send_email(self, subject: str, body: str) -> bool:
        """Send an email via SMTP with STARTTLS.

        Returns True if the email was sent successfully, False otherwise.
        All exceptions are caught and logged as warnings.
        """
        try:
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = self.smtp_from
            msg["To"] = self.smtp_to

            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.smtp_user, self.smtp_pass)
                server.sendmail(self.smtp_from, self.smtp_to, msg.as_string())

            logger.info("EMAIL SENT: %s to %s", subject, self.smtp_to)
            return True

        except smtplib.SMTPException as e:
            logger.warning("EMAIL FAILED: %s — %s", subject, e)
            return False
        except OSError as e:
            logger.warning("EMAIL FAILED: %s — %s", subject, e)
            return False
        except Exception as e:
            logger.warning("EMAIL FAILED: %s — %s", subject, e)
            return False

    def send_alert(
        self,
        target: str,
        domain: str,
        expected_ip: str,
        actual_info: str,
        consecutive_failures: int,
        since: datetime,
    ) -> bool:
        """Send a failure alert email."""
        subject = alert_subject(target)
        body = alert_body(target, domain, expected_ip, actual_info,
                          consecutive_failures, since)
        return self._send_email(subject, body)

    def send_consolidated_alert(self, alerts: List[dict]) -> bool:
        """Send a consolidated alert email covering multiple failing targets.

        Args:
            alerts: List of dicts with keys: target, domain, expected_ip,
                    actual_info, consecutive_failures, since.
        """
        if not alerts:
            return True
        subject = consolidated_alert_subject(len(alerts))
        body = consolidated_alert_body(alerts)
        return self._send_email(subject, body)

    def send_recovery(
        self,
        target: str,
        domain: str,
        expected_ip: str,
        actual_ip: str,
        consecutive_successes: int,
    ) -> bool:
        """Send a recovery email."""
        subject = recovery_subject(target)
        body = recovery_body(target, domain, expected_ip, actual_ip,
                             consecutive_successes)
        return self._send_email(subject, body)


# ---------------------------------------------------------------------------
# ProbeState
# ---------------------------------------------------------------------------

class ProbeState:
    """Tracks per-target consecutive success/failure counts and manages
    alert/recovery email delivery at threshold boundaries.

    State is keyed by ``(target, domain)`` tuples.  Each entry stores:
        - ``consecutive_failures``: int
        - ``consecutive_successes``: int
        - ``alert_sent``: bool
        - ``last_alert_time``: datetime | None
        - ``last_failure_time``: datetime | None
        - ``expected_ip``: str
        - ``last_actual_ip``: str | None
    """

    def __init__(self, alert_manager: AlertManager):
        self._alert_manager = alert_manager
        self._state: dict = {}
        self._pending_alerts: List[dict] = []

    def _get_state(self, target: str, domain: str) -> dict:
        """Return or create the state entry for a (target, domain) pair."""
        key = (target, domain)
        if key not in self._state:
            self._state[key] = {
                "consecutive_failures": 0,
                "consecutive_successes": 0,
                "alert_sent": False,
                "last_alert_time": None,
                "last_failure_time": None,
                "expected_ip": "",
                "last_actual_ip": None,
            }
        return self._state[key]

    def record_success(self, target: str, domain: str,
                       expected_ip: str, actual_ip: str) -> None:
        """Record a successful probe.

        Resets ``consecutive_failures`` to 0 and increments
        ``consecutive_successes``.  When the recovery threshold is reached
        and an alert was previously sent, a recovery email is dispatched
        and the counters are reset.

        Args:
            target: The DoH/DoT target URL or host.
            domain: The domain that was resolved.
            expected_ip: The expected A record IP.
            actual_ip: The actual IP returned by the probe.
        """
        state = self._get_state(target, domain)
        state["consecutive_failures"] = 0
        state["consecutive_successes"] += 1
        state["expected_ip"] = expected_ip
        state["last_actual_ip"] = actual_ip

        if (state["consecutive_successes"] >= self._alert_manager.recovery_threshold
                and state["alert_sent"]):
            self._alert_manager.send_recovery(
                target=target,
                domain=domain,
                expected_ip=expected_ip,
                actual_ip=actual_ip,
                consecutive_successes=state["consecutive_successes"],
            )
            state["alert_sent"] = False
            state["consecutive_failures"] = 0
            state["consecutive_successes"] = 0
            state["last_failure_time"] = None
            state["last_alert_time"] = None

    def record_failure(self, target: str, domain: str,
                       expected_ip: str, actual_info: str) -> None:
        """Record a failed probe.

        Resets ``consecutive_successes`` to 0 and increments
        ``consecutive_failures``.  When the failure threshold is reached
        and no alert has been sent yet, the failure is queued for
        consolidated alerting.

        Args:
            target: The DoH/DoT target URL or host.
            domain: The domain that was resolved.
            expected_ip: The expected A record IP.
            actual_info: The actual IP received, or "TIMEOUT" / error
                         description.
        """
        state = self._get_state(target, domain)
        state["consecutive_successes"] = 0
        state["consecutive_failures"] += 1
        state["last_failure_time"] = datetime.now(timezone.utc)
        state["expected_ip"] = expected_ip
        state["last_actual_ip"] = actual_info

        # Debug logging on every call
        logger.debug(
            "record_failure(%s, %s): consecutive_failures=%d alert_sent=%s "
            "failure_threshold=%d",
            target, domain, state["consecutive_failures"],
            state["alert_sent"], self._alert_manager.failure_threshold,
        )

        if (state["consecutive_failures"] >= self._alert_manager.failure_threshold
                and not state["alert_sent"]):
            # Queue for consolidated alert instead of sending immediately
            self._pending_alerts.append({
                "target": target,
                "domain": domain,
                "expected_ip": expected_ip,
                "actual_info": actual_info,
                "consecutive_failures": state["consecutive_failures"],
                "since": state["last_failure_time"],
                "state_key": (target, domain),
            })
            # Mark as alert_sent immediately so subsequent failures in the
            # same cycle don't duplicate the queue entry.
            state["alert_sent"] = True
            state["last_alert_time"] = datetime.now(timezone.utc)
        elif (state["consecutive_failures"] >= self._alert_manager.failure_threshold
                and state["alert_sent"]):
            logger.info("ALERT SUPPRESSED: %s — already alerting", target)

    def flush_pending_alerts(self) -> bool:
        """Send a consolidated alert email for all queued failures, then clear
        the pending queue.

        Returns True if an email was sent (or there were no pending alerts).
        """
        if not self._pending_alerts:
            return True

        alerts = list(self._pending_alerts)
        self._pending_alerts.clear()

        result = self._alert_manager.send_consolidated_alert(alerts)

        # Update last_alert_time on each state entry
        now = datetime.now(timezone.utc)
        for alert in alerts:
            key = alert["state_key"]
            if key in self._state:
                self._state[key]["last_alert_time"] = now

        return result

    def get_state(self, target: str, domain: str) -> dict:
        """Return a copy of the current state for a (target, domain) pair."""
        return dict(self._get_state(target, domain))
