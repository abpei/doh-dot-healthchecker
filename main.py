"""DNS-over-HTTPS/TLS healthchecker — main entry point.

Loads configuration from environment variables, initializes modules, and
runs the probe loop with email alerting on threshold breaches.
"""

import logging
import os
import sys
import time

from alerting import AlertManager, ProbeState
from dns_probe import (
    _is_ip_address,
    _reverse_dns_lookup,
    parse_target,
    parse_test_domains,
    probe_doh,
    probe_dot,
)

logger = logging.getLogger("doh-healthchecker")


# ---------------------------------------------------------------------------
# Environment variable helpers
# ---------------------------------------------------------------------------

REQUIRED_ENV_VARS = [
    "TARGETS",
    "TEST_DOMAINS",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASS",
    "SMTP_FROM",
    "SMTP_TO",
]


def _load_env() -> dict:
    """Load and validate environment variables, returning a config dict.

    Raises SystemExit with a clear message if any required variable is missing.
    """
    missing = [var for var in REQUIRED_ENV_VARS if not os.environ.get(var)]
    if missing:
        logger.error(
            "Missing required environment variables: %s",
            ", ".join(missing),
        )
        sys.exit(1)

    return {
        # Required
        "targets": os.environ["TARGETS"],
        "test_domains": os.environ["TEST_DOMAINS"],
        "smtp_host": os.environ["SMTP_HOST"],
        "smtp_port": int(os.environ["SMTP_PORT"]),
        "smtp_user": os.environ["SMTP_USER"],
        "smtp_pass": os.environ["SMTP_PASS"],
        "smtp_from": os.environ["SMTP_FROM"],
        "smtp_to": os.environ["SMTP_TO"],
        # Optional with defaults
        "probe_interval": int(os.environ.get("PROBE_INTERVAL", "300")),
        "failure_threshold": int(os.environ.get("FAILURE_THRESHOLD", "5")),
        "recovery_threshold": int(os.environ.get("RECOVERY_THRESHOLD", "3")),
        "dns_server": os.environ.get("DNS_SERVER", "1.1.1.1"),
        # DoT TLS options
        "dot_hostname": os.environ.get("DOT_HOSTNAME") or None,
        "dot_verify_hostname": os.environ.get("DOT_VERIFY_HOSTNAME", "true").lower() != "false",
    }


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def _setup_logging() -> None:
    """Configure root logger to stdout with a compact timestamp format."""
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(
        fmt="[%(asctime)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(handler)
    # Ensure the app logger inherits INFO level (default is WARNING)
    logging.getLogger("doh-healthchecker").setLevel(logging.INFO)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Load config, initialise modules, and run the infinite probe loop."""
    _setup_logging()

    cfg = _load_env()

    # Parse targets and test domains
    targets = [parse_target(t) for t in cfg["targets"].split(",") if t.strip()]
    test_domains = parse_test_domains(cfg["test_domains"])

    # Build alert manager and state tracker
    alert_manager = AlertManager(
        smtp_host=cfg["smtp_host"],
        smtp_port=cfg["smtp_port"],
        smtp_user=cfg["smtp_user"],
        smtp_pass=cfg["smtp_pass"],
        smtp_from=cfg["smtp_from"],
        smtp_to=cfg["smtp_to"],
        failure_threshold=cfg["failure_threshold"],
        recovery_threshold=cfg["recovery_threshold"],
    )
    probe_state = ProbeState(alert_manager)

    logger.info(
        "Starting DOH healthchecker — %d target(s), %d domain(s), "
        "probe interval %ds",
        len(targets), len(test_domains), cfg["probe_interval"],
    )

    # Pre-cache PTR lookups for raw-IP DoT targets so we resolve once, not per cycle.
    for target in targets:
        if target["type"] == "dot" and _is_ip_address(target["host"]):
            ptr_host, from_cache = _reverse_dns_lookup(target["host"], cfg["dns_server"])
            if ptr_host:
                if from_cache:
                    logger.debug(
                        "PTR cache hit for %s → %s", target["host"], ptr_host,
                    )
                else:
                    logger.info(
                        "PTR lookup: %s → %s (will be used as TLS SNI)",
                        target["host"],
                        ptr_host,
                    )

    try:
        while True:
            for target in targets:
                for td in test_domains:
                    domain = td["domain"]
                    expected_ip = td["expected_ip"]

                    if target["type"] == "doh":
                        result = probe_doh(
                            target_url=target["url"],
                            domain=domain,
                            expected_ip=expected_ip,
                        )
                    else:
                        result = probe_dot(
                            host=target["host"],
                            port=target["port"],
                            domain=domain,
                            expected_ip=expected_ip,
                            dns_server=cfg["dns_server"],
                            dot_hostname=cfg["dot_hostname"],
                            dot_verify_hostname=cfg["dot_verify_hostname"],
                        )

                    # Build human-readable target label
                    target_label = (
                        target["url"] if target["type"] == "doh"
                        else f"{target['host']}:{target['port']}"
                    )

                    if result["success"]:
                        logger.info(
                            "OK   %s -> %s (%s) %.0fms",
                            target_label,
                            domain,
                            expected_ip,
                            result["response_time_ms"],
                        )
                        probe_state.record_success(
                            target=target_label,
                            domain=domain,
                            expected_ip=expected_ip,
                            actual_ip=result["actual_ip"],
                        )
                    else:
                        error_msg = result["error"] or "TIMEOUT"
                        logger.info(
                            "FAIL %s -> %s %s",
                            target_label,
                            domain,
                            error_msg,
                        )
                        probe_state.record_failure(
                            target=target_label,
                            domain=domain,
                            expected_ip=expected_ip,
                            actual_info=error_msg,
                        )

            # Send any consolidated alerts for failures detected this cycle
            probe_state.flush_pending_alerts()

            time.sleep(cfg["probe_interval"])

    except KeyboardInterrupt:
        logger.info("Shutting down (received Ctrl+C)")
        sys.exit(0)


if __name__ == "__main__":
    main()
