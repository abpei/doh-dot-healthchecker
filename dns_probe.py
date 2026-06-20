"""DNS probing module for DoH (DNS-over-HTTPS) and DoT (DNS-over-TLS) health checks."""

import base64
import logging
import socket
import ssl
import struct
import time
from typing import Optional

import dns.message
import dns.query
import dns.resolver
import httpx

logger = logging.getLogger("doh-healthchecker")

# Module-level cache for PTR lookup results.  Keyed by (ip, dns_server) so the
# same IP resolved via different upstreams is tracked separately.
_ptr_cache: dict[tuple[str, str], Optional[str]] = {}


def _extract_a_record_ip(response: dns.message.Message) -> Optional[str]:
    """Extract the first A record IP from a DNS response answer section."""
    for rrset in response.answer:
        for rdata in rrset:
            if hasattr(rdata, "address"):
                return rdata.address
    return None


def _resolve_hostname(hostname: str, dns_server: str = "1.1.1.1") -> Optional[str]:
    """Resolve a hostname to an IP address using the specified DNS server."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        answers = resolver.resolve(hostname, "A")
        for rdata in answers:
            return rdata.address
    except Exception:
        return None


def _reverse_dns_lookup(
    ip: str,
    dns_server: str = "1.1.1.1",
    *,
    use_cache: bool = True,
) -> Optional[str]:
    """Perform a PTR (reverse DNS) lookup for the given IP address.

    Results are cached in ``_ptr_cache`` so repeated calls for the same
    IP+upstream pair return instantly without additional DNS traffic.

    Args:
        ip: The IPv4 address to reverse-resolve.
        dns_server: Upstream DNS server to query.
        use_cache: When True (default), return a cached result if available.

    Returns:
        The hostname from the PTR record, or ``None`` on failure / no record.
    """
    cache_key = (ip, dns_server)
    if use_cache and cache_key in _ptr_cache:
        return _ptr_cache[cache_key]

    hostname: Optional[str] = None
    try:
        # Build a PTR query for the IP (e.g. 1.2.3.4 → 4.3.2.1.in-addr.arpa.)
        reversed_octets = ".".join(reversed(ip.split(".")))
        ptr_name = f"{reversed_octets}.in-addr.arpa."

        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]
        answers = resolver.resolve(ptr_name, "PTR")
        for rdata in answers:
            # PTR records end with a dot; strip it for a clean hostname
            hostname = str(rdata.target).rstrip(".")
            break
    except Exception as exc:
        logger.debug("PTR lookup failed for %s via %s: %s", ip, dns_server, exc)
        hostname = None

    if use_cache:
        _ptr_cache[cache_key] = hostname

    return hostname


def clear_ptr_cache() -> None:
    """Clear the PTR lookup cache.  Useful for testing."""
    _ptr_cache.clear()


def _is_ip_address(value: str) -> bool:
    """Return True if *value* looks like a dotted-decimal IPv4 address."""
    try:
        socket.inet_aton(value)
        return True
    except OSError:
        return False


def _build_wireformat_query(domain: str) -> bytes:
    """Build a DNS A-record query message in wireformat."""
    msg = dns.message.make_query(domain, "A")
    return msg.to_wire()


def probe_doh(
    target_url: str,
    domain: str,
    expected_ip: str,
    timeout: int = 10,
) -> dict:
    """Probe a DoH endpoint using JSON API first, then wireformat POST fallback.

    Args:
        target_url: The DoH endpoint URL.
        domain: The domain to query.
        expected_ip: The expected A record IP address.
        timeout: Request timeout in seconds.

    Returns:
        Dict with keys: success, actual_ip, response_time_ms, error.
    """
    result = {"success": False, "actual_ip": None, "response_time_ms": 0.0, "error": None}

    with httpx.Client(http2=True, timeout=timeout) as client:
        # --- Attempt 1: JSON API ---
        start = time.monotonic()
        try:
            resp = client.get(
                target_url,
                params={"name": domain, "type": "A"},
                headers={"accept": "application/dns-json"},
            )
            elapsed_ms = (time.monotonic() - start) * 1000

            if resp.status_code == 200:
                data = resp.json()
                if data.get("Status") != 0:
                    result["error"] = f"DNS status code {data.get('Status')}"
                    result["response_time_ms"] = elapsed_ms
                    return result

                # Look for expected A record in Answer section
                actual_ip = None
                for answer in data.get("Answer", []):
                    if answer.get("type") == 1:  # A record
                        actual_ip = answer.get("data")
                        break

                result["response_time_ms"] = elapsed_ms
                if actual_ip == expected_ip:
                    result["success"] = True
                    result["actual_ip"] = actual_ip
                else:
                    result["actual_ip"] = actual_ip
                    result["error"] = (
                        f"Expected {expected_ip}, got {actual_ip}"
                        if actual_ip
                        else "No A record found in response"
                    )
                return result
            else:
                # Non-200 → fall through to wireformat
                pass

        except httpx.TimeoutException:
            elapsed_ms = (time.monotonic() - start) * 1000
            result["response_time_ms"] = elapsed_ms
            result["error"] = f"JSON API timeout after {elapsed_ms:.0f}ms"
            return result
        except httpx.ConnectError as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            result["response_time_ms"] = elapsed_ms
            result["error"] = f"JSON API connection error: {e}"
            return result
        except httpx.HTTPError as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            result["response_time_ms"] = elapsed_ms
            result["error"] = f"JSON API request error: {e}"
            return result
        except Exception as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            result["response_time_ms"] = elapsed_ms
            result["error"] = f"JSON API unexpected error: {e}"
            return result

        # --- Attempt 2: Wireformat POST fallback ---
        start = time.monotonic()
        try:
            wire_query = _build_wireformat_query(domain)
            resp = client.post(
                target_url,
                content=wire_query,
                headers={
                    "content-type": "application/dns-message",
                    "accept": "application/dns-message",
                },
            )
            elapsed_ms = (time.monotonic() - start) * 1000
            result["response_time_ms"] = elapsed_ms

            if resp.status_code != 200:
                result["error"] = f"Wireformat POST returned HTTP {resp.status_code}"
                return result

            wire_response = dns.message.from_wire(resp.content)
            actual_ip = _extract_a_record_ip(wire_response)

            if actual_ip == expected_ip:
                result["success"] = True
                result["actual_ip"] = actual_ip
            else:
                result["actual_ip"] = actual_ip
                result["error"] = (
                    f"Expected {expected_ip}, got {actual_ip}"
                    if actual_ip
                    else "No A record found in wireformat response"
                )
            return result

        except httpx.TimeoutException:
            elapsed_ms = (time.monotonic() - start) * 1000
            result["response_time_ms"] = elapsed_ms
            result["error"] = f"Wireformat POST timeout after {elapsed_ms:.0f}ms"
            return result
        except httpx.ConnectError as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            result["response_time_ms"] = elapsed_ms
            result["error"] = f"Wireformat POST connection error: {e}"
            return result
        except httpx.HTTPError as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            result["response_time_ms"] = elapsed_ms
            result["error"] = f"Wireformat POST request error: {e}"
            return result
        except Exception as e:
            elapsed_ms = (time.monotonic() - start) * 1000
            result["response_time_ms"] = elapsed_ms
            result["error"] = f"Wireformat POST unexpected error: {e}"
            return result


def _determine_server_hostname(
    host: str,
    dns_server: str,
    dot_hostname: Optional[str],
) -> tuple[str, Optional[str]]:
    """Determine the TLS server_hostname for a DoT connection.

    Resolution order:
      1. Explicit *dot_hostname* override (from DOT_HOSTNAME env var).
      2. PTR lookup on raw IP → hostname.
      3. Fall back to the raw IP (cert verification will likely fail).

    Returns:
        (server_hostname, ptr_host) — *ptr_host* is the PTR-derived name so the
        caller can log it separately.
    """
    # If the caller supplied an explicit hostname, use it directly.
    if dot_hostname:
        logger.debug("Using explicit DOT_HOSTNAME=%s for %s", dot_hostname, host)
        return dot_hostname, None

    # Only attempt PTR for raw IP addresses.
    if not _is_ip_address(host):
        return host, None

    ptr_host = _reverse_dns_lookup(host, dns_server)
    if ptr_host:
        logger.info(
            "PTR lookup for %s returned %s — using as TLS server_hostname",
            host,
            ptr_host,
        )
        return ptr_host, ptr_host

    logger.warning(
        "No PTR record for %s and DOT_HOSTNAME not set — "
        "connecting with raw IP as server_hostname (cert verification may fail)",
        host,
    )
    return host, None


def probe_dot(
    host: str,
    port: int,
    domain: str,
    expected_ip: str,
    timeout: int = 10,
    dns_server: str = "1.1.1.1",
    dot_hostname: Optional[str] = None,
    dot_verify_hostname: bool = True,
) -> dict:
    """Probe a DoT (DNS-over-TLS) endpoint.

    Hostname resolution order for TLS SNI:
      1. Explicit *dot_hostname* parameter (DOT_HOSTNAME env var).
      2. PTR (reverse DNS) lookup when *host* is a raw IP.
      3. Fall back to *host* itself (raw IP — cert check may fail).

    Args:
        host: The DoT server hostname or IP.
        port: The DoT server port (typically 853).
        domain: The domain to query.
        expected_ip: The expected A record IP address.
        timeout: Connection and read timeout in seconds.
        dns_server: DNS server to use for resolving host if it's a hostname.
        dot_hostname: If set, used as TLS server_hostname (SNI) for all connections.
            When connecting to a raw IP, set this to the domain whose cert the server
            presents (e.g. "dns1.example.com").
        dot_verify_hostname: When False, skip TLS hostname verification entirely.
            Useful for raw IP targets where no matching cert exists.

    Returns:
        Dict with keys: success, actual_ip, response_time_ms, error.
    """
    result = {"success": False, "actual_ip": None, "response_time_ms": 0.0, "error": None}

    start = time.monotonic()

    # Resolve hostname to IP if needed
    connect_host = host
    try:
        socket.inet_aton(host)
    except OSError:
        # Not a valid IP, resolve it
        resolved = _resolve_hostname(host, dns_server)
        if resolved is None:
            elapsed_ms = (time.monotonic() - start) * 1000
            result["response_time_ms"] = elapsed_ms
            result["error"] = f"Failed to resolve DoT host '{host}' using DNS server {dns_server}"
            return result
        connect_host = resolved

    try:
        # Build DNS query
        query_msg = dns.message.make_query(domain, "A")
        query_wire = query_msg.to_wire()

        # Determine server_hostname for TLS SNI
        server_hostname, _ptr_host = _determine_server_hostname(
            host, dns_server, dot_hostname
        )

        # Open TLS connection
        context = ssl.create_default_context()
        if not dot_verify_hostname:
            logger.warning(
                "Hostname verification disabled for DoT connection to %s:%d",
                host, port,
            )
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((connect_host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=server_hostname) as tls_sock:
                tls_sock.settimeout(timeout)
                # Send query (2-byte length prefix per DNS-over-TLS spec)
                length_prefix = struct.pack("!H", len(query_wire))
                tls_sock.sendall(length_prefix + query_wire)

                # Read response (2-byte length prefix)
                length_data = _recv_exact(tls_sock, 2)
                if length_data is None:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    result["response_time_ms"] = elapsed_ms
                    result["error"] = "Failed to read response length from DoT server"
                    return result

                response_length = struct.unpack("!H", length_data)[0]
                response_data = _recv_exact(tls_sock, response_length)
                if response_data is None:
                    elapsed_ms = (time.monotonic() - start) * 1000
                    result["response_time_ms"] = elapsed_ms
                    result["error"] = "Failed to read response data from DoT server"
                    return result

                elapsed_ms = (time.monotonic() - start) * 1000
                result["response_time_ms"] = elapsed_ms

                # Parse DNS response
                wire_response = dns.message.from_wire(response_data)
                actual_ip = _extract_a_record_ip(wire_response)

                if actual_ip == expected_ip:
                    result["success"] = True
                    result["actual_ip"] = actual_ip
                else:
                    result["actual_ip"] = actual_ip
                    result["error"] = (
                        f"Expected {expected_ip}, got {actual_ip}"
                        if actual_ip
                        else "No A record found in DoT response"
                    )
                return result

    except ssl.SSLError as e:
        elapsed_ms = (time.monotonic() - start) * 1000
        result["response_time_ms"] = elapsed_ms
        result["error"] = f"DoT TLS error: {e}"
        return result
    except socket.timeout:
        elapsed_ms = (time.monotonic() - start) * 1000
        result["response_time_ms"] = elapsed_ms
        result["error"] = f"DoT timeout after {elapsed_ms:.0f}ms"
        return result
    except ConnectionRefusedError:
        elapsed_ms = (time.monotonic() - start) * 1000
        result["response_time_ms"] = elapsed_ms
        result["error"] = f"DoT connection refused by {connect_host}:{port}"
        return result
    except OSError as e:
        elapsed_ms = (time.monotonic() - start) * 1000
        result["response_time_ms"] = elapsed_ms
        result["error"] = f"DoT OS error: {e}"
        return result
    except Exception as e:
        elapsed_ms = (time.monotonic() - start) * 1000
        result["response_time_ms"] = elapsed_ms
        result["error"] = f"DoT unexpected error: {e}"
        return result


def _recv_exact(sock: socket.socket, num_bytes: int) -> Optional[bytes]:
    """Receive exactly num_bytes from a socket, or return None on failure."""
    data = b""
    while len(data) < num_bytes:
        chunk = sock.recv(num_bytes - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def parse_target(target_str: str) -> dict:
    """Parse a target string into its components.

    Args:
        target_str: Either an HTTPS URL (for DoH) or host:port (for DoT).

    Returns:
        Dict with keys: type, host, port, url.
    """
    if target_str.startswith("https://"):
        return {
            "type": "doh",
            "host": "",
            "port": 0,
            "url": target_str,
        }

    # DoT target: host or host:port
    if ":" in target_str:
        parts = target_str.rsplit(":", 1)
        try:
            port = int(parts[1])
        except ValueError:
            raise ValueError(f"Invalid port in target: {target_str!r}")
        return {
            "type": "dot",
            "host": parts[0],
            "port": port,
            "url": "",
        }

    return {
        "type": "dot",
        "host": target_str,
        "port": 853,
        "url": "",
    }


def parse_test_domains(domains_str: str) -> list:
    """Parse a comma-separated domain list.

    Args:
        domains_str: Comma-separated entries of 'domain|expected_ip'.

    Returns:
        List of dicts with keys: domain, expected_ip.
    """
    result = []
    for entry in domains_str.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split("|", 1)
        if len(parts) != 2:
            raise ValueError(
                f"Invalid domain entry '{entry}': expected 'domain|expected_ip' format"
            )
        domain, expected_ip = parts[0].strip(), parts[1].strip()
        if not domain or not expected_ip:
            raise ValueError(
                f"Invalid domain entry '{entry}': domain and expected_ip must be non-empty"
            )
        result.append({"domain": domain, "expected_ip": expected_ip})
    return result
