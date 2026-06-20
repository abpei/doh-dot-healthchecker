"""Tests for dns_probe module — covers all 4 public functions with edge cases."""

import socket
import ssl
import struct
from unittest.mock import MagicMock, patch, Mock

import dns.name
import dns.message
import dns.rdata
import dns.rdatatype

import httpx

from dns_probe import (
    _build_wireformat_query,
    _determine_server_hostname,
    _extract_a_record_ip,
    _is_ip_address,
    _ptr_cache,
    _recv_exact,
    _reverse_dns_lookup,
    clear_ptr_cache,
    parse_target,
    parse_test_domains,
    probe_doh,
    probe_dot,
)


# ---------------------------------------------------------------------------
# parse_target tests
# ---------------------------------------------------------------------------

class TestParseTarget:
    def test_https_url(self):
        result = parse_target("https://dns.google/dns-query")
        assert result == {
            "type": "doh",
            "host": "",
            "port": 0,
            "url": "https://dns.google/dns-query",
        }

    def test_https_cloudflare(self):
        result = parse_target("https://cloudflare-dns.com/dns-query")
        assert result["type"] == "doh"
        assert result["url"] == "https://cloudflare-dns.com/dns-query"

    def test_dot_host_port(self):
        result = parse_target("1.1.1.1:853")
        assert result == {
            "type": "dot",
            "host": "1.1.1.1",
            "port": 853,
            "url": "",
        }

    def test_dot_host_only(self):
        result = parse_target("1.1.1.1")
        assert result == {
            "type": "dot",
            "host": "1.1.1.1",
            "port": 853,
            "url": "",
        }

    def test_dot_hostname_with_port(self):
        result = parse_target("dns.google:853")
        assert result == {
            "type": "dot",
            "host": "dns.google",
            "port": 853,
            "url": "",
        }

    def test_dot_custom_port(self):
        result = parse_target("1.0.0.1:8853")
        assert result == {
            "type": "dot",
            "host": "1.0.0.1",
            "port": 8853,
            "url": "",
        }

    def test_invalid_port_raises(self):
        import pytest
        with pytest.raises(ValueError, match="Invalid port"):
            parse_target("1.1.1.1:notaport")


# ---------------------------------------------------------------------------
# parse_test_domains tests
# ---------------------------------------------------------------------------

class TestParseTestDomains:
    def test_single_domain(self):
        result = parse_test_domains("example.com|93.184.216.34")
        assert result == [{"domain": "example.com", "expected_ip": "93.184.216.34"}]

    def test_multiple_domains(self):
        result = parse_test_domains("example.com|93.184.216.34,google.com|142.250.80.46")
        assert len(result) == 2
        assert result[0]["domain"] == "example.com"
        assert result[1]["domain"] == "google.com"

    def test_whitespace_handling(self):
        result = parse_test_domains(" example.com | 93.184.216.34 , google.com | 142.250.80.46 ")
        assert len(result) == 2
        assert result[0]["domain"] == "example.com"
        assert result[0]["expected_ip"] == "93.184.216.34"

    def test_empty_string(self):
        result = parse_test_domains("")
        assert result == []

    def test_missing_pipe_raises(self):
        import pytest
        with pytest.raises(ValueError, match="expected 'domain\\|expected_ip' format"):
            parse_test_domains("example.com")

    def test_empty_domain_raises(self):
        import pytest
        with pytest.raises(ValueError, match="must be non-empty"):
            parse_test_domains("|93.184.216.34")

    def test_empty_ip_raises(self):
        import pytest
        with pytest.raises(ValueError, match="must be non-empty"):
            parse_test_domains("example.com|")


# ---------------------------------------------------------------------------
# _extract_a_record_ip tests
# ---------------------------------------------------------------------------

class TestExtractARecordIp:
    def test_extracts_ip_from_answer(self):
        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        # Add a synthetic answer section
        rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdatatype.A, dns.rdataclass.IN)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)
        result = _extract_a_record_ip(msg)
        assert result == "93.184.216.34"

    def test_returns_none_for_no_answer(self):
        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        result = _extract_a_record_ip(msg)
        assert result is None


# ---------------------------------------------------------------------------
# _build_wireformat_query tests
# ---------------------------------------------------------------------------

class TestBuildWireformatQuery:
    def test_returns_bytes(self):
        wire = _build_wireformat_query("example.com")
        assert isinstance(wire, bytes)
        assert len(wire) > 0

    def test_valid_dns_message(self):
        wire = _build_wireformat_query("example.com")
        msg = dns.message.from_wire(wire)
        assert msg.question[0].name.to_text() == "example.com."


# ---------------------------------------------------------------------------
# _recv_exact tests
# ---------------------------------------------------------------------------

class TestRecvExact:
    def test_receives_exact_bytes(self):
        sock = MagicMock()
        sock.recv.side_effect = [b"he", b"llo"]
        result = _recv_exact(sock, 5)
        assert result == b"hello"

    def test_returns_none_on_eof(self):
        sock = MagicMock()
        sock.recv.return_value = b""
        result = _recv_exact(sock, 5)
        assert result is None


# ---------------------------------------------------------------------------
# probe_doh tests
# ---------------------------------------------------------------------------

class TestProbeDoh:
    @patch("dns_probe.httpx.Client")
    def test_json_api_success(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 0,
            "Answer": [
                {"type": 1, "data": "93.184.216.34", "name": "example.com"},
            ],
        }
        mock_client.get.return_value = mock_resp

        result = probe_doh("https://dns.google/dns-query", "example.com", "93.184.216.34")
        assert result["success"] is True
        assert result["actual_ip"] == "93.184.216.34"
        assert result["error"] is None
        assert result["response_time_ms"] >= 0

    @patch("dns_probe.httpx.Client")
    def test_json_api_wrong_ip(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "Status": 0,
            "Answer": [
                {"type": 1, "data": "1.2.3.4", "name": "example.com"},
            ],
        }
        mock_client.get.return_value = mock_resp

        result = probe_doh("https://dns.google/dns-query", "example.com", "93.184.216.34")
        assert result["success"] is False
        assert result["actual_ip"] == "1.2.3.4"
        assert "Expected 93.184.216.34, got 1.2.3.4" in result["error"]

    @patch("dns_probe.httpx.Client")
    def test_json_api_nxdomain(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"Status": 3, "Answer": []}
        mock_client.get.return_value = mock_resp

        result = probe_doh("https://dns.google/dns-query", "nonexistent.test", "1.2.3.4")
        assert result["success"] is False
        assert "DNS status code 3" in result["error"]

    @patch("dns_probe.httpx.Client")
    def test_json_api_non200_falls_through_to_wireformat(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        # JSON API returns 404
        mock_404 = MagicMock()
        mock_404.status_code = 404
        mock_client.get.return_value = mock_404

        # Wireformat POST returns success
        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdatatype.A, dns.rdataclass.IN)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)

        mock_wire = MagicMock()
        mock_wire.status_code = 200
        mock_wire.content = msg.to_wire()
        mock_client.post.return_value = mock_wire

        result = probe_doh("https://dns.google/dns-query", "example.com", "93.184.216.34")
        assert result["success"] is True
        assert result["actual_ip"] == "93.184.216.34"

    @patch("dns_probe.httpx.Client")
    def test_json_api_timeout(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.get.side_effect = httpx.TimeoutException("timed out")

        result = probe_doh("https://dns.google/dns-query", "example.com", "93.184.216.34")
        assert result["success"] is False
        assert "timeout" in result["error"].lower()

    @patch("dns_probe.httpx.Client")
    def test_json_api_connection_error(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_client.get.side_effect = httpx.ConnectError("refused")

        result = probe_doh("https://dns.google/dns-query", "example.com", "93.184.216.34")
        assert result["success"] is False
        assert "connection error" in result["error"].lower()

    @patch("dns_probe.httpx.Client")
    def test_wireformat_fallback_success(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_404 = MagicMock()
        mock_404.status_code = 404
        mock_client.get.return_value = mock_404

        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdatatype.A, dns.rdataclass.IN)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = msg.to_wire()
        mock_client.post.return_value = mock_resp

        result = probe_doh("https://dns.google/dns-query", "example.com", "93.184.216.34")
        assert result["success"] is True
        assert result["actual_ip"] == "93.184.216.34"

    @patch("dns_probe.httpx.Client")
    def test_wireformat_non200(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_404 = MagicMock()
        mock_404.status_code = 404
        mock_client.get.return_value = mock_404

        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_client.post.return_value = mock_resp

        result = probe_doh("https://dns.google/dns-query", "example.com", "93.184.216.34")
        assert result["success"] is False
        assert "500" in result["error"]

    @patch("dns_probe.httpx.Client")
    def test_wireformat_timeout(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_404 = MagicMock()
        mock_404.status_code = 404
        mock_client.get.return_value = mock_404
        mock_client.post.side_effect = httpx.TimeoutException("timed out")

        result = probe_doh("https://dns.google/dns-query", "example.com", "93.184.216.34")
        assert result["success"] is False
        assert "timeout" in result["error"].lower()

    @patch("dns_probe.httpx.Client")
    def test_wireformat_connection_error(self, MockClient):
        mock_client = MagicMock()
        MockClient.return_value.__enter__ = MagicMock(return_value=mock_client)
        MockClient.return_value.__exit__ = MagicMock(return_value=False)

        mock_404 = MagicMock()
        mock_404.status_code = 404
        mock_client.get.return_value = mock_404
        mock_client.post.side_effect = httpx.ConnectError("refused")

        result = probe_doh("https://dns.google/dns-query", "example.com", "93.184.216.34")
        assert result["success"] is False
        assert "connection error" in result["error"].lower()


# ---------------------------------------------------------------------------
# probe_dot tests
# ---------------------------------------------------------------------------

class TestProbeDot:
    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    def test_dot_success(self, mock_conn, mock_resolve):
        mock_resolve.return_value = None  # host is already an IP

        # Build a fake TLS-wrapped socket
        inner_sock = MagicMock()
        tls_sock = MagicMock()

        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdatatype.A, dns.rdataclass.IN)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)
        response_wire = msg.to_wire()

        # Simulate: sendall succeeds, then recv returns length + data
        length_prefix = struct.pack("!H", len(response_wire))
        tls_sock.recv.side_effect = [length_prefix[:1], length_prefix[1:], response_wire[:5], response_wire[5:]]
        tls_sock.__enter__ = MagicMock(return_value=tls_sock)
        tls_sock.__exit__ = MagicMock(return_value=False)

        mock_conn.return_value.__enter__ = MagicMock(return_value=inner_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        # Mock ssl context
        with patch("dns_probe.ssl.create_default_context") as mock_ssl:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=tls_sock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_ssl.return_value = mock_ctx

            result = probe_dot("1.1.1.1", 853, "example.com", "93.184.216.34")
            assert result["success"] is True
            assert result["actual_ip"] == "93.184.216.34"

    @patch("dns_probe._resolve_hostname")
    def test_dot_host_resolution_failure(self, mock_resolve):
        mock_resolve.return_value = None

        result = probe_dot("dns.google", 853, "example.com", "93.184.216.34")
        assert result["success"] is False
        assert "Failed to resolve" in result["error"]

    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    def test_dot_tls_error(self, mock_conn, mock_resolve):
        mock_resolve.return_value = None
        import ssl as ssl_mod
        inner_sock = MagicMock()
        mock_conn.return_value.__enter__ = MagicMock(return_value=inner_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        with patch("dns_probe.ssl.create_default_context") as mock_ssl:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.side_effect = ssl_mod.SSLError("handshake failed")
            mock_ssl.return_value = mock_ctx

            result = probe_dot("1.1.1.1", 853, "example.com", "93.184.216.34")
            assert result["success"] is False
            assert "TLS error" in result["error"]

    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    def test_dot_timeout(self, mock_conn, mock_resolve):
        mock_resolve.return_value = None
        mock_conn.side_effect = socket.timeout("timed out")

        result = probe_dot("1.1.1.1", 853, "example.com", "93.184.216.34")
        assert result["success"] is False
        assert "timeout" in result["error"].lower()

    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    def test_dot_connection_refused(self, mock_conn, mock_resolve):
        mock_resolve.return_value = None
        mock_conn.side_effect = ConnectionRefusedError("Connection refused")

        result = probe_dot("1.1.1.1", 853, "example.com", "93.184.216.34")
        assert result["success"] is False
        assert "connection refused" in result["error"].lower()


class TestProbeDotHostnameVerification:
    """Tests for DOT_HOSTNAME and DOT_VERIFY_HOSTNAME in probe_dot."""

    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    def test_dot_hostname_used_as_server_hostname(self, mock_conn, mock_resolve):
        """When dot_hostname is set, it is used as server_hostname in wrap_socket."""
        mock_resolve.return_value = None

        inner_sock = MagicMock()
        tls_sock = MagicMock()

        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdatatype.A, dns.rdataclass.IN)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)
        response_wire = msg.to_wire()

        length_prefix = struct.pack("!H", len(response_wire))
        tls_sock.recv.side_effect = [length_prefix[:1], length_prefix[1:], response_wire[:5], response_wire[5:]]
        tls_sock.__enter__ = MagicMock(return_value=tls_sock)
        tls_sock.__exit__ = MagicMock(return_value=False)

        mock_conn.return_value.__enter__ = MagicMock(return_value=inner_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        with patch("dns_probe.ssl.create_default_context") as mock_ssl:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=tls_sock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_ssl.return_value = mock_ctx

            result = probe_dot(
                "188.245.192.196", 853, "example.com", "93.184.216.34",
                dot_hostname="dns1.example.com",
            )
            assert result["success"] is True
            # Verify wrap_socket was called with the custom hostname
            mock_ctx.wrap_socket.assert_called_once()
            call_args = mock_ctx.wrap_socket.call_args
            assert call_args[1]["server_hostname"] == "dns1.example.com"

    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    def test_dot_hostname_none_uses_host(self, mock_conn, mock_resolve):
        """When dot_hostname is None, the original host is used as server_hostname."""
        mock_resolve.return_value = "1.2.3.4"  # resolve hostname to an IP

        inner_sock = MagicMock()
        tls_sock = MagicMock()

        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdatatype.A, dns.rdataclass.IN)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)
        response_wire = msg.to_wire()

        length_prefix = struct.pack("!H", len(response_wire))
        tls_sock.recv.side_effect = [length_prefix[:1], length_prefix[1:], response_wire[:5], response_wire[5:]]
        tls_sock.__enter__ = MagicMock(return_value=tls_sock)
        tls_sock.__exit__ = MagicMock(return_value=False)

        mock_conn.return_value.__enter__ = MagicMock(return_value=inner_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        with patch("dns_probe.ssl.create_default_context") as mock_ssl:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=tls_sock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_ssl.return_value = mock_ctx

            result = probe_dot(
                "dns.google", 853, "example.com", "93.184.216.34",
                dot_hostname=None,
            )
            assert result["success"] is True
            mock_ctx.wrap_socket.assert_called_once()
            call_args = mock_ctx.wrap_socket.call_args
            assert call_args[1]["server_hostname"] == "dns.google"

    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    def test_dot_verify_hostname_false_skips_verification(self, mock_conn, mock_resolve):
        """When dot_verify_hostname=False, check_hostname=False and CERT_NONE are set."""
        mock_resolve.return_value = None

        inner_sock = MagicMock()
        tls_sock = MagicMock()

        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdatatype.A, dns.rdataclass.IN)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)
        response_wire = msg.to_wire()

        length_prefix = struct.pack("!H", len(response_wire))
        tls_sock.recv.side_effect = [length_prefix[:1], length_prefix[1:], response_wire[:5], response_wire[5:]]
        tls_sock.__enter__ = MagicMock(return_value=tls_sock)
        tls_sock.__exit__ = MagicMock(return_value=False)

        mock_conn.return_value.__enter__ = MagicMock(return_value=inner_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        with patch("dns_probe.ssl.create_default_context") as mock_ssl:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=tls_sock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_ssl.return_value = mock_ctx

            result = probe_dot(
                "188.245.192.196", 853, "example.com", "93.184.216.34",
                dot_verify_hostname=False,
            )
            assert result["success"] is True
            assert mock_ctx.check_hostname is False
            assert mock_ctx.verify_mode == ssl.CERT_NONE

    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    def test_dot_verify_hostname_true_preserves_default(self, mock_conn, mock_resolve):
        """When dot_verify_hostname=True (default), context is unchanged."""
        mock_resolve.return_value = None

        inner_sock = MagicMock()
        tls_sock = MagicMock()

        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        rrset = dns.rrset.RRset(dns.name.from_text("example.com."), dns.rdatatype.A, dns.rdataclass.IN)
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)
        response_wire = msg.to_wire()

        length_prefix = struct.pack("!H", len(response_wire))
        tls_sock.recv.side_effect = [length_prefix[:1], length_prefix[1:], response_wire[:5], response_wire[5:]]
        tls_sock.__enter__ = MagicMock(return_value=tls_sock)
        tls_sock.__exit__ = MagicMock(return_value=False)

        mock_conn.return_value.__enter__ = MagicMock(return_value=inner_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        with patch("dns_probe.ssl.create_default_context") as mock_ssl:
            mock_ctx = MagicMock()
            # Set default values to verify they're not overridden
            mock_ctx.check_hostname = True
            mock_ctx.verify_mode = ssl.CERT_REQUIRED
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=tls_sock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_ssl.return_value = mock_ctx

            result = probe_dot(
                "188.245.192.196", 853, "example.com", "93.184.216.34",
                dot_verify_hostname=True,
            )
            assert result["success"] is True
            # check_hostname and verify_mode should NOT be modified
            assert mock_ctx.check_hostname is True
            assert mock_ctx.verify_mode == ssl.CERT_REQUIRED


# ---------------------------------------------------------------------------
# _is_ip_address tests
# ---------------------------------------------------------------------------

class TestIsIpAddress:
    def test_valid_ipv4(self):
        assert _is_ip_address("1.2.3.4") is True

    def test_valid_ipv4_private(self):
        assert _is_ip_address("192.168.1.1") is True

    def test_hostname(self):
        assert _is_ip_address("dns.google") is False

    def test_empty_string(self):
        assert _is_ip_address("") is False

    def test_partial_ip(self):
        # inet_aton accepts 2-3 octet strings (pads internally), which is fine
        # since real IPs are always 4 octets from parse_target.
        assert _is_ip_address("1.2.3.4.5") is False


# ---------------------------------------------------------------------------
# _reverse_dns_lookup tests
# ---------------------------------------------------------------------------

class TestReverseDnsLookup:
    def setup_method(self):
        clear_ptr_cache()

    def teardown_method(self):
        clear_ptr_cache()

    @patch("dns_probe.dns.resolver.Resolver")
    def test_ptr_returns_hostname(self, MockResolver):
        """PTR lookup returns the hostname from a PTR record."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        # Simulate PTR answer
        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("one.one.one.one.")
        mock_resolver.resolve.return_value = [mock_rdata]

        result = _reverse_dns_lookup("1.1.1.1", "8.8.8.8")
        assert result == "one.one.one.one"

    @patch("dns_probe.dns.resolver.Resolver")
    def test_ptr_strips_trailing_dot(self, MockResolver):
        """PTR hostname has trailing dot stripped."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("example.com.")
        mock_resolver.resolve.return_value = [mock_rdata]

        result = _reverse_dns_lookup("93.184.216.34", "8.8.8.8")
        assert result == "example.com"
        assert not result.endswith(".")

    @patch("dns_probe.dns.resolver.Resolver")
    def test_ptr_failure_returns_none(self, MockResolver):
        """PTR lookup failure returns None."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        result = _reverse_dns_lookup("192.0.2.1", "8.8.8.8")
        assert result is None

    @patch("dns_probe.dns.resolver.Resolver")
    def test_ptr_caches_result(self, MockResolver):
        """Second call uses cache, not DNS query."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("cached.host.")
        mock_resolver.resolve.return_value = [mock_rdata]

        # First call — hits DNS
        r1 = _reverse_dns_lookup("10.0.0.1", "8.8.8.8")
        assert r1 == "cached.host"
        assert mock_resolver.resolve.call_count == 1

        # Second call — should use cache
        r2 = _reverse_dns_lookup("10.0.0.1", "8.8.8.8")
        assert r2 == "cached.host"
        assert mock_resolver.resolve.call_count == 1  # no additional call

    @patch("dns_probe.dns.resolver.Resolver")
    def test_ptr_cache_bypass(self, MockResolver):
        """use_cache=False forces a fresh DNS lookup."""
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver

        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("fresh.host.")
        mock_resolver.resolve.return_value = [mock_rdata]

        r1 = _reverse_dns_lookup("10.0.0.2", "8.8.8.8", use_cache=False)
        assert r1 == "fresh.host"
        r2 = _reverse_dns_lookup("10.0.0.2", "8.8.8.8", use_cache=False)
        assert mock_resolver.resolve.call_count == 2

    def test_clear_ptr_cache(self):
        """clear_ptr_cache empties the cache."""
        _ptr_cache[("1.2.3.4", "8.8.8.8")] = "cached"
        clear_ptr_cache()
        assert ("1.2.3.4", "8.8.8.8") not in _ptr_cache


# ---------------------------------------------------------------------------
# _determine_server_hostname tests
# ---------------------------------------------------------------------------

class TestDetermineServerHostname:
    """Tests for the hostname resolution logic used in probe_dot."""

    def setup_method(self):
        clear_ptr_cache()

    def teardown_method(self):
        clear_ptr_cache()

    @patch("dns_probe._reverse_dns_lookup")
    def test_explicit_hostname_takes_priority(self, mock_ptr):
        """DOT_HOSTNAME override is used even if PTR would return something."""
        host, _ptr = _determine_server_hostname(
            "188.245.192.196", "8.8.8.8", dot_hostname="dns1.example.com"
        )
        assert host == "dns1.example.com"
        mock_ptr.assert_not_called()

    @patch("dns_probe._reverse_dns_lookup")
    def test_ptr_derived_hostname(self, mock_ptr):
        """PTR lookup result is used as server_hostname when no override."""
        mock_ptr.return_value = "one.one.one.one"
        host, ptr = _determine_server_hostname("1.1.1.1", "8.8.8.8", None)
        assert host == "one.one.one.one"
        assert ptr == "one.one.one.one"

    @patch("dns_probe._reverse_dns_lookup")
    def test_ptr_fails_uses_raw_ip(self, mock_ptr):
        """When PTR returns None, raw IP is used as server_hostname."""
        mock_ptr.return_value = None
        host, ptr = _determine_server_hostname("188.245.192.196", "8.8.8.8", None)
        assert host == "188.245.192.196"
        assert ptr is None

    def test_hostname_not_ip_skips_ptr(self):
        """Non-IP hostnames skip PTR lookup entirely."""
        host, ptr = _determine_server_hostname("dns.google", "8.8.8.8", None)
        assert host == "dns.google"
        assert ptr is None

    @patch("dns_probe._reverse_dns_lookup")
    def test_explicit_hostname_skips_ptr_for_hostname(self, mock_ptr):
        """Explicit DOT_HOSTNAME with a hostname host still skips PTR."""
        host, _ptr = _determine_server_hostname("dns.google", "8.8.8.8", "my.custom.host")
        assert host == "my.custom.host"
        mock_ptr.assert_not_called()


# ---------------------------------------------------------------------------
# probe_dot with PTR lookup integration tests
# ---------------------------------------------------------------------------

class TestProbeDotWithPtr:
    """Integration tests for probe_dot using PTR-derived hostnames."""

    def setup_method(self):
        clear_ptr_cache()

    def teardown_method(self):
        clear_ptr_cache()

    @patch("dns_probe._reverse_dns_lookup")
    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    def test_ptr_hostname_used_for_sni(self, mock_conn, mock_resolve, mock_ptr):
        """When PTR returns a hostname, it is used as TLS server_hostname."""
        mock_resolve.return_value = None  # host is already an IP
        mock_ptr.return_value = "one.one.one.one"

        inner_sock = MagicMock()
        tls_sock = MagicMock()

        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        rrset = dns.rrset.RRset(
            dns.name.from_text("example.com."),
            dns.rdatatype.A,
            dns.rdataclass.IN,
        )
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)
        response_wire = msg.to_wire()

        length_prefix = struct.pack("!H", len(response_wire))
        tls_sock.recv.side_effect = [
            length_prefix[:1], length_prefix[1:],
            response_wire[:5], response_wire[5:],
        ]
        tls_sock.__enter__ = MagicMock(return_value=tls_sock)
        tls_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value.__enter__ = MagicMock(return_value=inner_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        with patch("dns_probe.ssl.create_default_context") as mock_ssl:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=tls_sock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_ssl.return_value = mock_ctx

            result = probe_dot(
                "1.1.1.1", 853, "example.com", "93.184.216.34",
            )
            assert result["success"] is True
            # Verify PTR-derived hostname was used for SNI
            mock_ctx.wrap_socket.assert_called_once()
            call_args = mock_ctx.wrap_socket.call_args
            assert call_args[1]["server_hostname"] == "one.one.one.one"

    @patch("dns_probe._reverse_dns_lookup")
    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    def test_explicit_hostname_overrides_ptr(self, mock_conn, mock_resolve, mock_ptr):
        """DOT_HOSTNAME override takes priority over PTR lookup."""
        mock_resolve.return_value = None
        mock_ptr.return_value = "one.one.one.one"  # PTR would return this

        inner_sock = MagicMock()
        tls_sock = MagicMock()

        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        rrset = dns.rrset.RRset(
            dns.name.from_text("example.com."),
            dns.rdatatype.A,
            dns.rdataclass.IN,
        )
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)
        response_wire = msg.to_wire()

        length_prefix = struct.pack("!H", len(response_wire))
        tls_sock.recv.side_effect = [
            length_prefix[:1], length_prefix[1:],
            response_wire[:5], response_wire[5:],
        ]
        tls_sock.__enter__ = MagicMock(return_value=tls_sock)
        tls_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value.__enter__ = MagicMock(return_value=inner_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        with patch("dns_probe.ssl.create_default_context") as mock_ssl:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=tls_sock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_ssl.return_value = mock_ctx

            result = probe_dot(
                "188.245.192.196", 853, "example.com", "93.184.216.34",
                dot_hostname="dns1.example.com",
            )
            assert result["success"] is True
            mock_ctx.wrap_socket.assert_called_once()
            call_args = mock_ctx.wrap_socket.call_args
            # Explicit hostname wins over PTR
            assert call_args[1]["server_hostname"] == "dns1.example.com"
            mock_ptr.assert_not_called()

    @patch("dns_probe._reverse_dns_lookup")
    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    def test_ptr_fails_falls_back_to_raw_ip(self, mock_conn, mock_resolve, mock_ptr):
        """When PTR fails, raw IP is used as server_hostname (cert may fail)."""
        mock_resolve.return_value = None
        mock_ptr.return_value = None

        inner_sock = MagicMock()
        tls_sock = MagicMock()

        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        rrset = dns.rrset.RRset(
            dns.name.from_text("example.com."),
            dns.rdatatype.A,
            dns.rdataclass.IN,
        )
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)
        response_wire = msg.to_wire()

        length_prefix = struct.pack("!H", len(response_wire))
        tls_sock.recv.side_effect = [
            length_prefix[:1], length_prefix[1:],
            response_wire[:5], response_wire[5:],
        ]
        tls_sock.__enter__ = MagicMock(return_value=tls_sock)
        tls_sock.__exit__ = MagicMock(return_value=False)
        mock_conn.return_value.__enter__ = MagicMock(return_value=inner_sock)
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        with patch("dns_probe.ssl.create_default_context") as mock_ssl:
            mock_ctx = MagicMock()
            mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=tls_sock)
            mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
            mock_ssl.return_value = mock_ctx

            # Use dot_verify_hostname=False so cert check doesn't fail
            result = probe_dot(
                "188.245.192.196", 853, "example.com", "93.184.216.34",
                dot_verify_hostname=False,
            )
            assert result["success"] is True
            mock_ctx.wrap_socket.assert_called_once()
            call_args = mock_ctx.wrap_socket.call_args
            # Falls back to raw IP
            assert call_args[1]["server_hostname"] == "188.245.192.196"

    @patch("dns_probe._resolve_hostname")
    @patch("dns_probe.socket.create_connection")
    @patch("dns_probe.dns.resolver.Resolver")
    def test_ptr_cached_across_cycles(self, MockResolver, mock_conn, mock_resolve):
        """PTR is only resolved once (cached), not per probe cycle."""
        mock_resolve.return_value = None  # host is already an IP

        # Mock the resolver to return a PTR record
        mock_resolver = MagicMock()
        MockResolver.return_value = mock_resolver
        mock_rdata = MagicMock()
        mock_rdata.target = dns.name.from_text("cached.host.")
        mock_resolver.resolve.return_value = [mock_rdata]

        def _make_recv_side_effect(response_wire):
            length_prefix = struct.pack("!H", len(response_wire))
            return [length_prefix[:1], length_prefix[1:], response_wire[:5], response_wire[5:]]

        # Build the DNS response wire data once
        msg = dns.message.make_response(dns.message.make_query("example.com", "A"))
        rrset = dns.rrset.RRset(
            dns.name.from_text("example.com."),
            dns.rdatatype.A,
            dns.rdataclass.IN,
        )
        rrset.add(dns.rdata.from_text(dns.rdataclass.IN, dns.rdatatype.A, "93.184.216.34"))
        msg.answer.append(rrset)
        response_wire = msg.to_wire()

        # Simulate two probe cycles, each with a fresh TLS socket mock
        for _ in range(2):
            inner_sock = MagicMock()
            tls_sock = MagicMock()
            tls_sock.recv.side_effect = _make_recv_side_effect(response_wire)
            tls_sock.__enter__ = MagicMock(return_value=tls_sock)
            tls_sock.__exit__ = MagicMock(return_value=False)
            mock_conn.return_value.__enter__ = MagicMock(return_value=inner_sock)
            mock_conn.return_value.__exit__ = MagicMock(return_value=False)

            with patch("dns_probe.ssl.create_default_context") as mock_ssl:
                mock_ctx = MagicMock()
                mock_ctx.wrap_socket.return_value.__enter__ = MagicMock(return_value=tls_sock)
                mock_ctx.wrap_socket.return_value.__exit__ = MagicMock(return_value=False)
                mock_ssl.return_value = mock_ctx

                result = probe_dot(
                    "1.1.1.1", 853, "example.com", "93.184.216.34",
                )
                assert result["success"] is True

        # PTR resolve() should only be called once (first call populates cache)
        assert mock_resolver.resolve.call_count == 1


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
