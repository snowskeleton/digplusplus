"""Tests for dnstools.py: validation, lookup(), and trace()."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import dns.exception
import dns.flags
import dns.rcode
import dns.resolver
import dns.rrset
import pytest

import dnstools


class FakeResponse:
    """Minimal stand-in for a dns.message.Message, exposing just what
    dnstools reads: rcode() and flags."""

    def __init__(self, rcode=dns.rcode.NOERROR, flags=0):
        self._rcode = rcode
        self.flags = flags

    def rcode(self):
        return self._rcode


def make_rrset(name, ttl, rdtype, *rdatas):
    return dns.rrset.from_text(name, ttl, "IN", rdtype, *rdatas)


# ---------------------------------------------------------------------------
# validate_domain
# ---------------------------------------------------------------------------

class TestValidateDomain:
    def test_simple_domain(self):
        assert dnstools.validate_domain("example.com") == "example.com"

    def test_strips_whitespace(self):
        assert dnstools.validate_domain("  example.com  ") == "example.com"

    def test_underscore_label_dmarc(self):
        assert dnstools.validate_domain("_dmarc.example.com") == "_dmarc.example.com"

    def test_underscore_label_domainkey(self):
        assert dnstools.validate_domain("selector1._domainkey.example.com") == (
            "selector1._domainkey.example.com"
        )

    def test_underscore_srv_style(self):
        assert dnstools.validate_domain("_sip._tcp.example.com") == "_sip._tcp.example.com"

    def test_trailing_dot_allowed(self):
        assert dnstools.validate_domain("example.com.") == "example.com."

    def test_empty_domain_raises(self):
        with pytest.raises(dnstools.InvalidInputError):
            dnstools.validate_domain("")

    def test_none_domain_raises(self):
        with pytest.raises(dnstools.InvalidInputError):
            dnstools.validate_domain(None)

    def test_leading_hyphen_label_raises(self):
        with pytest.raises(dnstools.InvalidInputError):
            dnstools.validate_domain("-example.com")

    def test_trailing_hyphen_label_raises(self):
        with pytest.raises(dnstools.InvalidInputError):
            dnstools.validate_domain("example-.com")

    def test_invalid_characters_raise(self):
        with pytest.raises(dnstools.InvalidInputError):
            dnstools.validate_domain("exa mple.com")

    def test_ptr_converts_ipv4(self):
        result = dnstools.validate_domain("93.184.216.34", rdtype="PTR")
        assert result == "34.216.184.93.in-addr.arpa."

    def test_ptr_converts_ipv6(self):
        result = dnstools.validate_domain("2001:db8::1", rdtype="PTR")
        assert result.endswith("ip6.arpa.")

    def test_ptr_non_ip_falls_back_to_hostname_validation(self):
        result = dnstools.validate_domain("example.com", rdtype="PTR")
        assert result == "example.com"


# ---------------------------------------------------------------------------
# validate_server
# ---------------------------------------------------------------------------

class TestValidateServer:
    def test_none_returns_none(self):
        assert dnstools.validate_server(None) is None

    def test_empty_string_returns_none(self):
        assert dnstools.validate_server("") is None

    def test_valid_ipv4(self):
        assert dnstools.validate_server("8.8.8.8") == "8.8.8.8"

    def test_valid_ipv6(self):
        assert dnstools.validate_server("::1") == "::1"

    def test_invalid_ip_raises(self):
        with pytest.raises(dnstools.InvalidInputError):
            dnstools.validate_server("not-an-ip")

    def test_hostname_not_allowed(self):
        with pytest.raises(dnstools.InvalidInputError):
            dnstools.validate_server("dns.google")


# ---------------------------------------------------------------------------
# validate_rdtype
# ---------------------------------------------------------------------------

class TestValidateRdtype:
    def test_default_is_a(self):
        assert dnstools.validate_rdtype(None) == "A"

    def test_lowercase_uppercased(self):
        assert dnstools.validate_rdtype("mx") == "MX"

    def test_unsupported_type_raises(self):
        with pytest.raises(dnstools.InvalidInputError):
            dnstools.validate_rdtype("BOGUS")


# ---------------------------------------------------------------------------
# lookup()
# ---------------------------------------------------------------------------

class TestLookup:
    def test_noerror_full(self, monkeypatch):
        rrset = make_rrset("example.com.", 300, "A", "93.184.216.34")
        answer = SimpleNamespace(rrset=rrset, response=FakeResponse(flags=dns.flags.AA))
        resolver_instance = MagicMock()
        resolver_instance.resolve.return_value = answer
        monkeypatch.setattr(
            dnstools.dns.resolver, "Resolver", MagicMock(return_value=resolver_instance)
        )

        result = dnstools.lookup("example.com", "A")

        assert result["rcode"] == "NOERROR"
        assert result["authoritative"] is True
        assert result["answers"] == [
            {"name": "example.com.", "ttl": 300, "type": "A", "data": "93.184.216.34"}
        ]

    def test_short_mode(self, monkeypatch):
        rrset = make_rrset("example.com.", 300, "A", "93.184.216.34", "93.184.216.35")
        answer = SimpleNamespace(rrset=rrset, response=FakeResponse())
        resolver_instance = MagicMock()
        resolver_instance.resolve.return_value = answer
        monkeypatch.setattr(
            dnstools.dns.resolver, "Resolver", MagicMock(return_value=resolver_instance)
        )

        result = dnstools.lookup("example.com", "A", short=True)

        assert set(result["answers"]) == {"93.184.216.34", "93.184.216.35"}
        assert "rcode" not in result

    def test_nxdomain_is_valid_result(self, monkeypatch):
        resolver_instance = MagicMock()
        resolver_instance.resolve.side_effect = dns.resolver.NXDOMAIN()
        monkeypatch.setattr(
            dnstools.dns.resolver, "Resolver", MagicMock(return_value=resolver_instance)
        )

        result = dnstools.lookup("thisdomaindoesnotexist12345.com", "A")

        assert result["rcode"] == "NXDOMAIN"
        assert result["answers"] == []

    def test_no_answer_returns_empty_answers(self, monkeypatch):
        answer = SimpleNamespace(rrset=None, response=FakeResponse())
        resolver_instance = MagicMock()
        resolver_instance.resolve.return_value = answer
        monkeypatch.setattr(
            dnstools.dns.resolver, "Resolver", MagicMock(return_value=resolver_instance)
        )

        result = dnstools.lookup("example.com", "MX")

        assert result["answers"] == []

    def test_timeout_raises_digerror(self, monkeypatch):
        resolver_instance = MagicMock()
        resolver_instance.resolve.side_effect = dns.exception.Timeout(timeout=5.0)
        monkeypatch.setattr(
            dnstools.dns.resolver, "Resolver", MagicMock(return_value=resolver_instance)
        )

        with pytest.raises(dnstools.DigError) as exc_info:
            dnstools.lookup("example.com", "A", server="192.0.2.1")

        assert exc_info.value.code == "timeout"

    def test_no_nameservers_raises_digerror(self, monkeypatch):
        resolver_instance = MagicMock()
        resolver_instance.resolve.side_effect = dns.resolver.NoNameservers(
            request=MagicMock(), errors=[]
        )
        monkeypatch.setattr(
            dnstools.dns.resolver, "Resolver", MagicMock(return_value=resolver_instance)
        )

        with pytest.raises(dnstools.DigError) as exc_info:
            dnstools.lookup("example.com", "A", server="192.0.2.1")

        assert exc_info.value.code == "no_nameservers"

    def test_custom_server_used(self, monkeypatch):
        rrset = make_rrset("example.com.", 300, "A", "93.184.216.34")
        answer = SimpleNamespace(rrset=rrset, response=FakeResponse())
        resolver_instance = MagicMock()
        resolver_instance.resolve.return_value = answer
        monkeypatch.setattr(
            dnstools.dns.resolver, "Resolver", MagicMock(return_value=resolver_instance)
        )

        dnstools.lookup("example.com", "A", server="1.1.1.1")

        assert resolver_instance.nameservers == ["1.1.1.1"]


# ---------------------------------------------------------------------------
# trace()
# ---------------------------------------------------------------------------

def _msg(text):
    import dns.message

    return dns.message.from_text(text)


ROOT_REFERRAL = _msg(
    """id 1
opcode QUERY
rcode NOERROR
flags QR
;QUESTION
example.com. IN A
;ANSWER
;AUTHORITY
com. 172800 IN NS a.gtld-servers.net.
;ADDITIONAL
a.gtld-servers.net. 172800 IN A 192.5.6.30
"""
)

TLD_REFERRAL = _msg(
    """id 2
opcode QUERY
rcode NOERROR
flags QR
;QUESTION
example.com. IN A
;ANSWER
;AUTHORITY
example.com. 172800 IN NS ns1.example.com.
;ADDITIONAL
ns1.example.com. 172800 IN A 1.2.3.4
"""
)

FINAL_ANSWER = _msg(
    """id 3
opcode QUERY
rcode NOERROR
flags QR AA
;QUESTION
example.com. IN A
;ANSWER
example.com. 300 IN A 93.184.216.34
;AUTHORITY
;ADDITIONAL
"""
)

NXDOMAIN_RESPONSE = _msg(
    """id 4
opcode QUERY
rcode NXDOMAIN
flags QR AA
;QUESTION
nonexistent.example. IN A
;ANSWER
;AUTHORITY
;ADDITIONAL
"""
)

CNAME_RESPONSE = _msg(
    """id 5
opcode QUERY
rcode NOERROR
flags QR AA
;QUESTION
www.example.com. IN A
;ANSWER
www.example.com. 300 IN CNAME example.com.
;AUTHORITY
;ADDITIONAL
"""
)


class TestTrace:
    def test_full_delegation_chain(self, monkeypatch):
        responses = {
            "198.41.0.4": ROOT_REFERRAL,
            "192.5.6.30": TLD_REFERRAL,
            "1.2.3.4": FINAL_ANSWER,
        }

        def fake_udp(q, ip, timeout=None):
            if ip not in responses:
                raise OSError(f"unexpected server {ip}")
            return responses[ip]

        monkeypatch.setattr(dnstools.dns.query, "udp", fake_udp)

        result = dnstools.trace("example.com", "A")

        assert result["error"] is None
        assert len(result["hops"]) == 3
        assert result["hops"][0]["referral"][0]["ns"] == "a.gtld-servers.net."
        assert result["hops"][1]["referral"][0]["ns"] == "ns1.example.com."
        assert result["hops"][2]["answers"][0]["data"] == "93.184.216.34"
        assert result["final_answer"]["answers"][0]["data"] == "93.184.216.34"

    def test_nxdomain_stops_trace(self, monkeypatch):
        def fake_udp(q, ip, timeout=None):
            return NXDOMAIN_RESPONSE

        monkeypatch.setattr(dnstools.dns.query, "udp", fake_udp)

        result = dnstools.trace("nonexistent.example", "A")

        assert result["error"] is not None
        assert result["hops"][-1]["rcode"] == "NXDOMAIN"

    def test_cname_restart(self, monkeypatch):
        call_log = []

        def fake_udp(q, ip, timeout=None):
            qname = q.question[0].name.to_text()
            call_log.append((ip, qname))
            if qname == "www.example.com.":
                return CNAME_RESPONSE
            if qname == "example.com." and ip == "198.41.0.4":
                return FINAL_ANSWER
            raise OSError(f"unexpected query {ip} {qname}")

        monkeypatch.setattr(dnstools.dns.query, "udp", fake_udp)

        result = dnstools.trace("www.example.com", "A")

        assert result["error"] is None
        assert result["hops"][0]["cname"] == "example.com."
        assert result["hops"][1]["answers"][0]["data"] == "93.184.216.34"

    def test_no_reachable_server_sets_error(self, monkeypatch):
        def fake_udp(q, ip, timeout=None):
            raise OSError("unreachable")

        monkeypatch.setattr(dnstools.dns.query, "udp", fake_udp)

        result = dnstools.trace("example.com", "A")

        assert result["error"] == "No reachable nameserver could be queried for this hop."
        assert result["hops"] == []
