import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from datetime import datetime, timezone
from kaliauto.findings import ModuleUnavailable
from kaliauto.modules import dns, headers, ports, tls

NOW = datetime(2026, 10, 30, tzinfo=timezone.utc)


def test_healthy_certificate_raises_nothing():
    assert tls.grade({"protocol": "TLSv1.3", "expires": "Mar 01 00:00:00 2027 GMT"}, "h", now=NOW) == []


def test_expired_certificate_is_high():
    ids = [f.check_id for f in tls.grade({"protocol": "TLSv1.3", "expires": "Jan 01 00:00:00 2020 GMT"}, "h", now=NOW)]
    assert "KAT001" in ids


def test_certificate_expiring_within_30_days_is_medium():
    found = tls.grade({"protocol": "TLSv1.3", "expires": "Nov 10 00:00:00 2026 GMT"}, "h", now=NOW)
    assert [f.check_id for f in found] == ["KAT002"]


def test_tls_1_1_is_high():
    found = tls.grade({"protocol": "TLSv1.1", "expires": "Mar 01 00:00:00 2027 GMT"}, "h", now=NOW)
    assert found[0].check_id == "KAT003" and found[0].severity == "high"


def test_unverified_certificate_is_high():
    assert tls.grade({"verified": False, "error": "self signed"}, "h", now=NOW)[0].check_id == "KAT004"


def test_header_free_response_flags_the_four_missing_controls():
    assert {f.check_id for f in headers.grade({}, "h")} == {"KAH001", "KAH002", "KAH003", "KAH004"}


def test_hardened_headers_without_banners_are_clean():
    h = {"strict-transport-security": "max-age=63072000",
         "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
         "x-content-type-options": "nosniff", "x-frame-options": "DENY", "server": "nginx"}
    assert headers.grade(h, "h") == []


def test_version_banner_is_flagged():
    found = headers.grade({"strict-transport-security": "x", "content-security-policy": "y",
                           "x-content-type-options": "z", "x-frame-options": "w", "server": "nginx/1.18.0"}, "h")
    assert [f.check_id for f in found] == ["KAH005"]


def test_risky_open_ports_reported_and_closed_ones_ignored():
    out = "Host: 10.0.0.1 (h)\tPorts: 22/open/tcp//ssh///, 6379/open/tcp//redis///, 6379/closed/tcp//redis///"
    found = ports.parse_greppable(out, "h")
    assert len(found) == 1 and "6379" in found[0].detail


def test_nmap_argv_is_fixed_and_carries_no_user_flags():
    args = ports.argv("example.com", 5.0)
    assert args[:2] == ["nmap", "-sT"] and "--script" not in args and "-A" not in args
    assert args[-1] == "example.com" and "-oG" in args


def test_missing_dns_records_are_flagged():
    def records(host, rrtype):
        return ["v=spf1 -all"] if rrtype == "TXT" else []
    found = {f.check_id for f in dns.run("h", addresses=lambda t: ["10.0.0.1"], records=records)}
    assert {"KAD002", "KAD003"} <= found and "KAD004" not in found


def test_unresolvable_name_stops_early():
    import socket
    def boom(t):
        raise socket.gaierror("nope")
    assert dns.run("h", addresses=boom)[0].check_id == "KAD000"


def test_dns_without_resolver_client_is_honest(monkeypatch):
    def no_dig(host, rrtype, runner=None):
        raise ModuleUnavailable("dig missing")
    monkeypatch.setattr(dns, "_dig", no_dig)
    assert [f.check_id for f in dns.run("h", addresses=lambda t: ["10.0.0.1"])] == ["KAD900"]
