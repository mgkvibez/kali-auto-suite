import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest
from kaliauto.audit import AuditLog, redact
from kaliauto.ratelimit import RateLimiter


def test_audit_appends_and_reads_back(tmp_path):
    log = AuditLog(path=str(tmp_path / "audit.jsonl"))
    log.record("plan", scope="s.json", targets=["example.com"])
    log.record("refused", reason="out of scope")
    entries = log.entries()
    assert [e["event"] for e in entries] == ["plan", "refused"]
    assert all("iso" in e and "ts" in e for e in entries)


def test_audit_redacts_secretish_values(tmp_path):
    log = AuditLog(path=str(tmp_path / "audit.jsonl"))
    log.record("module_start", note="using token=abc123")
    assert "abc123" not in log.entries()[0]["note"]


def test_redact_leaves_ordinary_text_alone():
    assert redact("port 22 open") == "port 22 open"


def test_refusal_is_recorded_not_dropped(tmp_path):
    log = AuditLog(path=str(tmp_path / "audit.jsonl"))
    entry = log.record("refused", reason="'evil.org' is not listed")
    assert entry["event"] == "refused" and "evil.org" in entry["reason"]


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.slept = []

    def clock(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


def test_limiter_sleeps_to_keep_the_interval():
    fc = FakeClock()
    rl = RateLimiter(per_second=1.0, clock=fc.clock, sleep=fc.sleep)
    rl.wait("h"); rl.wait("h")
    assert fc.slept and abs(fc.slept[0] - 1.0) < 1e-9


def test_limiter_does_not_sleep_when_interval_has_passed():
    fc = FakeClock()
    rl = RateLimiter(per_second=1.0, clock=fc.clock, sleep=fc.sleep)
    rl.wait("h"); fc.now += 5.0; rl.wait("h")
    assert fc.slept == []


def test_limiter_is_per_host():
    fc = FakeClock()
    rl = RateLimiter(per_second=1.0, clock=fc.clock, sleep=fc.sleep)
    rl.wait("a"); rl.wait("b")
    assert fc.slept == []


def test_zero_rate_is_rejected():
    with pytest.raises(ValueError):
        RateLimiter(per_second=0)
