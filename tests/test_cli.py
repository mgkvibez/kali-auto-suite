import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest
from kaliauto import cli
from kaliauto.audit import AuditLog
from kaliauto.findings import Finding, ModuleUnavailable

FIX = pathlib.Path(__file__).parent / "fixtures"
GOOD = str(FIX / "scope.good.json")


@pytest.fixture(autouse=True)
def isolated_audit(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    yield


def test_dry_run_is_the_default_and_sends_nothing(capsys, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("a dry run must not execute any module")
    monkeypatch.setattr(cli, "run_module", forbidden)
    assert cli.main(["scan", "--scope", GOOD, "--targets", "example.com"]) == cli.EXIT_CLEAN
    out = capsys.readouterr().out
    assert "dry run" in out and "nothing has been sent" in out


def test_dry_run_still_records_a_plan(tmp_path):
    cli.main(["scan", "--scope", GOOD, "--targets", "example.com"])
    events = [e["event"] for e in AuditLog().entries()]
    assert "plan" in events


def test_out_of_scope_target_is_refused_with_exit_4(tmp_path, capsys):
    assert cli.main(["scan", "--scope", GOOD, "--targets", "evil.example.org"]) == cli.EXIT_REFUSED
    assert "refused" in capsys.readouterr().err
    assert [e["event"] for e in AuditLog().entries()] == ["refused"]


def test_missing_authorization_is_refused(capsys):
    assert cli.main(["scan", "--scope", str(FIX / "scope.noauth.json")]) == cli.EXIT_REFUSED
    assert "authorized_by" in capsys.readouterr().err


def test_findings_produce_exit_3_and_valid_json(capsys, monkeypatch):
    monkeypatch.setattr(cli, "run_module", lambda m, t, timeout=0: [
        Finding("KAT001", "Certificate has expired", "high", t, "expired 5 day(s) ago")])
    assert cli.main(["scan", "--scope", GOOD, "--targets", "example.com",
                     "--modules", "tls", "--execute", "--json"]) == cli.EXIT_FINDINGS
    doc = json.loads(capsys.readouterr().out)
    assert doc["findings"][0]["check"] == "KAT001" and doc["scope"]["sha256"]


def test_clean_execute_says_none_found_by_checkset(capsys, monkeypatch):
    monkeypatch.setattr(cli, "run_module", lambda m, t, timeout=0: [])
    assert cli.main(["scan", "--scope", GOOD, "--targets", "example.com",
                     "--modules", "tls", "--execute"]) == cli.EXIT_CLEAN
    out = capsys.readouterr().out
    assert "No issues found by checkset v1" in out and "safe." not in out


def test_missing_dependency_is_reported_not_guessed(capsys, monkeypatch):
    def unavailable(*a, **k):
        raise ModuleUnavailable("nmap is not installed")
    monkeypatch.setattr(cli, "run_module", unavailable)
    assert cli.main(["scan", "--scope", GOOD, "--targets", "example.com",
                     "--modules", "ports", "--execute"]) == cli.EXIT_DEPENDENCY
    assert "nmap is not installed" in capsys.readouterr().out


def test_unknown_module_is_a_usage_error(capsys):
    assert cli.main(["scan", "--scope", GOOD, "--modules", "exploit"]) == cli.EXIT_USAGE
    assert "unknown module" in capsys.readouterr().err


def test_modules_and_scope_commands(capsys):
    assert cli.main(["modules"]) == cli.EXIT_CLEAN
    assert "dns" in capsys.readouterr().out
    assert cli.main(["scope", "--scope", GOOD]) == cli.EXIT_CLEAN
    assert "authorized:" in capsys.readouterr().out


def test_no_subcommand_is_a_usage_error():
    assert cli.main([]) == cli.EXIT_USAGE


def test_audit_records_each_module_start(capsys, monkeypatch):
    monkeypatch.setattr(cli, "run_module", lambda m, t, timeout=0: [])
    cli.main(["scan", "--scope", GOOD, "--targets", "example.com",
              "--modules", "tls,dns", "--execute"])
    starts = [e for e in AuditLog().entries() if e["event"] == "module_start"]
    assert [e["module"] for e in starts] == ["tls", "dns"]
    assert all(e["target"] == "example.com" for e in starts)
