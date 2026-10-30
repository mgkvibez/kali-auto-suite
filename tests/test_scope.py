import json, pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import pytest
from kaliauto.scope import (MissingAuthorization, OutOfScope, UnsafeTarget, authorize,
                           load_scope, targets_for_run)

FIX = pathlib.Path(__file__).parent / "fixtures"


def scope(name="scope.good.json"):
    return load_scope(str(FIX / name))


def test_good_scope_loads_with_stable_fingerprint():
    a, b = scope(), scope()
    assert a.fingerprint() == b.fingerprint() and len(a.fingerprint()) == 12


def test_missing_authorization_fields_are_refused():
    with pytest.raises(MissingAuthorization) as exc:
        load_scope(str(FIX / "scope.noauth.json"))
    assert "authorized_by" in str(exc.value) or "contact" in str(exc.value)


def test_absent_file_is_refused():
    with pytest.raises(MissingAuthorization):
        load_scope(str(FIX / "nope.json"))


def test_broken_json_is_refused(tmp_path):
    bad = tmp_path / "scope.json"; bad.write_text("{not json")
    with pytest.raises(MissingAuthorization):
        load_scope(str(bad))


def test_no_targets_is_refused(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"authorized_by": "x", "authorized_on": "2026-10-30",
                             "contact": "c", "authorization_reference": "r", "targets": []}))
    with pytest.raises(MissingAuthorization):
        load_scope(str(p))


def test_target_outside_scope_is_refused():
    with pytest.raises(OutOfScope):
        authorize(scope(), "not-listed.example.org")


def test_listed_target_passes():
    assert authorize(scope(), "example.com") == "example.com"


def test_wildcard_covers_subdomains_only():
    s = scope()
    assert authorize(s, "a.internal.example") == "a.internal.example"
    with pytest.raises(OutOfScope):
        authorize(s, "internal.example.evil.org")


def test_cidr_target_matches_member_address(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({"authorized_by": "x", "authorized_on": "2026-10-30", "contact": "c",
                             "authorization_reference": "r", "allow_private": True,
                             "targets": ["10.20.30.0/30"]}))
    s = load_scope(str(p))
    assert authorize(s, "10.20.30.2") == "10.20.30.2"
    with pytest.raises(OutOfScope):
        authorize(s, "10.20.30.9")


def test_private_range_needs_explicit_opt_in():
    with pytest.raises(OutOfScope) as exc:
        authorize(scope("scope.private.json"), "10.1.2.3")
    assert "allow_private" in str(exc.value)


@pytest.mark.parametrize("hostile", [
    "example.com; id", "$(id)", "example.com && curl http://x",
    "exa mple.com", "`id`", "example.com\nother.com", "example.com | tee /tmp/x",
])
def test_shell_metacharacters_and_spaces_are_refused(hostile):
    with pytest.raises(UnsafeTarget):
        authorize(scope(), hostile)


def test_targets_for_run_dedupes_and_keeps_order():
    assert targets_for_run(scope(), ["example.com", "example.com", "127.0.0.1"]) == ["example.com", "127.0.0.1"]
