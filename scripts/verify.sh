#!/usr/bin/env bash
# Release gate for kaliauto: run before every push that claims "done".
set -uo pipefail
fail() { echo "GATE FAILED: $1"; exit 1; }

echo "== check 1/5: install"
python3 -m pip install -q -e ".[dev]" || fail "install"

echo "== check 2/5: version consistency (pyproject vs module)"
pv=$(python3 - <<'PY'
import pathlib, re
try:
    import tomllib
    print(tomllib.loads(pathlib.Path("pyproject.toml").read_text())["project"]["version"])
except ModuleNotFoundError:
    print(re.search(r'(?m)^version\s*=\s*"([^"]+)"', pathlib.Path("pyproject.toml").read_text()).group(1))
PY
)
mv=$(python3 -c "import kaliauto;print(kaliauto.__version__)")
[ "$pv" = "$mv" ] || fail "pyproject says $pv, module says $mv"

echo "== check 3/5: test suite"
python3 -m pytest tests -q || fail "tests"

echo "== check 4/5: CLI contract (dry run 0, refusal 4, bad module 2)"
out=$(mktemp)
python3 -m kaliauto.cli scan --scope tests/fixtures/scope.good.json --targets example.com >"$out" 2>&1
[ $? -eq 0 ] || fail "dry run should exit 0"
grep -q "nothing has been sent" "$out" || fail "dry run did not say it sent nothing"
python3 -m kaliauto.cli scan --scope tests/fixtures/scope.good.json --targets evil.example.org >/dev/null 2>&1
[ $? -eq 4 ] || fail "out-of-scope target should exit 4"
python3 -m kaliauto.cli scan --scope tests/fixtures/scope.good.json --modules exploit >/dev/null 2>&1
[ $? -eq 2 ] || fail "unknown module should exit 2"
echo "contract ok (0 / 4 / 2)"
python3 - "$out" <<'PY'
import os, sys
os.unlink(sys.argv[1])
PY

echo "== check 5/5: the built wheel contains the package"
tmpd=$(mktemp -d); blog=$(mktemp)
if ! python3 -m build --wheel --outdir "$tmpd" >"$blog" 2>&1; then
  echo "wheel build failed:"; tail -5 "$blog"; exit 1
fi
python3 - "$tmpd" <<'PY'
import glob, shutil, sys, zipfile
matches = glob.glob(sys.argv[1] + "/*.whl")
if not matches:
    sys.exit("no wheel produced")
names = [n for n in zipfile.ZipFile(matches[0]).namelist() if n.startswith("kaliauto/") and n.endswith(".py")]
shutil.rmtree(sys.argv[1], ignore_errors=True)
if len(names) < 8:
    sys.exit("wheel has %d module file(s); the package is incomplete" % len(names))
PY
[ $? -eq 0 ] || fail "wheel is missing package files; an editable install hides this"
echo "wheel contains the package"

echo "ALL CHECKS PASSED"
