# Changelog

## v0.1.0 - 2026-10-30

- First release: scope-gated, dry-run-by-default recon over four fixed modules (dns, tls, headers, ports).
- Refusals are audited, private ranges need explicit opt-in, targets validated before they reach an argv list.
- Exit codes 0/3/4/5/2 as a contract; 50 offline tests; 5-check release gate.
