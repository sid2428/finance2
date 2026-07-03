# Security Policy

AEGIS is a compliance and interdiction control plane: the system that signs the
audit ledger must itself withstand audit. Security reports are treated as
priority work.

## Reporting a vulnerability

**Do not open a public issue for security vulnerabilities.**

Email **kartikgaikwad2828@gmail.com** with:

- A description of the vulnerability and the component affected
  (`aegis/pipeline`, `aegis/ap2`, `aegis/ledger`, gateway, providers, …)
- Reproduction steps or a proof-of-concept
- The impact you believe it has (e.g. "a crafted mandate bypasses the
  delegation-chain verifier", "a ledger entry can be mutated without breaking
  the hash chain")

You will receive an acknowledgement within 72 hours and a triage assessment
within 7 days. Please allow up to 90 days for a fix before public disclosure;
we will credit reporters in the release notes unless you prefer otherwise.

## Scope

In scope:

- Verifier bypasses: any input that produces `ALLOW` where the design says
  `BLOCK`/fail-closed (mandate forgery, constraint evasion, rebind/replay,
  quorum forgery, screening evasion)
- Ledger integrity: tampering that survives `verify_chain`, replay divergence
- Evidence forgery: evidence bundles that verify against the wrong decision
- Fail-open behavior: any dependency failure that silently skips a pipeline
  stage instead of blocking

Out of scope:

- Denial of service against the demo gateway (it is not a hardened deployment)
- Vulnerabilities in third-party providers themselves (report to Moov,
  OpenSanctions, etc.); the *integration* is in scope
- The synthetic demo data (it is intentionally fictional)

## Known design-stage limitations

Tracked openly rather than reported: demo-mode keys are held in process memory
(keystore/HSM abstraction is on the roadmap), and the reference gateway does
not enforce mTLS. See `ROADMAP.md`.
