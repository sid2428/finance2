# Contributing to AEGIS

Thanks for your interest. AEGIS is a fail-closed, deterministic compliance
control plane for agentic payments — contributions are judged first against
those three words.

## Ground rules (the invariants)

Every change must preserve these; PRs that weaken them will be declined:

1. **Fail-closed.** No dependency failure, timeout, or unknown input may ever
   resolve toward `ALLOW`. Unknown constraint types fail. Stale data fails.
   Exceptions block.
2. **Deterministic and replayable.** A decision is a pure function of
   `(mandate, world_snapshot, ruleset_version)`. Any new input that varies at
   decision time (clocks, external lookups, list versions) must be captured in
   the evidence/archive so replay uses recorded values.
3. **Single authority path.** Nothing settles without a signature-valid
   verdict envelope. Do not add code paths around `adapters.settle()` or the
   delegation-chain verifier.
4. **ML on the periphery.** Learned signals may raise risk or add evidence;
   they may never lift a deterministic block or act as verdict authority.
5. **Adversarial coverage.** A new feature ships with at least one adversarial
   test attempting to bypass it. The fuzzer invariant `escaped == []` must
   hold in CI.

## Workflow

- Fork / branch from `main`; open a PR even for small changes.
- Small, well-messaged commits — one logical change per commit.
- `python -m pytest` must be green; add tests alongside code.
- Match the surrounding style: type hints, module docstrings that state the
  regulatory or protocol anchor, `snake_case` files, no new dependencies
  without discussion (zero-infrastructure demo mode is a feature).

## What's welcome

- Screening providers behind the `ScreeningProvider` interface
- Jurisdiction packs with citations (see `aegis/data/`)
- Adversarial cases for the sandbox/fuzzer
- Conformance fixes against the AP2 spec (cite the section)
- Detection typologies with labeled test cases

## What's out of scope

Case-management UI, settlement rails themselves, and anything that turns AEGIS
into a general fraud platform. AEGIS is the deterministic pre-settlement
decision point and its evidence; it emits events for case managers, it doesn't
become one.

## Legal

By contributing you agree your contribution is licensed under Apache-2.0.
Reminder: sanctions screening, SAR filing, and liability determinations in a
live financial system must be reviewed by qualified compliance and legal
counsel — this project is a reference design.
