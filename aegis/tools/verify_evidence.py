"""Auditor-side evidence verification.

Usage:
    python -m aegis.tools.verify_evidence <evidence-bundle.json>

Validates a per-decision evidence bundle using only the public key embedded in
the file (see ``aegis/ledger/evidence.py`` for the checks). Exit code 0 iff
every check passes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from ..ledger.evidence import verify_evidence


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) != 1:
        print(__doc__)
        return 2
    bundle = json.loads(Path(argv[0]).read_text(encoding="utf-8"))
    ok, checks = verify_evidence(bundle)
    for name, result in checks.items():
        print(f"  {name:16s}: {'PASS' if result else 'FAIL'}")
    verdict = bundle.get("envelope", {}).get("verdict", "?")
    decision = bundle.get("envelope", {}).get("decision_id", "?")
    print(f"decision {decision} (verdict {verdict}): "
          f"{'VERIFIED' if ok else 'VERIFICATION FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
