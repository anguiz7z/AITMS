"""D3FEND mitigation-actionability engine (v0.14).

Reads `kb/d3fend/mappings.yaml` and decorates every Mitigation with:

- ``control_family``     — preventive / detective / responsive / corrective / deterrent
- ``automatable``        — whether a CI / IaC test can validate the control
- ``validation_test``    — concrete one-liner: how to verify it works
- ``d3fend``             — MITRE D3FEND technique IDs
- ``vendor_examples``    — concrete tools that implement the control

This is what turns the mitigation list from a wish-list into a backlog
the engineering team can act on.

The engine matches via case-insensitive substring on Mitigation.title or
Mitigation.description; the first matching rule wins (rules in
mappings.yaml are ordered by specificity).
"""

from __future__ import annotations

from ..kb import KnowledgeBase, get_kb
from ..models import Mitigation


def apply_d3fend_actionability(
    mitigations: list[Mitigation],
    kb: KnowledgeBase | None = None,
) -> list[Mitigation]:
    kb = kb or get_kb()
    rules = kb.d3fend_rules or []
    if not rules:
        return mitigations
    for m in mitigations:
        # Skip when this mitigation has clearly been hand-curated already —
        # the test we use is `d3fend`, since it has no sensible default and
        # is therefore the cleanest signal that a playbook author already
        # set the actionability fields by hand.
        already_curated = bool(m.d3fend)
        if already_curated:
            continue
        haystack = (m.title + " " + m.description).lower()
        for rule in rules:
            keys = rule.get("mitigation_match") or []
            if isinstance(keys, str):
                keys = [keys]
            # Word-boundary-ish match: keys with spaces match as substrings;
            # bare-token keys (e.g. "tls", "kms") match only with non-alnum
            # neighbours so we don't false-trigger on `tls_smuggling`.
            matched = False
            for k in keys:
                if not isinstance(k, str):
                    continue
                kl = k.lower()
                if " " in kl:
                    if kl in haystack:
                        matched = True
                        break
                else:
                    # Token boundary: kl must be flanked by characters that
                    # are NOT identifier characters (alnum or `_` or `-`).
                    # That way `tls` does not match `tls_smuggling` or
                    # `tls-bypass`, but does match `enable TLS in transit`.
                    def _is_word(ch: str) -> bool:
                        return ch.isalnum() or ch in {"_", "-"}
                    idx = haystack.find(kl)
                    while idx != -1:
                        before_ok = idx == 0 or not _is_word(haystack[idx - 1])
                        after_ok = (idx + len(kl) == len(haystack)
                                    or not _is_word(haystack[idx + len(kl)]))
                        if before_ok and after_ok:
                            matched = True
                            break
                        idx = haystack.find(kl, idx + 1)
                    if matched:
                        break
            if not matched:
                continue
            if not m.control_family:
                fam = rule.get("control_family", "") or ""
                if fam:
                    m.control_family = fam  # type: ignore[assignment]
            # Only set automatable when we're confident the engine is the
            # author of this row (already_curated == False above), so this
            # write is fine; preserve any explicit False set on a hand-
            # written record by gating the whole block on `not already_curated`.
            m.automatable = bool(rule.get("automatable", False))
            if not m.validation_test:
                m.validation_test = str(rule.get("validation_test", ""))[:500]
            d3 = rule.get("d3fend") or []
            m.d3fend = [str(x) for x in d3 if x]
            if not m.vendor_examples:
                v = rule.get("vendor_examples") or []
                m.vendor_examples = [str(x) for x in v if x][:8]
            break
    return mitigations


__all__ = ["apply_d3fend_actionability"]
