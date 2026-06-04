"""Deterministic ID generation for analysis artefacts.

v0.19.1 (Roadmap V5 Phase 1) — the analysis engines previously stamped
mitigation / attack-path / structural-recommendation / fallback-threat
IDs with ``uuid.uuid4()``. That made every ``analyze()`` run produce a
DIFFERENT report for the SAME input: IDs churned, so HTML / Markdown
reports were not reproducible and could not be diffed (`atms diff`),
referenced in a ticket, or cached. The Phase 1 determinism floor caught
it.

This module derives a stable, content-addressed suffix from the
artefact's defining content. Same input → same IDs → byte-identical
reports (modulo the human-readable "Generated on <timestamp>" line,
which downstream renderers stamp separately).

The hash is cosmetic (an ID label, never a security boundary), so a
short truncated digest is fine. ``usedforsecurity=False`` documents
that intent and keeps strict hashlib linters quiet.
"""

from __future__ import annotations

import hashlib


def stable_id(prefix: str, *parts: object) -> str:
    """Return ``"{PREFIX}-{8 hex}"`` derived deterministically from
    ``parts``.

    Args:
        prefix: short uppercase tag, e.g. ``"MIT"`` / ``"PATH"`` / ``"REC"``.
        *parts: the artefact's defining content. Order matters; values
            are stringified and joined with a separator that can't occur
            inside a normal token, so distinct part-tuples don't collide
            via concatenation ambiguity.

    The digest is the first 8 hex chars of SHA-256 over the joined
    parts — 16^8 ≈ 4.3e9 space, ample for the dozens-to-hundreds of
    artefacts in a single analysis, and the callers already dedup on a
    separate semantic key so a hypothetical collision is cosmetic only.
    """
    joined = "\x1f".join(str(p) for p in parts)
    digest = hashlib.sha256(joined.encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"{prefix}-{digest[:8].upper()}"


__all__ = ["stable_id"]
