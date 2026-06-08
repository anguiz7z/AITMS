"""Framework-citation integrity net (audit 2026-05-30).

A threat-modeling tool's credibility rests on its framework citations
being real, current, and correctly attributed. This test pins the
facts that were verified against authoritative published sources on
2026-05-30, so a future KB edit can't silently reintroduce a wrong
date, a wrong attribution, or a fabricated "OWASP" threat ID.

Sources verified:
  * OWASP LLM Top 10 2025  — genai.owasp.org/llm-top-10/
  * OWASP Agentic AI Threats & Mitigations (ASI, Feb 2025) — T1..T15
    — genai.owasp.org/resource/agentic-ai-threats-and-mitigations/
  * CSA MAESTRO (CSA, 6 Feb 2025) — 7 layers
  * Singapore CSA Guidelines on Securing AI Systems (15 Oct 2024)
  * MITRE ATLAS tactic/technique/mitigation IDs + names — pinned to the
    authoritative values from mitre-atlas/atlas-data.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from atms.kb import get_kb

ROOT = Path(__file__).resolve().parents[1]
KB = ROOT / "kb"


@pytest.fixture(scope="module")
def kb():
    return get_kb()


# ─── OWASP LLM Top 10 2025 — exactly LLM01:2025 .. LLM10:2025 ────────

def test_owasp_llm_is_2025_edition_ten_entries(kb):
    # KB keys the catalog by the full 2025-edition ID (LLM01:2025 ..).
    assert len(kb.owasp_llm) == 10, f"expected 10 OWASP LLM entries, got {len(kb.owasp_llm)}"
    expected = [f"LLM{n:02d}:2025" for n in range(1, 11)]
    assert sorted(kb.owasp_llm.keys()) == expected, (
        f"OWASP LLM keys drifted from the 2025 edition: {sorted(kb.owasp_llm.keys())}"
    )
    raw = yaml.safe_load((KB / "owasp_llm" / "llm_top10_2025.yaml").read_text(encoding="utf-8"))
    assert [e["id"] for e in raw] == expected, "OWASP LLM source-file IDs drifted"


# ─── OWASP Agentic — canonical T1..T15, with T16/T17 as extensions ──

def test_owasp_agentic_canonical_fifteen_plus_flagged_extensions(kb):
    """The official OWASP Agentic publication (ASI, Feb 2025) defines
    exactly T1..T15. ATMS keeps two extra threats (AGT16/AGT17) but
    they MUST be flagged as ATMS extensions, never passed off as OWASP."""
    for n in range(1, 16):
        cid = f"AGT{n:02d}"
        assert cid in kb.owasp_agentic, f"missing canonical {cid}"
        assert kb.owasp_agentic[cid].get("standing") != "atms_extension", (
            f"{cid} is a canonical OWASP threat — must NOT be flagged extension"
        )
    for ext in ("AGT16", "AGT17"):
        if ext in kb.owasp_agentic:
            assert kb.owasp_agentic[ext].get("standing") == "atms_extension", (
                f"{ext} is NOT in OWASP T1..T15 — must be flagged "
                f"standing: atms_extension with a published anchor in `note`"
            )
            assert kb.owasp_agentic[ext].get("note"), (
                f"{ext} extension must cite the framework it IS anchored to"
            )


def test_owasp_agentic_header_attribution_and_date():
    """The KB file must attribute Agentic AI to OWASP / ASI and the
    correct Feb-2025 date — not 'CSA' and not 2026."""
    txt = (KB / "owasp_agentic" / "threats.yaml").read_text(encoding="utf-8")
    head = "\n".join(txt.splitlines()[:12])
    assert "OWASP" in head and "ASI" in head
    assert "February 2025" in head, "Agentic AI publication date must be Feb 2025"
    assert "2026" not in head.split("Verified")[0], "stale 2026 date in Agentic header"


# ─── MAESTRO — CSA, Feb 2025, 7 layers ──────────────────────────────

def test_maestro_date_is_2025_not_2026():
    for fname in ("layers.yaml", "threats.yaml"):
        txt = (KB / "maestro" / fname).read_text(encoding="utf-8")
        head = "\n".join(txt.splitlines()[:6])
        assert "2025-02-06" in head or "February 2025" in head, (
            f"maestro/{fname}: MAESTRO was published Feb 2025"
        )
        assert "2026-02-06" not in head and "February 2026" not in head, (
            f"maestro/{fname}: stale 2026 MAESTRO date"
        )


def test_maestro_has_seven_layers(kb):
    assert len(kb.maestro_layers) == 7, "MAESTRO defines 7 layers (L1..L7)"


# ─── Singapore CSA Guidelines — Oct 2024 ────────────────────────────

def test_csa_singapore_date_is_oct_2024():
    txt = (KB / "csa_singapore" / "guidelines.yaml").read_text(encoding="utf-8")
    head = "\n".join(txt.splitlines()[:6])
    assert "2024" in head and "October" in head, (
        "Singapore CSA Guidelines were published 15 Oct 2024"
    )


# ─── MITRE ATLAS — IDs/names match authoritative atlas-data ─────────
#
# These pin the specific corrections made on 2026-05-30 against the
# authoritative mitre-atlas/atlas-data values, so the prior
# mis-numbering (e.g. Defense Evasion on TA0008) can't silently return.

# A spot-check of canonical (id -> name) facts that were WRONG before.
_ATLAS_TACTIC_FACTS = {
    "AML.TA0000": "AI Model Access",
    "AML.TA0005": "Execution",
    "AML.TA0006": "Persistence",
    "AML.TA0007": "Defense Evasion",
    "AML.TA0008": "Discovery",
    "AML.TA0010": "Exfiltration",
    "AML.TA0011": "Impact",
    "AML.TA0012": "Privilege Escalation",
}


def test_atlas_tactic_ids_match_authoritative(kb):
    for tid, name in _ATLAS_TACTIC_FACTS.items():
        got = kb.get_atlas_tactic(tid)
        assert got is not None, f"missing ATLAS tactic {tid}"
        assert got["name"] == name, (
            f"{tid} should be {name!r} (authoritative ATLAS), got {got['name']!r}"
        )


def test_atlas_technique_names_use_ai_not_ml(kb):
    """MITRE renamed ML->AI across ATLAS. Spot-check the corrected names."""
    facts = {
        "AML.T0010": "AI Supply Chain Compromise",
        "AML.T0015": "Evade AI Model",
        "AML.T0024": "Exfiltration via AI Inference API",
        "AML.T0053": "AI Agent Tool Invocation",
    }
    for tid, name in facts.items():
        got = kb.get_atlas_technique(tid)
        if got is not None:
            assert got["name"] == name, (
                f"{tid} should be {name!r} (authoritative ATLAS), got {got['name']!r}"
            )


def test_atlas_technique_tactic_refs_resolve(kb):
    """Every tactic referenced by a technique must be a real loaded tactic."""
    tac_ids = set(kb.atlas_tactics.keys())
    for tid, tech in kb.atlas_techniques.items():
        for ref in tech.get("tactics", []):
            assert ref in tac_ids, f"{tid} references unknown tactic {ref}"


def test_no_stale_agentic_t17_or_2026_in_shipping_surfaces():
    """Regression guard for the 2026-05-30 citation fix. OWASP Agentic
    has 15 canonical threats (T1..T15); AGT16/AGT17 are flagged ATMS
    extensions. No user-facing/source surface may imply OWASP publishes
    17, nor mis-date Agentic/MAESTRO to 2026. CHANGELOG is exempt
    (append-only dev history)."""
    import re
    root = Path(__file__).resolve().parents[1]
    surfaces = [root / "README.md", root / "docs" / "ARCHITECTURE.md",
                root / "src" / "atms" / "kb.py", root / "src" / "atms" / "models.py",
                root / "src" / "atms" / "engines" / "mitigations.py"]
    surfaces += list((root / "src" / "atms" / "templates").rglob("*.html"))
    surfaces += list((root / "src" / "atms" / "templates").rglob("*.j2"))

    # (1) Any "17 / T1-T17" framing that implies OWASP Agentic has 17 threats.
    t17 = re.compile(r"T1[–—-]T17|T1\.\.T17|all 17 OWASP|17 OWASP Agentic"
                     r"|through T17|AGT01\.\.AGT17")
    # (2) Blanket date guard: any line naming OWASP Agentic / ASI / MAESTRO
    #     that ALSO contains "2026" is a mis-date (both were published 2025).
    #     Phrasing-agnostic so new wordings can't slip a wrong year past it.
    fw = re.compile(r"OWASP Agentic|Agentic Security Initiative|\bASI\b|MAESTRO")
    mis2026 = re.compile(r"\b2026\b")
    offenders = []
    for f in surfaces:
        if not f.exists():
            continue
        for n, line in enumerate(f.read_text(encoding="utf-8").splitlines(), 1):
            if t17.search(line):
                offenders.append(f"{f.relative_to(root).as_posix()}:{n} [T17]")
            elif fw.search(line) and mis2026.search(line):
                offenders.append(f"{f.relative_to(root).as_posix()}:{n} [2026 mis-date]")
    assert not offenders, (
        "stale OWASP-Agentic/MAESTRO citation framing (should be T1-T15 / 2025):\n  "
        + "\n  ".join(offenders)
    )


# ─── Playbook citations must reference REAL KB entries ──────────────
# v1.0.5 (output-justification review): a threat library is only
# defensible if every framework ID it cites actually exists. The review
# found AML.T0042 cited by output_filter/T_OF_003 — an ATLAS technique
# that isn't in MITRE ATLAS (or the bundled KB). These guards make any
# such fabricated citation a hard test failure, so it can't reach a
# client report.


def _iter_playbook_threats():
    for f in sorted((KB / "playbooks").glob("*.yaml")):
        data = yaml.safe_load(f.read_text(encoding="utf-8")) or {}
        for th in (data.get("threats") or []):
            yield f.name, th


def test_every_playbook_atlas_id_exists_in_kb(kb):
    """Every `atlas:` technique ID cited by any playbook threat must be a
    real ATLAS technique in the KB. Guards against fabricated citations
    (the AML.T0042 class of defect)."""
    valid = set(kb.atlas_techniques.keys())
    offenders: list[str] = []
    for fname, th in _iter_playbook_threats():
        for aid in (th.get("atlas") or []):
            if aid not in valid:
                offenders.append(f"{fname}:{th.get('id')} cites {aid!r}")
    assert not offenders, (
        "playbook threats cite ATLAS technique IDs that don't exist in the "
        "KB (fabricated citations — indefensible in a client report):\n  "
        + "\n  ".join(offenders)
    )


def test_every_playbook_owasp_llm_id_exists_in_kb(kb):
    """Every `owasp_llm:` ID cited by a playbook threat must be a real
    OWASP LLM Top 10 2025 entry."""
    valid = set(kb.owasp_llm.keys())
    offenders: list[str] = []
    for fname, th in _iter_playbook_threats():
        for cid in (th.get("owasp_llm") or []):
            if cid not in valid:
                offenders.append(f"{fname}:{th.get('id')} cites {cid!r}")
    assert not offenders, (
        "playbook threats cite OWASP LLM IDs not in the KB:\n  "
        + "\n  ".join(offenders)
    )


def test_every_playbook_owasp_agentic_id_exists_in_kb(kb):
    """Every `owasp_agentic:` ID cited by a playbook threat must be a real
    OWASP Agentic entry (AGT01..AGT15 canonical, AGT16/17 ATMS ext)."""
    valid = set(kb.owasp_agentic.keys())
    offenders: list[str] = []
    for fname, th in _iter_playbook_threats():
        for cid in (th.get("owasp_agentic") or []):
            if cid not in valid:
                offenders.append(f"{fname}:{th.get('id')} cites {cid!r}")
    assert not offenders, (
        "playbook threats cite OWASP Agentic IDs not in the KB:\n  "
        + "\n  ".join(offenders)
    )


def test_every_playbook_nist_ai_100_2_id_exists_in_kb(kb):
    """Every `nist_ai_100_2:` ID cited by a playbook threat must be a real
    entry in the loaded NIST AI 100-2 adversarial-ML taxonomy. Guards the
    audit F002-F007 class: fabricated NIST_GAI_*/NIST_PAI_* IDs (e.g.
    NIST_GAI_CONFABULATION, NIST_PAI_POISONING_MODEL) that don't exist in
    the catalogue but reached client nist_ai_100_2_coverage."""
    valid = set(kb.nist_ai_100_2.keys())
    offenders: list[str] = []
    for fname, th in _iter_playbook_threats():
        for cid in (th.get("nist_ai_100_2") or []):
            if cid not in valid:
                offenders.append(f"{fname}:{th.get('id')} cites {cid!r}")
    assert not offenders, (
        "playbook threats cite NIST AI 100-2 IDs not in the KB taxonomy "
        "(fabricated citations -- indefensible in a client report):\n  "
        + "\n  ".join(offenders)
    )


def test_every_playbook_maestro_id_exists_in_kb(kb):
    """Every `maestro:` ID cited by a playbook threat must be a real CSA
    MAESTRO threat in the KB (M.L1..M.L7 layers + M.X cross-layer). Guards
    the audit F005/F007 class: a fabricated M.L4.07 (the L4 layer stops at
    M.L4.06) that reached client maestro coverage + STIX external_references."""
    valid = set(kb.maestro_threats.keys())
    offenders: list[str] = []
    for fname, th in _iter_playbook_threats():
        for cid in (th.get("maestro") or []):
            if cid not in valid:
                offenders.append(f"{fname}:{th.get('id')} cites {cid!r}")
    assert not offenders, (
        "playbook threats cite MAESTRO IDs not in the KB:\n  "
        + "\n  ".join(offenders)
    )


def test_analysis_output_has_no_fabricated_atlas_ids(kb):
    """End-to-end: analysing every bundled sample must never surface a
    threat carrying an ATLAS ID absent from the KB. This is the surface a
    client actually sees, so pin it directly."""
    from atms.cli import _load_system_yaml
    from atms.workflow import analyze

    valid = set(kb.atlas_techniques.keys())
    samples = ROOT / "samples"
    offenders: list[str] = []
    for p in sorted(samples.glob("*.yaml")):
        try:
            model = analyze(_load_system_yaml(p))
        except Exception:
            continue  # non-AI / invalid samples are exercised elsewhere
        for t in model.threats:
            for aid in t.atlas_techniques:
                if aid not in valid:
                    offenders.append(f"{p.name}:{t.id} -> {aid!r}")
    assert not offenders, (
        "analysis output cites ATLAS IDs not in the KB:\n  "
        + "\n  ".join(sorted(set(offenders)))
    )


def test_every_playbook_nist_ai_rmf_id_exists_in_kb(kb):
    """audit F073: every `nist:` (NIST AI 600-1 GenAI Profile) id cited by a
    playbook must resolve in the loaded catalogue. Also guards that the
    catalogue is no longer structurally dead -- at least one playbook cites it."""
    valid = set(kb.nist_ai_rmf.keys())
    cited = 0
    offenders: list[str] = []
    for fname, th in _iter_playbook_threats():
        for cid in (th.get("nist") or []):
            cited += 1
            if cid not in valid:
                offenders.append(f"{fname}:{th.get('id')} cites {cid!r}")
    assert not offenders, (
        "playbook threats cite NIST AI 600-1 ids not in the KB:\n  " + "\n  ".join(offenders)
    )
    assert cited > 0, "the NIST AI 600-1 catalogue is loaded + marketed but no playbook cites it (dead)"


def test_analysis_output_has_no_mislabeled_atlas_mitigations(kb):
    """audit F069/F071/F072: the only ATLAS-MIT references a threat may carry
    are real ATLAS mitigation ids (AML.M*). The playbook `refs` field was
    polluted with ATT&CK techniques (T1190, ICS T08xx), OWASP categories
    (LLM05:2025) and ATLAS techniques (AML.T*), all of which were wrongly
    rendered to clients as 'ATLAS-MIT:<id>' mitigations."""
    from atms.cli import _load_system_yaml
    from atms.workflow import analyze

    samples = ROOT / "samples"
    offenders: list[str] = []
    for p in sorted(samples.glob("*.yaml")):
        try:
            model = analyze(_load_system_yaml(p))
        except Exception:
            continue
        for t in model.threats:
            for ref in (t.references or []):
                if ref.startswith("ATLAS-MIT:") and not ref.startswith("ATLAS-MIT:AML.M"):
                    offenders.append(f"{p.name}:{t.id} -> {ref!r}")
            for mid in t.mitigation_ids:
                if str(mid).startswith(("T", "LLM", "API", "ML", "AML.T")):
                    offenders.append(f"{p.name}:{t.id} mitigation_id {mid!r} is not an AML.M id")
    assert not offenders, (
        "analysis output presents non-mitigation ids as ATLAS mitigations:\n  "
        + "\n  ".join(sorted(set(offenders))[:20])
    )


def test_analysis_output_maestro_and_agentic_respect_applies_to(kb):
    """audit F020/F021/F022/F061: a MAESTRO threat id or OWASP-Agentic id may
    only surface on a component its catalogue applies_to permits (cross-layer
    M.X.* and unrestricted ids exempt). Pins that e.g. an Agent-Ecosystem (L7)
    id can't reach a non-agent component's coverage."""
    from atms.cli import _load_system_yaml
    from atms.workflow import analyze

    comp_types = {}  # filled per sample
    offenders: list[str] = []
    for p in sorted((ROOT / "samples").glob("*.yaml")):
        try:
            model = analyze(_load_system_yaml(p))
        except Exception:
            continue
        comp_types = {c.id: c.type for c in model.system.components}
        for t in model.threats:
            ctype = comp_types.get(t.component_id, "")
            for mid in t.maestro_threats:
                m = kb.maestro_threats.get(mid)
                if not isinstance(m, dict) or str(mid).startswith("M.X") or m.get("layer") == "cross":
                    continue
                applies = m.get("applies_to") or []
                if applies and ctype not in set(applies):
                    offenders.append(f"{p.name}:{t.id} ({ctype}) -> MAESTRO {mid} applies_to={applies}")
            for aid in t.owasp_agentic:
                a = kb.owasp_agentic.get(aid)
                if not isinstance(a, dict):
                    continue
                applies = a.get("applies_to") or []
                if applies and ctype not in set(applies):
                    offenders.append(f"{p.name}:{t.id} ({ctype}) -> AGT {aid} applies_to={applies}")
    assert not offenders, (
        "MAESTRO/OWASP-Agentic ids surfaced on components their applies_to excludes:\n  "
        + "\n  ".join(sorted(set(offenders))[:20])
    )


def test_analysis_output_has_no_fabricated_maestro_or_nist_ids(kb):
    """End-to-end guard for audit F002-F007: analysing every bundled sample
    must never surface a MAESTRO or NIST AI 100-2 ID absent from the KB --
    these flow into summary coverage maps and the STIX external_references a
    client ingests, so pin the actual output surface."""
    from atms.cli import _load_system_yaml
    from atms.workflow import analyze

    valid_mae = set(kb.maestro_threats.keys())
    valid_nist = set(kb.nist_ai_100_2.keys())
    samples = ROOT / "samples"
    offenders: list[str] = []
    for p in sorted(samples.glob("*.yaml")):
        try:
            model = analyze(_load_system_yaml(p))
        except Exception:
            continue
        for t in model.threats:
            for mid in t.maestro_threats:
                if mid not in valid_mae:
                    offenders.append(f"{p.name}:{t.id} -> MAESTRO {mid!r}")
            for nid in t.nist_ai_100_2:
                if nid not in valid_nist:
                    offenders.append(f"{p.name}:{t.id} -> NIST {nid!r}")
    assert not offenders, (
        "analysis output cites MAESTRO/NIST IDs not in the KB:\n  "
        + "\n  ".join(sorted(set(offenders)))
    )
