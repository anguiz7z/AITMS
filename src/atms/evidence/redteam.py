"""Red-team artefact parsers (v0.14).

Layer 2 of the evidence model from the v0.12 design doc:
``red_team`` evidence carries proof that an attack TTP succeeded against
the system in a controlled exercise — not theoretical, not a scanner
guess, an actual chain that worked.

Supported formats:

* **MITRE Caldera** — JSON export from the operations REST API (``/api/v2/operations/<id>``)
  or the bundled ``operations.json`` artefact.
* **Atomic Red Team** — the per-test ``invocation-*.json`` log written by Invoke-AtomicTest.
* **AttackIQ / Cymulate / SafeBreach CSV** — generic adversary-emulation CSV
  with ``Technique ID``, ``Target``, ``Result`` columns. Header sniffing is
  forgiving so most BAS exports load without manual mapping.

The output of every parser is a list of `Evidence` rows with
``source="red_team"``. Downstream the evidence engine flips matched threats
to ``status="exploited"`` and ``likelihood=5`` — that's the whole point.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from ..features import gated
from ..models import Evidence


def _atomic_severity(result: str) -> str:
    r = (result or "").strip().lower()
    if r in {"success", "succeeded", "true", "passed", "detected"}:
        return "high"
    if r in {"partial", "partial success", "blocked but executed"}:
        return "medium"
    if r in {"prevented", "blocked", "false", "failed", "no impact"}:
        return "low"
    return "medium"


# ─── Caldera ──────────────────────────────────────────────────────────────
@gated("redteam")
def parse_caldera(path: Path) -> list[Evidence]:
    """Parse a MITRE Caldera operations export.

    Caldera operations are an array (or single object with ``links``/``chain``)
    of executed abilities. We materialise every **successful** ability as
    an Evidence row.

    Success semantics: Caldera v2/v4 reports ``status=0`` for success;
    older v1 exports used ``status=1``. We accept either, plus explicit
    Caldera v4 fields (``state == "finished"`` and the ``collect: true``
    flag set when output was captured). The intent is to be tolerant of
    every flavour of operations.json a user might paste in.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8-sig"))
    rows: list[Evidence] = []
    operations = raw if isinstance(raw, list) else [raw]
    for op in operations:
        if not isinstance(op, dict):
            continue
        op_name = op.get("name") or op.get("operation") or "caldera-op"
        for link in op.get("chain") or op.get("links") or []:
            if not isinstance(link, dict):
                continue
            ability = link.get("ability") or {}
            status = link.get("status")
            state = (link.get("state") or "").lower()
            #
            # Success semantics — hard problem because Caldera v1 used
            # ``status == 1`` for success and v2/v4 use ``status == 0`` for
            # success. We CANNOT trust both — that would mark every
            # numeric status as a hit.
            #
            # Decision: trust ``state`` first when it's present (it's
            # unambiguous in v4); otherwise fall back to ``status == 0``
            # (the modern semantics). The legacy v1 path ``status == 1``
            # is opt-in via metadata: an exporter that knows it's v1 can
            # set ``link.api_version`` or include ``state="success"``.
            # We deliberately do NOT promote ``link["collect"] = True``;
            # that field merely indicates stdout/stderr was captured and
            # is set on failed abilities too.
            #
            if state:
                succeeded = state in {"finished", "success", "succeeded"}
                if state in {"failed", "error", "killed", "untrained"}:
                    continue
            elif status is not None:
                succeeded = (status == 0)
            else:
                # Neither field present → assume failure.
                succeeded = False
            if not succeeded:
                continue
            # Technique ID lookup is tolerant of three shapes seen in the
            # wild: (1) the canonical v2/v4 nested form
            # ``link.ability.technique_id``, (2) flat ``link.technique_id``
            # produced by hand-rolled exports and some third-party tooling,
            # and (3) the legacy ``attack_id`` / ``technique`` aliases. A
            # silently-missed match here means red-team evidence does NOT
            # promote the corresponding threat to ``exploited`` — bad UX.
            tech_id = (
                ability.get("technique_id")
                or ability.get("technique")
                or ability.get("attack_id")
                or link.get("technique_id")
                or link.get("technique")
                or link.get("attack_id")
                or ""
            )
            host = (link.get("host") or link.get("paw") or "").strip()
            description = (ability.get("description") or "").strip()
            references: list[str] = [f"caldera:operation:{op_name}"]
            if tech_id:
                # `attack:Tnnnn` is the canonical anchor used by the matcher;
                # also include the bare ID so existing equality checks fire.
                references.append(f"attack:{tech_id}")
                references.append(tech_id)
            tactic = ability.get("tactic") or ""
            if tactic:
                references.append(f"caldera:tactic:{tactic}")
            rows.append(Evidence(
                source="red_team",
                source_type="caldera",
                source_id=str(ability.get("ability_id") or ability.get("id") or "")[:64],
                title=str(ability.get("name") or tech_id or "Caldera ability")[:200],
                description=description[:1000],
                severity="high",
                affected_asset=host[:200],
                observed_at=str(link.get("finish") or link.get("decide") or "")[:25],
                references=[r for r in references if r],
            ))
    return [r for r in rows if r.title]


# ─── Atomic Red Team ──────────────────────────────────────────────────────
@gated("redteam")
def parse_atomic_red_team(path: Path) -> list[Evidence]:
    """Parse Invoke-AtomicTest's per-invocation JSON log.

    The log is a single object describing one test execution; in practice
    teams concatenate runs into a JSONL file or wrap them in an array.
    Both shapes work here.
    """
    # `utf-8-sig` strips the optional BOM that PowerShell's `Out-File`
    # writes by default. Without it, `json.loads` chokes on the U+FEFF
    # character at the start of the buffer.
    text = Path(path).read_text(encoding="utf-8-sig").strip()
    if not text:
        return []
    invocations: list = []
    # Line-by-line first: any input where >=1 line begins with `{` is
    # parsed as JSONL. This covers both LF and CRLF terminators (the old
    # `"\n{" in text` check missed CRLF). A single-record file with no
    # trailing newline is also handled by the per-line scan.
    object_lines = [line for line in text.splitlines() if line.strip().startswith("{")]
    if text.startswith("["):
        invocations = json.loads(text)
    elif len(object_lines) >= 2:
        invocations = [json.loads(line) for line in object_lines]
    else:
        invocations = [json.loads(text)]
    rows: list[Evidence] = []
    for inv in invocations:
        if not isinstance(inv, dict):
            # Tolerate JSONL files containing `null` lines, sentinel
            # markers, or top-level arrays — just skip them rather than
            # crashing the whole batch.
            continue
        atomic = inv.get("Atomic") or inv
        tech_id = atomic.get("attack_technique") or atomic.get("AttackTechnique") or ""
        host = atomic.get("Hostname") or inv.get("Hostname") or ""
        result = inv.get("ExecutionResult") or atomic.get("Result") or ""
        rows.append(Evidence(
            source="red_team",
            source_type="atomic_red_team",
            source_id=str(atomic.get("auto_generated_guid") or atomic.get("name") or "")[:64],
            title=str(atomic.get("display_name") or atomic.get("name") or tech_id or "Atomic test")[:200],
            description=str(atomic.get("description", ""))[:1000],
            severity=_atomic_severity(result),
            affected_asset=str(host)[:200],
            observed_at=str(inv.get("StartTime", ""))[:25],
            references=[f"attack:{tech_id}"] if tech_id else [],
        ))
    return rows


# ─── AttackIQ / Cymulate / SafeBreach generic BAS CSV ─────────────────────
def _norm_col(s: str) -> str:
    return "".join(ch for ch in s.lower() if ch.isalnum())


_BAS_ALIASES: dict[str, set[str]] = {
    "technique": {"techniqueid", "technique", "attackid", "attacktechnique", "ttp"},
    "name": {"scenario", "scenarioname", "techniquename", "name", "test", "testname"},
    "asset": {"target", "host", "hostname", "asset", "endpoint", "ip"},
    "result": {"result", "outcome", "status", "verdict", "execution"},
    "severity": {"severity", "risk", "impact", "criticality"},
    "description": {"description", "details", "summary"},
    "started": {"starttime", "startedat", "timestamp", "executionstart", "datetime"},
}


@gated("redteam")
def parse_bas_csv(path: Path) -> list[Evidence]:
    """Parse an AttackIQ / Cymulate / SafeBreach BAS CSV export.

    Column auto-sniff (case-insensitive). Severity defaults from the
    result column ("Successful" → high, "Prevented" → low) when no
    explicit severity column exists.
    """
    text = Path(path).read_text(encoding="utf-8-sig")
    reader = csv.DictReader(text.splitlines())
    if not reader.fieldnames:
        return []
    norm_to_orig = {_norm_col(c): c for c in reader.fieldnames}
    cols: dict[str, str] = {}
    for field, aliases in _BAS_ALIASES.items():
        for alias in aliases:
            if alias in norm_to_orig and field not in cols:
                cols[field] = norm_to_orig[alias]
                break
    rows: list[Evidence] = []
    for raw in reader:
        result = (raw.get(cols.get("result", ""), "") or "").strip()
        severity = (raw.get(cols.get("severity", ""), "") or "").strip().lower()
        if severity not in {"info", "low", "medium", "high", "critical"}:
            severity = _atomic_severity(result)
        tech = (raw.get(cols.get("technique", ""), "") or "").strip()
        rows.append(Evidence(
            source="red_team",
            source_type="bas_csv",
            source_id=tech[:64] or (raw.get(cols.get("name", ""), "") or "")[:64],
            title=(raw.get(cols.get("name", ""), "") or tech or "BAS scenario")[:200],
            description=(raw.get(cols.get("description", ""), "") or "")[:1000],
            severity=severity,
            affected_asset=(raw.get(cols.get("asset", ""), "") or "")[:200],
            observed_at=(raw.get(cols.get("started", ""), "") or "")[:25],
            references=[f"attack:{tech}"] if tech else [],
        ))
    return rows


# ─── Auto-detect ──────────────────────────────────────────────────────────
@gated("redteam")
def parse_redteam(path: Path) -> list[Evidence]:
    """Pick the right parser by extension + content sniff."""
    p = Path(path)
    suffix = p.suffix.lower()
    if suffix == ".csv":
        return parse_bas_csv(p)
    if suffix in (".json", ".jsonl"):
        text = p.read_text(encoding="utf-8")
        if "Atomic" in text or "AttackTechnique" in text or "auto_generated_guid" in text:
            return parse_atomic_red_team(p)
        if "ability" in text or '"chain"' in text or '"paw"' in text:
            return parse_caldera(p)
        # Default to Caldera shape for unknown JSON blobs.
        return parse_caldera(p)
    raise ValueError(
        f"Unrecognised red-team format: {suffix or '(none)'}. "
        "Supported: Caldera (.json), Atomic Red Team (.json/.jsonl), BAS CSV (.csv)."
    )


__all__ = [
    "parse_caldera", "parse_atomic_red_team", "parse_bas_csv", "parse_redteam",
]
