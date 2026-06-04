"""Evidence → component matching (v0.12, expanded v0.13).

Maps a list of `Evidence` rows onto the components in a System. We try
several heuristics in order; the first one that produces a non-empty
match wins:

  1. **CPE / pURL** exact match against ``component.metadata['cpe']`` or
     ``component.metadata['purl']`` (v0.13). Highest fidelity.
  2. Hostname / IP / FQDN exact match against ``metadata['hostname']``,
     ``metadata['ip']``, ``metadata['fqdn']``.
  3. Product + (optional) version substring match across the evidence's
     title, description AND affected_asset.
  4. Vendor token across title + description.
  5. Component-name substring match across title + description + asset.

A returned match-list may be empty; callers (workflow / engine) should
surface those as the ``evidence_unmatched`` count rather than dropping
the row silently — losing evidence quietly is the cardinal sin here.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from ..models import Component, Evidence


def _norm(s: object) -> str:
    if s is None:
        return ""
    return str(s).strip().lower()


def _parse_network(s: str) -> ipaddress._BaseNetwork | None:
    """Parse a CIDR / IP-range / single-IP string into an ipaddress network.

    Accepts: ``10.0.0.0/24``, ``10.0.0.5``, ``2001:db8::/32``, ``::1``.
    Returns None for hostnames or anything that isn't an IP literal.
    """
    s = (s or "").strip()
    if not s:
        return None
    try:
        # ip_network handles both single IPs (treated as /32 or /128) and CIDR.
        return ipaddress.ip_network(s, strict=False)
    except (ValueError, TypeError):
        return None


def _parse_ip(s: str) -> ipaddress._BaseAddress | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return ipaddress.ip_address(s)
    except (ValueError, TypeError):
        return None


def _cpe_product(cpe: str) -> tuple[str, str, str]:
    """Pull (vendor, product, version) tokens out of a CPE 2.3 string."""
    cpe = (cpe or "").strip().lower()
    if not cpe.startswith("cpe:2.3:"):
        return "", "", ""
    parts = cpe.split(":")
    if len(parts) < 7:
        return "", "", ""
    return parts[3], parts[4], parts[5]


def match_evidence(
    evidence: Iterable[Evidence],
    components: list[Component],
) -> list[tuple[Evidence, list[Component]]]:
    """Return ``[(evidence, [matched_components])]`` for every evidence row."""
    pairs: list[tuple[Evidence, list[Component]]] = []
    for ev in evidence:
        matches: list[Component] = []
        target_asset = _norm(ev.affected_asset)
        target_title = _norm(ev.title)
        target_desc = _norm(ev.description)
        haystack = f"{target_asset} {target_title} {target_desc}"

        # 1) CPE exact match — pull from any reference URL or affected_asset
        candidate_cpes: list[str] = []
        for ref in [ev.affected_asset, *ev.references]:
            ref_str = _norm(ref)
            if "cpe:2.3:" in ref_str:
                # crude extraction
                idx = ref_str.find("cpe:2.3:")
                candidate_cpes.append(ref_str[idx:].split()[0])
        if candidate_cpes:
            for c in components:
                meta = c.metadata or {}
                cpe = _norm(meta.get("cpe", ""))
                if cpe and any(cpe in cand or cand in cpe for cand in candidate_cpes):
                    matches.append(c)

        # 1b) pURL match
        if not matches:
            candidate_purls: list[str] = []
            for ref in [ev.affected_asset, *ev.references]:
                ref_str = _norm(ref)
                if "pkg:" in ref_str:
                    idx = ref_str.find("pkg:")
                    candidate_purls.append(ref_str[idx:].split()[0])
            if candidate_purls:
                for c in components:
                    meta = c.metadata or {}
                    purl = _norm(meta.get("purl", ""))
                    if purl and any(purl in cand or cand in purl for cand in candidate_purls):
                        matches.append(c)

        # 2a) CIDR / IP-range containment match — Nessus and most VAPT
        # tools report `affected_asset` as a CIDR (`10.0.0.0/24`) or a
        # range; the component's `metadata.ip` is typically a single
        # address. Without this branch the exact-string compare below
        # silently misses every CIDR-shaped row.
        if not matches and target_asset:
            ev_net = _parse_network(target_asset)
            if ev_net is not None:
                for c in components:
                    meta = c.metadata or {}
                    comp_ip = _parse_ip(_norm(meta.get("ip", "")))
                    comp_net = _parse_network(_norm(meta.get("cidr", "")))
                    if comp_ip is not None and comp_ip in ev_net or comp_net is not None and (
                        comp_net.overlaps(ev_net) if comp_net.version == ev_net.version else False
                    ):
                        matches.append(c)

        # 2b) hostname / ip / fqdn exact match
        if not matches and target_asset:
            for c in components:
                meta = c.metadata or {}
                hostname = _norm(meta.get("hostname", ""))
                ip = _norm(meta.get("ip", ""))
                fqdn = _norm(meta.get("fqdn", ""))
                if target_asset in {hostname, ip, fqdn}:
                    matches.append(c)

        # 3) product + version substring match across the whole haystack
        if not matches:
            for c in components:
                meta = c.metadata or {}
                prod = _norm(meta.get("product", ""))
                ver = _norm(meta.get("version", ""))
                if prod and prod in haystack:
                    if not ver or ver in haystack:
                        matches.append(c)

        # 4) vendor token in title or description
        if not matches:
            for c in components:
                meta = c.metadata or {}
                vendor = _norm(meta.get("vendor", ""))
                if vendor and vendor in haystack:
                    matches.append(c)

        # 5) component name substring match (last-resort)
        if not matches:
            for c in components:
                cname = _norm(c.name)
                if cname and len(cname) >= 4 and cname in haystack:
                    matches.append(c)

        pairs.append((ev, matches))
    return pairs


__all__ = ["match_evidence"]
