"""Lockheed Martin Cyber Kill Chain phase mapper (v0.11).

Tags every threat with the kill-chain phase it most plausibly belongs to,
based on STRIDE-AI category, MITRE ATT&CK mapping, and keyword heuristics.

Phases:
1. Reconnaissance       — info gathering, enumeration, port scan
2. Weaponization        — preparing the exploit / payload / poisoned data
3. Delivery             — phish, malicious attachment, prompt injection vector
4. Exploitation         — running the exploit, gaining a foothold
5. Installation         — implants, backdoors, persistence
6. Command_and_Control  — beacons, tool invocation, agent callbacks
7. Actions_on_Objectives — exfiltration, data destruction, fraud, manipulation

Pure-Python, deterministic. Sets `threat.kill_chain_phase` in place.
"""

from __future__ import annotations

from ..models import Threat

PHASES = (
    "Reconnaissance",
    "Weaponization",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command_and_Control",
    "Actions_on_Objectives",
)

# Keyword anchors per phase. Order matters: more specific terms first.
# We score each threat against every phase and pick the highest scorer.
_PHASE_KEYWORDS: dict[str, list[str]] = {
    "Reconnaissance": [
        "enumerat", "scan", "discover", "fingerprint", "shodan",
        "harvest", "recon", "footprint",
    ],
    "Weaponization": [
        "poison", "backdoor", "trojan", "weaponize", "craft",
        "trigger", "tamper with model", "supply chain",
    ],
    "Delivery": [
        "phish", "spear-phish", "smish", "vish", "drive-by",
        "indirect prompt injection", "attachment", "lure", "watering hole",
        "usb", "removable", "physical media",
    ],
    "Exploitation": [
        "exploit", "rce", "deserialization", "ssrf",
        "sql injection", "xss", "cve", "vulnerability",
        "buffer overflow", "evasion", "jailbreak", "bypass",
        "prompt injection", "vlan hop", "credential stuff",
        "brute force", "kerberoast", "dcsync", "golden ticket",
    ],
    "Installation": [
        "implant", "persistence", "rootkit", "service install",
        "scheduled task", "cron", "registry run", "autostart",
        "domain policy", "gpo abuse", "mailbox rule", "auto-forward",
        "inbox rule", "fine-tune backdoor",
    ],
    "Command_and_Control": [
        "c2", "command and control", "beacon", "callback",
        "tool call", "agent action", "https tunnel", "dns tunnel",
        "websocket exfil", "function call",
    ],
    "Actions_on_Objectives": [
        "exfil", "exfiltrat", "data destruction", "wipe",
        "ransom", "encrypt for impact", "fraud", "manipulate",
        "denial of service", "dos", "outage", "shutdown plant",
        "modify setpoint", "spoof reporting",
        "leak", "regurgitate", "extract training",
    ],
}

_STRIDE_HINTS: dict[str, str] = {
    # Default phase per STRIDE-AI category if no keyword wins.
    "Spoofing": "Delivery",
    "Tampering": "Weaponization",
    "Repudiation": "Actions_on_Objectives",
    "Information_Disclosure": "Actions_on_Objectives",
    "Denial_of_Service": "Actions_on_Objectives",
    "Elevation_of_Privilege": "Exploitation",
    "Defense_Evasion": "Installation",
}


def _score_phase(text: str, phase: str) -> int:
    score = 0
    for kw in _PHASE_KEYWORDS[phase]:
        if kw in text:
            score += 2 if " " in kw else 1
    return score


def assign_kill_chain_phases(threats: list[Threat]) -> list[Threat]:
    """Set `threat.kill_chain_phase` for each threat.

    Strategy:
    1. Score the threat title+description against each phase's keyword set.
    2. If a clear winner emerges (>= 2 points and ahead of runner-up), use it.
    3. Otherwise fall back to the STRIDE-AI hint mapping.
    4. Otherwise default to "Exploitation" (the most common default).
    """
    for threat in threats:
        if threat.kill_chain_phase:
            continue
        text = (threat.title + " " + threat.description).lower()
        scored = sorted(
            ((p, _score_phase(text, p)) for p in PHASES),
            key=lambda t: t[1], reverse=True,
        )
        top, top_score = scored[0]
        runner = scored[1][1]
        if top_score >= 2 and top_score > runner:
            threat.kill_chain_phase = top
            continue
        # Fallback via STRIDE-AI category
        for cat in threat.stride_ai:
            if cat in _STRIDE_HINTS:
                threat.kill_chain_phase = _STRIDE_HINTS[cat]
                break
        if not threat.kill_chain_phase:
            threat.kill_chain_phase = "Exploitation"
    return threats


__all__ = ["PHASES", "assign_kill_chain_phases"]
