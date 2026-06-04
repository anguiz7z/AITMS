"""Knowledge base loader and search.

Loads the bundled YAML knowledge base (OWASP LLM Top 10 2025, MITRE ATLAS tactics
and techniques, NIST AI RMF entries, per-component playbooks, STRIDE-AI matrix)
into in-memory dicts. Provides a simple keyword-based search across the KB.

v0.18.47 Phase 3 — pickle cache:
  Cold KB load (166 YAML files → 722 records) costs ~920ms on a modern
  laptop. After Phase 3 we keep a pickle next to the kb root that is
  invalidated by the recursive max-mtime of the YAML tree. Hot-cache
  load is ~30ms — a 30× speedup on every process that touches the KB.

  Disable with ATMS_KB_NO_CACHE=1 (CI / debug).
  Cache file is git-ignored.
"""

from __future__ import annotations

import logging
import os
import pickle
import re
import sys
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from .paths import kb_dir as _kb_dir

log = logging.getLogger(__name__)

# Pickle cache format version. Bump if any KnowledgeBase field is added
# / removed / renamed so stale caches from an older ATMS get invalidated
# even when the underlying YAML hasn't changed.
_CACHE_VERSION = 2


def _cache_path(root: Path) -> Path:
    """Where to store the pickle cache.

    In a writable repo, sit next to the KB root. In a PyInstaller
    frozen build (where the bundled `kb/` is inside a read-only
    directory under the temp _MEIPASS), use the user-data location
    so the cache is still warm across invocations.
    """
    if getattr(sys, "frozen", False):
        # %LOCALAPPDATA%\Programs\ATMS\.atms_kb_cache.pkl on Windows,
        # or ~/.cache/atms/kb_cache.pkl on POSIX.
        local = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~/.cache")
        cache_dir = Path(local) / "atms"
        cache_dir.mkdir(parents=True, exist_ok=True)
        return cache_dir / f"kb_cache_v{_CACHE_VERSION}.pkl"
    return root.parent / ".atms_kb_cache.pkl"


def _kb_signature(root: Path) -> tuple[int, int, int]:
    """Cheap content-fingerprint: (yaml-file count, total bytes, max mtime).

    All three need to match for a pickle to be considered valid.
    """
    count = 0
    total_bytes = 0
    max_mtime_ns = 0
    for p in root.rglob("*.yaml"):
        try:
            st = p.stat()
        except OSError:
            continue
        count += 1
        total_bytes += st.st_size
        if st.st_mtime_ns > max_mtime_ns:
            max_mtime_ns = st.st_mtime_ns
    for p in root.rglob("*.json"):  # system.schema.json also gates the cache
        try:
            st = p.stat()
        except OSError:
            continue
        count += 1
        total_bytes += st.st_size
        if st.st_mtime_ns > max_mtime_ns:
            max_mtime_ns = st.st_mtime_ns
    return (count, total_bytes, max_mtime_ns)


class KnowledgeBase:
    """In-memory representation of the bundled KB."""

    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root) if root else _kb_dir()
        self.owasp_llm: dict[str, dict] = {}
        self.owasp_agentic: dict[str, dict] = {}  # AGT01..AGT15 (OWASP T1..T15) + AGT16/17 ATMS extensions
        self.owasp_api: dict[str, dict] = {}  # API1:2023..API10:2023
        self.atlas_tactics: dict[str, dict] = {}
        self.atlas_techniques: dict[str, dict] = {}
        self.atlas_mitigations: dict[str, dict] = {}
        self.attack_cloud: dict[str, dict] = {}  # MITRE ATT&CK Cloud subset
        self.attack_enterprise: dict[str, dict] = {}  # MITRE ATT&CK Enterprise + ICS (v0.10)
        self.linddun: dict[str, dict] = {}  # LINDDUN privacy threats (v0.10)
        self.nist_ai_100_2: dict[str, dict] = {}  # NIST AI 100-2 adversarial-ML taxonomy (v0.11)
        self.devices: list[dict] = []  # Device & product catalog (v0.11)
        self.kev_cves: list[str] = []  # CISA KEV catalog CVEs (v0.12)
        self.kev_entries: list[dict] = []  # Full KEV rows for the report appendix (v0.12)
        self.epss_scores: list[dict] = []  # EPSS top-N snapshot (v0.12)
        self.kev_meta: dict = {}  # {refreshed: ISO-date, source: URL, rows: int} (v0.13)
        self.epss_meta: dict = {}
        self.owasp_ml: dict[str, dict] = {}  # OWASP ML Top 10 (2023) (v0.13)
        self.compliance_controls: dict[str, dict] = {}  # NIS2.21.2.a, DORA.A6, … (v0.13)
        self.csa_singapore: dict[str, dict] = {}  # CSA Singapore Guidelines on Securing AI Systems (v0.15)
        # v0.16 — Cloud-service catalog keyed by (vendor, product). Lets users
        # write metadata: {vendor: AWS, product: dynamodb} and ATMS knows the
        # canonical component_type + applicable threats for that specific service.
        self.cloud_catalog: dict[tuple[str, str], dict] = {}
        # v0.16 — Vendor-specific threat overlays (aws_iam, aws_bedrock, azure_appservice, etc.)
        self.vendor_threats: dict[str, list[dict]] = {}
        # v0.16.1 — Scale-aware FAIR loss-magnitude priors. Tiers from
        # kb/priors/loss_priors.yaml; selected by (industry × revenue × stage).
        self.loss_prior_tiers: list[dict] = []
        # v0.16.4 — Reference-architecture patterns (AWS SRA / AWS GenAI Lens /
        # Azure LZA / Azure WAF AI workloads). Used to cross-walk mitigations
        # to canonical CSP patterns so reviewers see the delta vs the
        # platform's default reference instead of generic mitigation prose.
        self.reference_patterns: list[dict] = []
        self.d3fend_rules: list[dict] = []  # D3FEND mitigation actionability mappings (v0.14)
        self.nist_ai_rmf: dict[str, dict] = {}
        self.maestro_layers: dict[str, dict] = {}  # M.L1..M.L7
        self.maestro_threats: dict[str, dict] = {}  # M.L1.01, M.X.01, ...
        self.stride_matrix: dict[str, dict] = {}
        self.playbooks: dict[str, dict] = {}  # keyed by component_type
        # v0.16.10 — methodology provenance: per-STRIDE-for-AI category,
        # the published framework anchor + standing (standard vs
        # atms_extension). Loaded from kb/methodology_provenance.yaml.
        self.methodology_provenance: dict[str, dict] = {}
        self.load()

    # ----------------------------------------------------------------- loading
    def load(self) -> None:
        self._load_owasp()
        self._load_owasp_agentic()
        self._load_owasp_api()
        self._load_atlas()
        self._load_attack_cloud()
        self._load_attack_enterprise()
        self._load_linddun()
        self._load_nist_ai_100_2()
        self._load_devices()
        self._load_threat_intel()
        self._load_owasp_ml()
        self._load_compliance()
        self._load_csa_singapore()
        self._load_cloud_catalog()       # v0.16
        self._load_vendor_threats()      # v0.16
        self._load_loss_priors()         # v0.16.1
        self._load_reference_patterns()  # v0.16.4
        self._load_d3fend()
        self._load_nist()
        self._load_maestro()
        self._load_stride()
        self._load_playbooks()
        self._load_methodology_provenance()  # v0.16.10

    def _load_yaml(self, path: Path) -> Any:
        if not path.exists():
            return None
        with path.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)

    def _load_owasp(self) -> None:
        data = self._load_yaml(self.root / "owasp_llm" / "llm_top10_2025.yaml") or []
        self.owasp_llm = {item["id"]: item for item in data}

    def _load_owasp_agentic(self) -> None:
        data = self._load_yaml(self.root / "owasp_agentic" / "threats.yaml") or []
        self.owasp_agentic = {item["id"]: item for item in data}

    def _load_owasp_api(self) -> None:
        data = self._load_yaml(self.root / "owasp_api" / "api_top10_2023.yaml") or []
        self.owasp_api = {item["id"]: item for item in data}

    def _load_attack_cloud(self) -> None:
        data = self._load_yaml(self.root / "mitre_attack_cloud" / "techniques.yaml") or []
        self.attack_cloud = {item["id"]: item for item in data}

    def _load_attack_enterprise(self) -> None:
        data = self._load_yaml(self.root / "mitre_attack_enterprise" / "techniques.yaml") or []
        self.attack_enterprise = {item["id"]: item for item in data}

    def _load_linddun(self) -> None:
        data = self._load_yaml(self.root / "linddun" / "threats.yaml") or []
        self.linddun = {item["id"]: item for item in data}

    def _load_nist_ai_100_2(self) -> None:
        data = self._load_yaml(self.root / "nist_ai_100_2" / "taxonomy.yaml") or []
        self.nist_ai_100_2 = {item["id"]: item for item in data}

    def _load_devices(self) -> None:
        data = self._load_yaml(self.root / "devices" / "catalog.yaml") or []
        self.devices = [item for item in data if isinstance(item, dict) and "id" in item]

    def _load_threat_intel(self) -> None:
        kev_path = self.root / "threat_intel" / "cisa_kev.yaml"
        kev = self._load_yaml(kev_path) or []
        self.kev_entries = [k for k in kev if isinstance(k, dict) and "cve" in k]
        self.kev_cves = [str(k["cve"]).upper() for k in self.kev_entries]
        # v0.13: parse # Refreshed: line from the YAML header for dated reports
        if kev_path.exists():
            self.kev_meta = self._parse_feed_header(kev_path)
        epss_path = self.root / "threat_intel" / "epss_top.yaml"
        epss = self._load_yaml(epss_path) or []
        self.epss_scores = [e for e in epss if isinstance(e, dict) and "cve" in e]
        if epss_path.exists():
            self.epss_meta = self._parse_feed_header(epss_path)

    def _parse_feed_header(self, path: Path) -> dict:
        """Pull `# Refreshed:` and `# Source:` from a YAML header."""
        meta: dict[str, object] = {"path": str(path)}
        try:
            with path.open("r", encoding="utf-8") as fh:
                for _ in range(15):
                    line = fh.readline()
                    if not line:
                        break
                    s = line.strip()
                    if s.startswith("# Refreshed:"):
                        meta["refreshed"] = s.split(":", 1)[1].strip()
                    elif s.startswith("# Source:"):
                        meta["source"] = s.split(":", 1)[1].strip()
                    elif s.startswith("# Snapshot taken:"):
                        meta["refreshed"] = s.split(":", 1)[1].strip()
                    elif s.startswith("# Rows:"):
                        try:
                            meta["rows"] = int(s.split(":", 1)[1].strip())
                        except ValueError:
                            pass
        except OSError:
            pass
        return meta

    def _load_owasp_ml(self) -> None:
        data = self._load_yaml(self.root / "owasp_ml" / "ml_top10_2023.yaml") or []
        self.owasp_ml = {item["id"]: item for item in data if isinstance(item, dict) and "id" in item}

    def _load_compliance(self) -> None:
        data = self._load_yaml(self.root / "compliance" / "controls.yaml") or []
        self.compliance_controls = {
            item["id"]: item
            for item in data
            if isinstance(item, dict) and "id" in item
        }

    def _load_csa_singapore(self) -> None:
        """v0.15.0: load Singapore CSA Guidelines on Securing AI Systems."""
        data = self._load_yaml(self.root / "csa_singapore" / "guidelines.yaml") or []
        self.csa_singapore = {
            item["id"]: item
            for item in data
            if isinstance(item, dict) and "id" in item
        }

    def _load_cloud_catalog(self) -> None:
        """v0.16: load per-vendor cloud-service catalogs into a flat
        ``(vendor_lower, product_lower) -> entry`` index.

        Each entry maps a specific cloud service (e.g. AWS DynamoDB) to
        the canonical ATMS ``component_type`` + applicable threats.
        Users set ``metadata.vendor`` + ``metadata.product`` on a
        Component and the engine looks the entry up to determine
        which per-vendor threats also apply (in addition to the
        baseline playbook for the component_type).
        """
        catalog_dir = self.root / "cloud_catalog"
        if not catalog_dir.exists():
            return
        for yaml_path in sorted(catalog_dir.glob("*.yaml")):
            data = self._load_yaml(yaml_path) or []
            if not isinstance(data, list):
                continue
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                vendor = (entry.get("vendor") or "").lower().strip()
                product = (entry.get("product") or "").lower().strip()
                if not vendor or not product:
                    continue
                self.cloud_catalog[(vendor, product)] = entry

    def _load_vendor_threats(self) -> None:
        """v0.16: load per-vendor threat overlay playbooks (aws_iam,
        aws_bedrock, azure_appservice, azure_foundry, gcp_iam, ...).

        Each file contains a list of threats keyed by the same schema
        as ``kb/playbooks/*.yaml`` plus the v0.16 applicability
        predicates. The engine applies these in addition to the
        component-type playbook when the component's vendor/product
        metadata matches.
        """
        vt_dir = self.root / "vendor_threats"
        if not vt_dir.exists():
            return
        for yaml_path in sorted(vt_dir.glob("*.yaml")):
            data = self._load_yaml(yaml_path) or []
            if not isinstance(data, list):
                continue
            self.vendor_threats[yaml_path.stem] = [t for t in data if isinstance(t, dict)]

    def _load_loss_priors(self) -> None:
        """v0.16.1: load FAIR loss-magnitude priors keyed by
        (industry × revenue_bucket × deployment_stage).

        v0.16.9 (Bug-011): validate that loss_low <= loss_high on each
        tier. A typo / inverted range previously collapsed every threat's
        ALE to the broken value. We swap (best-effort recovery) and warn.
        """
        import logging

        data = self._load_yaml(self.root / "priors" / "loss_priors.yaml") or {}
        if isinstance(data, dict):
            tiers = data.get("tiers") or []
            for tier in tiers:
                if not isinstance(tier, dict):
                    continue
                lo = tier.get("loss_low_default")
                hi = tier.get("loss_high_default")
                if isinstance(lo, (int, float)) and isinstance(hi, (int, float)) and lo > hi:
                    logging.getLogger("atms.kb").warning(
                        "Tier %s has loss_low_default (%s) > loss_high_default (%s); "
                        "swapping to recover. Fix kb/priors/loss_priors.yaml.",
                        tier.get("id", "?"), lo, hi,
                    )
                    tier["loss_low_default"], tier["loss_high_default"] = hi, lo
            self.loss_prior_tiers = tiers

    def _load_reference_patterns(self) -> None:
        """v0.16.4: load reference-architecture patterns (AWS SRA / AWS
        GenAI Lens / Azure LZA / Azure WAF AI workloads) and stitch them
        into a single list for the mitigation cross-walk enricher.

        Each entry is keyed by `id`; the engine surfaces matches as a
        new `reference_patterns` field on Mitigation objects.
        """
        rp_dir = self.root / "reference_patterns"
        if not rp_dir.exists():
            return
        for yaml_path in sorted(rp_dir.glob("*.yaml")):
            data = self._load_yaml(yaml_path) or []
            if not isinstance(data, list):
                continue
            for entry in data:
                if isinstance(entry, dict) and entry.get("id"):
                    self.reference_patterns.append(entry)

    def lookup_loss_prior(
        self,
        industry: str | None = None,
        revenue_bucket: str | None = None,
        deployment_stage: str | None = None,
    ) -> dict:
        """Return the most-specific tier matching the given combination.

        Match semantics (per-key, in order):
          - Key absent in tier.match → always matches
          - Key present, value is a string → string equality (case-insensitive)
          - Key present, value is a list → membership

        Specificity is measured by how many ``match`` keys the tier
        declares. Most-specific tier wins; ties resolve to the first
        listed (so ``loss_priors.yaml`` order matters for ties).
        """
        if not self.loss_prior_tiers:
            return {}
        candidate = (industry or "").lower(), (revenue_bucket or "").lower(), (deployment_stage or "").lower()

        def matches(tier: dict) -> bool:
            m = tier.get("match") or {}
            for key, want in m.items():
                actual = {
                    "industry": candidate[0],
                    "revenue_bucket": candidate[1],
                    "deployment_stage": candidate[2],
                }.get(key)
                if isinstance(want, list):
                    want_lc = [str(w).lower() for w in want]
                    if actual not in want_lc:
                        return False
                else:
                    if actual != str(want).lower():
                        return False
            return True

        scored: list[tuple[int, dict]] = []
        for tier in self.loss_prior_tiers:
            if matches(tier):
                specificity = len(tier.get("match") or {})
                scored.append((specificity, tier))
        if not scored:
            return {}
        # Stable sort by specificity desc (highest first)
        scored.sort(key=lambda t: -t[0])
        return scored[0][1]

    def lookup_cloud_service(
        self, vendor: str | None, product: str | None
    ) -> dict | None:
        """Look up a (vendor, product) tuple in the cloud catalog.
        Case-insensitive. Returns None if no entry."""
        if not vendor or not product:
            return None
        return self.cloud_catalog.get((vendor.lower().strip(), product.lower().strip()))

    def _load_d3fend(self) -> None:
        data = self._load_yaml(self.root / "d3fend" / "mappings.yaml") or []
        self.d3fend_rules = [r for r in data if isinstance(r, dict)]

    def _load_maestro(self) -> None:
        layers = self._load_yaml(self.root / "maestro" / "layers.yaml") or []
        threats = self._load_yaml(self.root / "maestro" / "threats.yaml") or []
        self.maestro_layers = {item["id"]: item for item in layers}
        self.maestro_threats = {item["id"]: item for item in threats}

    def _load_atlas(self) -> None:
        tactics = self._load_yaml(self.root / "mitre_atlas" / "tactics.yaml") or []
        techniques = self._load_yaml(self.root / "mitre_atlas" / "techniques.yaml") or []
        mitigations = self._load_yaml(self.root / "mitre_atlas" / "mitigations.yaml") or []
        self.atlas_tactics = {item["id"]: item for item in tactics}
        self.atlas_techniques = {item["id"]: item for item in techniques}
        self.atlas_mitigations = {item["id"]: item for item in mitigations}

    def _load_nist(self) -> None:
        data = self._load_yaml(self.root / "nist_ai_rmf" / "genai_profile.yaml") or []
        self.nist_ai_rmf = {item["id"]: item for item in data}

    def _load_stride(self) -> None:
        data = self._load_yaml(self.root / "stride_ai_matrix.yaml") or {}
        self.stride_matrix = data

    def _load_playbooks(self) -> None:
        playbooks_dir = self.root / "playbooks"
        if not playbooks_dir.exists():
            return
        for path in sorted(playbooks_dir.glob("*.yaml")):
            data = self._load_yaml(path)
            if data and "component_type" in data:
                self.playbooks[data["component_type"]] = data

    def _load_methodology_provenance(self) -> None:
        """v0.16.10: load kb/methodology_provenance.yaml.

        Maps every STRIDE-for-AI category to its published framework
        anchor (Microsoft STRIDE / MITRE ATT&CK / NIST AI RMF / MITRE
        ATLAS). Used by the /methodology web page + the report template
        to surface where each category comes from.
        """
        data = self._load_yaml(self.root / "methodology_provenance.yaml") or {}
        if isinstance(data, dict):
            self.methodology_provenance = data.get("categories") or {}

    # ---------------------------------------------------------------- queries
    def get_playbook(self, component_type: str) -> dict | None:
        return self.playbooks.get(component_type)

    def get_methodology_provenance(self, category: str) -> dict | None:
        """v0.16.10: return the published-framework anchor for a STRIDE
        category, or None if unknown."""
        return self.methodology_provenance.get(category)

    def get_owasp(self, owasp_id: str) -> dict | None:
        return self.owasp_llm.get(owasp_id)

    def get_atlas_technique(self, technique_id: str) -> dict | None:
        return self.atlas_techniques.get(technique_id)

    def get_atlas_mitigation(self, mitigation_id: str) -> dict | None:
        return self.atlas_mitigations.get(mitigation_id)

    def get_atlas_tactic(self, tactic_id: str) -> dict | None:
        return self.atlas_tactics.get(tactic_id)

    def get_owasp_agentic(self, agt_id: str) -> dict | None:
        return self.owasp_agentic.get(agt_id)

    def get_owasp_api(self, api_id: str) -> dict | None:
        return self.owasp_api.get(api_id)

    def get_attack_cloud(self, technique_id: str) -> dict | None:
        return self.attack_cloud.get(technique_id)

    def get_attack_enterprise(self, technique_id: str) -> dict | None:
        return self.attack_enterprise.get(technique_id)

    def get_linddun(self, threat_id: str) -> dict | None:
        return self.linddun.get(threat_id)

    def get_nist_ai_100_2(self, entry_id: str) -> dict | None:
        return self.nist_ai_100_2.get(entry_id)

    def devices_for(self, component_type: str | None = None) -> list[dict]:
        """Return device-catalog entries, optionally filtered by component type."""
        if component_type is None:
            return list(self.devices)
        return [d for d in self.devices if d.get("category") == component_type]

    def get_maestro_layer(self, layer_id: str) -> dict | None:
        return self.maestro_layers.get(layer_id)

    def get_maestro_threat(self, threat_id: str) -> dict | None:
        return self.maestro_threats.get(threat_id)

    def search(self, query: str, framework: str | None = None, limit: int = 10) -> list[dict]:
        """Keyword-OR search across the KB. Returns ranked dicts with `framework`, `id`, `title`,
        `snippet`, and `score` fields."""
        terms = [t.lower() for t in re.findall(r"[\w-]+", query) if len(t) > 1]
        if not terms:
            return []

        candidates: list[tuple[str, dict, str, str]] = []
        if framework in (None, "owasp", "owasp_llm"):
            for v in self.owasp_llm.values():
                candidates.append(("owasp_llm", v, v["title"], v.get("description", "")))
        if framework in (None, "owasp", "owasp_agentic", "agentic"):
            for v in self.owasp_agentic.values():
                candidates.append(("owasp_agentic", v, v["title"], v.get("description", "")))
        if framework in (None, "owasp", "owasp_api", "api"):
            for v in self.owasp_api.values():
                candidates.append(("owasp_api", v, v["title"], v.get("description", "")))
        if framework in (None, "atlas"):
            for v in self.atlas_techniques.values():
                candidates.append(("atlas", v, v["name"], v.get("description", "")))
            for v in self.atlas_tactics.values():
                candidates.append(("atlas", v, v["name"], v.get("description", "")))
            for v in self.atlas_mitigations.values():
                candidates.append(("atlas", v, v["name"], v.get("description", "")))
        if framework in (None, "attack_cloud", "attack", "cloud"):
            for v in self.attack_cloud.values():
                candidates.append(("attack_cloud", v, v["name"], v.get("description", "")))
        if framework in (None, "attack", "attack_enterprise", "enterprise"):
            for v in self.attack_enterprise.values():
                candidates.append(("attack_enterprise", v, v["name"], v.get("description", "")))
        if framework in (None, "linddun", "privacy"):
            for v in self.linddun.values():
                candidates.append(("linddun", v, v["title"], v.get("description", "")))
        if framework in (None, "nist_ai_100_2", "adversarial_ml", "aml"):
            for v in self.nist_ai_100_2.values():
                candidates.append(("nist_ai_100_2", v, v["title"], v.get("description", "")))
        if framework in (None, "owasp", "owasp_ml", "ml"):
            for v in self.owasp_ml.values():
                candidates.append(("owasp_ml", v, v["title"], v.get("description", "")))
        if framework in (None, "compliance", "nis2", "dora", "eu_ai_act",
                          "gdpr", "pci_dss", "hipaa", "nist_800_53",
                          "nist_csf", "iso27001", "sec_cyber"):
            wanted = None
            if framework not in (None, "compliance"):
                wanted = framework.upper().replace("_", "_")
                # Map alias → canonical framework name used in YAML
                aliases = {
                    "NIS2": "NIS2", "DORA": "DORA", "EU_AI_ACT": "EU_AI_Act",
                    "GDPR": "GDPR", "PCI_DSS": "PCI_DSS", "HIPAA": "HIPAA",
                    "NIST_800_53": "NIST_800_53", "NIST_CSF": "NIST_CSF",
                    "ISO27001": "ISO27001", "SEC_CYBER": "SEC_CYBER",
                }
                wanted = aliases.get(wanted, wanted)
            for v in self.compliance_controls.values():
                if wanted and v.get("framework") != wanted:
                    continue
                candidates.append(("compliance", v, v["title"], v.get("description", "")))
        if framework in (None, "nist"):
            for v in self.nist_ai_rmf.values():
                candidates.append(("nist", v, v["title"], v.get("description", "")))
        if framework in (None, "maestro"):
            for v in self.maestro_layers.values():
                candidates.append(("maestro", v, v["name"], v.get("description", "")))
            for v in self.maestro_threats.values():
                candidates.append(("maestro", v, v["name"], v.get("description", "")))

        results: list[dict] = []
        for fw, raw, title, desc in candidates:
            kw_str = " ".join(str(k) for k in raw.get("keywords", []) if k is not None)
            haystack = (str(title) + " " + str(desc) + " " + kw_str).lower()
            score = sum(haystack.count(t) for t in terms)
            if score == 0:
                continue
            results.append(
                {
                    "framework": fw,
                    "id": raw["id"],
                    "title": title,
                    "snippet": desc[:240],
                    "score": score,
                    "source": raw,
                }
            )
        results.sort(key=lambda r: r["score"], reverse=True)
        return results[:limit]


@lru_cache(maxsize=1)
def get_kb() -> KnowledgeBase:
    """Module-level singleton — KB only loads once per process.

    Hot path: deserialize a pickle invalidated by recursive YAML
    mtime/size fingerprint (~30 ms).
    Cold path: parse 166 YAML files into dataclass-shaped dicts
    (~920 ms). Falls back automatically if pickle is missing,
    stale, corrupt, or ATMS_KB_NO_CACHE=1.
    """
    if os.environ.get("ATMS_KB_NO_CACHE"):
        return KnowledgeBase()

    root = _kb_dir()
    signature = _kb_signature(root)
    cache_file = _cache_path(root)

    if cache_file.exists():
        try:
            with cache_file.open("rb") as fh:
                payload = pickle.load(fh)
            if (isinstance(payload, dict)
                    and payload.get("version") == _CACHE_VERSION
                    and payload.get("signature") == signature
                    and isinstance(payload.get("state"), dict)):
                kb = KnowledgeBase.__new__(KnowledgeBase)
                kb.__dict__.update(payload["state"])
                return kb
        except (pickle.PickleError, EOFError, AttributeError, ImportError, OSError) as exc:
            log.debug("kb cache miss (%s); rebuilding", exc)

    kb = KnowledgeBase()
    try:
        cache_file.parent.mkdir(parents=True, exist_ok=True)
        # Pickle to a temp file then atomic-rename to avoid half-written
        # caches if the process dies mid-write.
        tmp = cache_file.with_suffix(cache_file.suffix + ".tmp")
        with tmp.open("wb") as fh:
            pickle.dump({
                "version": _CACHE_VERSION,
                "signature": signature,
                "state": dict(kb.__dict__),
            }, fh, protocol=pickle.HIGHEST_PROTOCOL)
        tmp.replace(cache_file)
    except OSError as exc:
        log.debug("kb cache write failed (%s); continuing without cache", exc)
    return kb
