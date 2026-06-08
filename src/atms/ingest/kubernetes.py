"""Kubernetes manifests → ATMS System (v0.18.7 Cycle W).

Adds Kubernetes YAML as an 8th ingest format. Most cloud-native shops
run k8s; many teams want their cluster topology threat-modeled
without re-drawing in another tool.

Coverage: 20+ Kubernetes kinds across workload, networking, identity,
storage, and policy. Multi-document YAMLs (the common case — Helm
output, `kubectl get all -o yaml`) parse via `yaml.safe_load_all`.

  Workload         Deployment / StatefulSet / DaemonSet / Pod /
                    ReplicaSet / Job / CronJob
  Network          Service / Ingress / NetworkPolicy / Gateway /
                    HTTPRoute
  Identity         ServiceAccount / Role / RoleBinding /
                    ClusterRole / ClusterRoleBinding
  Storage          PersistentVolume / PersistentVolumeClaim /
                    StorageClass
  Config           ConfigMap / Secret
  Boundary         Namespace (becomes a trust boundary)

Dataflow inference:
  - Service → backing Pods (via spec.selector matched on labels):
    represented as Service → Deployment (the most specific workload).
  - Workload → Secret (via spec.template.spec.containers[].envFrom
    / env[].valueFrom.secretKeyRef / volumes[].secret.secretName):
    the workload references the Secret.
  - Workload → ConfigMap: same pattern.
  - Workload → PersistentVolumeClaim (via volumes[].persistentVolumeClaim).
  - Ingress → Service (via spec.rules[].http.paths[].backend.service.name).

Pure-Python, stdlib + PyYAML, zero network, fully offline.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml

from ..features import gated
from ..models import Component, Dataflow, System, TrustBoundary

log = logging.getLogger(__name__)


# Kubernetes kind → ATMS component_type.
_KIND_MAP: dict[str, str] = {
    # Workload kinds — Deployments / StatefulSets / DaemonSets all
    # run pods on the cluster runtime. ATMS treats them as
    # container_runtime instances.
    "Pod": "container_runtime",
    "Deployment": "container_runtime",
    "StatefulSet": "container_runtime",
    "DaemonSet": "container_runtime",
    "ReplicaSet": "container_runtime",
    "ReplicationController": "container_runtime",
    "Job": "batch_compute",
    "CronJob": "batch_compute",

    # Networking
    "Service": "load_balancer",       # ClusterIP / LoadBalancer / NodePort
    "Ingress": "api_gateway",
    "Gateway": "api_gateway",          # Gateway API
    "HTTPRoute": "api_gateway",
    "NetworkPolicy": "firewall",

    # Identity / RBAC
    "ServiceAccount": "iam_principal",
    "Role": "iam_principal",
    "RoleBinding": "iam_principal",
    "ClusterRole": "iam_principal",
    "ClusterRoleBinding": "iam_principal",

    # Storage
    "PersistentVolume": "block_storage",
    "PersistentVolumeClaim": "block_storage",
    "StorageClass": "block_storage",

    # Config + Secrets
    "ConfigMap": "data_source",
    "Secret": "secrets_vault",

    # Skip:
    # HorizontalPodAutoscaler, PodDisruptionBudget,
    # CustomResourceDefinition, VerticalPodAutoscaler — not
    # threat-modeled as components (they're orchestration metadata).
}

_SKIP_KINDS = frozenset({
    "HorizontalPodAutoscaler", "VerticalPodAutoscaler",
    "PodDisruptionBudget", "CustomResourceDefinition", "Namespace",
    "Lease", "Event", "ResourceQuota", "LimitRange",
    "EndpointSlice", "Endpoints",
})


def _safe_id(raw: str, used: set[str]) -> str:
    """Sanitise a k8s resource name into an ATMS component id."""
    base = re.sub(r"[^a-z0-9_]+", "_", (raw or "").lower()).strip("_") or "resource"
    candidate = base
    n = 2
    while candidate in used:
        candidate = f"{base}_{n}"
        n += 1
    used.add(candidate)
    return candidate


def _collect_secret_refs(spec: dict) -> set[str]:
    """Walk a PodSpec (or PodTemplateSpec.spec) and return the set of
    Secret names referenced via envFrom, env.valueFrom.secretKeyRef,
    and volumes.secret.secretName."""
    if not isinstance(spec, dict):
        return set()
    found: set[str] = set()
    for container in spec.get("containers", []) or []:
        if not isinstance(container, dict):
            continue
        # envFrom: [{secretRef: {name: ...}}, ...]
        for env_from in container.get("envFrom", []) or []:
            if isinstance(env_from, dict):
                sr = env_from.get("secretRef")
                if isinstance(sr, dict) and isinstance(sr.get("name"), str):
                    found.add(sr["name"])
        # env: [{valueFrom: {secretKeyRef: {name: ...}}}]
        for env in container.get("env", []) or []:
            if isinstance(env, dict):
                vf = env.get("valueFrom")
                if isinstance(vf, dict):
                    sr = vf.get("secretKeyRef")
                    if isinstance(sr, dict) and isinstance(sr.get("name"), str):
                        found.add(sr["name"])
    # volumes: [{secret: {secretName: ...}}]
    for vol in spec.get("volumes", []) or []:
        if isinstance(vol, dict):
            s = vol.get("secret")
            if isinstance(s, dict) and isinstance(s.get("secretName"), str):
                found.add(s["secretName"])
    return found


def _collect_configmap_refs(spec: dict) -> set[str]:
    """Similar to _collect_secret_refs but for ConfigMaps."""
    if not isinstance(spec, dict):
        return set()
    found: set[str] = set()
    for container in spec.get("containers", []) or []:
        if not isinstance(container, dict):
            continue
        for env_from in container.get("envFrom", []) or []:
            if isinstance(env_from, dict):
                cmr = env_from.get("configMapRef")
                if isinstance(cmr, dict) and isinstance(cmr.get("name"), str):
                    found.add(cmr["name"])
        for env in container.get("env", []) or []:
            if isinstance(env, dict):
                vf = env.get("valueFrom")
                if isinstance(vf, dict):
                    cmr = vf.get("configMapKeyRef")
                    if isinstance(cmr, dict) and isinstance(cmr.get("name"), str):
                        found.add(cmr["name"])
    for vol in spec.get("volumes", []) or []:
        if isinstance(vol, dict):
            cm = vol.get("configMap")
            if isinstance(cm, dict) and isinstance(cm.get("name"), str):
                found.add(cm["name"])
    return found


def _collect_pvc_refs(spec: dict) -> set[str]:
    if not isinstance(spec, dict):
        return set()
    found: set[str] = set()
    for vol in spec.get("volumes", []) or []:
        if isinstance(vol, dict):
            pvc = vol.get("persistentVolumeClaim")
            if isinstance(pvc, dict) and isinstance(pvc.get("claimName"), str):
                found.add(pvc["claimName"])
    return found


def _pod_spec(doc: dict) -> dict:
    """Resolve the PodSpec from a workload manifest. For Pods it's
    `spec`. For Deployments/StatefulSets/etc. it's
    `spec.template.spec`."""
    kind = doc.get("kind", "")
    if kind == "Pod":
        return doc.get("spec", {}) or {}
    return ((doc.get("spec") or {}).get("template") or {}).get("spec") or {}


@gated("ingest_k8s")
def kubernetes_to_system(
    source: Path | str,
    system_name: str | None = None,
) -> System:
    """Parse a Kubernetes manifest YAML (single or multi-doc) into a System.

    Args:
        source: filesystem Path OR inline YAML text.
        system_name: override; defaults to filename stem or "k8s".

    Returns: System draft. Review + edit before analyze().
    """
    if isinstance(source, Path) or (
        isinstance(source, str) and Path(source).exists()
    ):
        path = Path(source)
        text = path.read_text(encoding="utf-8")
        default_name = path.stem
    else:
        text = str(source)
        default_name = "k8s"

    docs = [d for d in yaml.safe_load_all(text) if isinstance(d, dict)]
    # audit F055: a malformed manifest may carry a scalar/null `metadata`
    # (instead of a mapping). Normalise it to {} ONCE so every downstream loop
    # (workload labels, Service selectors, Ingress backends) is crash-safe.
    for _d in docs:
        if not isinstance(_d.get("metadata"), dict):
            _d["metadata"] = {}
    if not docs:
        raise ValueError(
            "No Kubernetes documents found in input. Expected one or "
            "more YAML documents with `kind:` and `metadata:` fields."
        )

    # First pass: collect components + index by (kind, name, namespace).
    # Using kind in the key is necessary because Service and Deployment
    # commonly share the same `name` in the same namespace (Helm idiom);
    # keying only on (name, namespace) loses one of them.
    used_ids: set[str] = set()
    name_to_id: dict[tuple[str, str, str], str] = {}  # (kind, name, ns) → id
    components: list[Component] = []
    namespace_members: dict[str, list[str]] = {}

    def _lookup_by_name(name: str, ns: str, kinds: tuple[str, ...]) -> str | None:
        """Look up a component id by name + namespace, restricted to one
        or more kinds. Returns the first match; order = kinds tuple."""
        for k in kinds:
            cid = name_to_id.get((k, name, ns))
            if cid:
                return cid
        return None

    _WORKLOAD_KINDS = (
        "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet",
        "Pod", "Job", "CronJob", "ReplicationController",
    )

    for doc in docs:
        # audit F055: a multi-doc YAML may contain a scalar/null document, and
        # metadata may be a scalar instead of a mapping -- tolerate both.
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        if kind in _SKIP_KINDS:
            continue
        if kind not in _KIND_MAP:
            continue  # unknown kind — silently skip (avoids cluttering with CRDs)
        meta = doc.get("metadata")
        meta = meta if isinstance(meta, dict) else {}
        name = meta.get("name") or ""
        namespace = meta.get("namespace") or "default"
        if not name:
            continue
        comp_id = _safe_id(f"{kind.lower()}_{name}", used_ids)
        name_to_id[(kind, name, namespace)] = comp_id

        # Type override: Service.spec.type=LoadBalancer signals public-
        # facing; otherwise it's internal. Both still map to
        # load_balancer in ATMS.
        ctype = _KIND_MAP[kind]

        components.append(Component(
            id=comp_id,
            name=f"{name} ({kind})",
            type=ctype,  # type: ignore[arg-type]
            trust_zone=namespace.replace("-", "_"),
            metadata={
                "source": f"kubernetes:{kind.lower()}",
                "k8s_kind": kind,
                "k8s_namespace": namespace,
                "k8s_name": name,
            },
        ))
        namespace_members.setdefault(namespace, []).append(comp_id)

    # Second pass: derive dataflows.
    dataflows: list[Dataflow] = []
    seen_edges: set[tuple[str, str]] = set()

    def _add_edge(src_id: str, tgt_id: str, label: str) -> None:
        if src_id == tgt_id:
            return
        edge = (src_id, tgt_id)
        if edge in seen_edges:
            return
        seen_edges.add(edge)
        dataflows.append(Dataflow(source=src_id, target=tgt_id, label=label))

    # Index pod-template labels for Service selectors.
    workload_labels: dict[str, dict] = {}  # comp_id → labels dict
    for doc in docs:
        kind = doc.get("kind", "")
        if kind not in _WORKLOAD_KINDS:
            continue
        meta = doc.get("metadata")
        meta = meta if isinstance(meta, dict) else {}  # audit F055
        name = meta.get("name")
        ns = meta.get("namespace") or "default"
        if not name:
            continue
        comp_id = name_to_id.get((kind, name, ns))
        if not comp_id:
            continue
        if kind == "Pod":
            labels = meta.get("labels")
            workload_labels[comp_id] = labels if isinstance(labels, dict) else {}
        else:
            template_meta = ((doc.get("spec") or {}).get("template") or {}).get("metadata")
            template_meta = template_meta if isinstance(template_meta, dict) else {}  # audit F055
            labels = template_meta.get("labels")
            workload_labels[comp_id] = labels if isinstance(labels, dict) else {}

    # Service.spec.selector → workload matching the labels.
    for doc in docs:
        if doc.get("kind") != "Service":
            continue
        meta = doc.get("metadata", {}) or {}
        svc_name = meta.get("name")
        svc_ns = meta.get("namespace") or "default"
        if not svc_name:
            continue
        svc_id = name_to_id.get(("Service", svc_name, svc_ns))
        if not svc_id:
            continue
        selector = (doc.get("spec") or {}).get("selector") or {}
        if not isinstance(selector, dict) or not selector:
            continue
        for wl_id, labels in workload_labels.items():
            if all(labels.get(k) == v for k, v in selector.items()):
                _add_edge(svc_id, wl_id, "route")

    # Ingress.spec.rules → backend Service.
    for doc in docs:
        if doc.get("kind") not in {"Ingress", "HTTPRoute"}:
            continue
        meta = doc.get("metadata", {}) or {}
        ing_id = name_to_id.get((doc["kind"], meta.get("name", ""),
                                  meta.get("namespace") or "default"))
        if not ing_id:
            continue
        rules = (doc.get("spec") or {}).get("rules") or []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            http = rule.get("http") or {}
            for path_spec in http.get("paths", []) or []:
                if not isinstance(path_spec, dict):
                    continue
                backend = path_spec.get("backend") or {}
                svc_ref = (backend.get("service") or {}).get("name")
                if not svc_ref:
                    svc_ref = backend.get("serviceName")
                if svc_ref:
                    target = name_to_id.get(("Service", svc_ref,
                                              meta.get("namespace") or "default"))
                    if target:
                        _add_edge(ing_id, target, "HTTPS route")

    # Workload → Secret / ConfigMap / PVC references.
    for doc in docs:
        kind = doc.get("kind", "")
        if kind not in _WORKLOAD_KINDS:
            continue
        meta = doc.get("metadata", {}) or {}
        name = meta.get("name")
        ns = meta.get("namespace") or "default"
        if not name:
            continue
        comp_id = name_to_id.get((kind, name, ns))
        if not comp_id:
            continue
        spec = _pod_spec(doc)
        for secret_name in _collect_secret_refs(spec):
            tgt = name_to_id.get(("Secret", secret_name, ns))
            if tgt:
                _add_edge(comp_id, tgt, "fetch secret")
        for cm_name in _collect_configmap_refs(spec):
            tgt = name_to_id.get(("ConfigMap", cm_name, ns))
            if tgt:
                _add_edge(comp_id, tgt, "load config")
        for pvc_name in _collect_pvc_refs(spec):
            tgt = name_to_id.get(("PersistentVolumeClaim", pvc_name, ns))
            if tgt:
                _add_edge(comp_id, tgt, "mount volume")

    # Trust boundaries from namespaces (skip 'default' if only one).
    trust_boundaries: list[TrustBoundary] = []
    namespace_ids_used: set[str] = set()
    for ns, members in namespace_members.items():
        if not members:
            continue
        # Skip the implicit 'default' ns when there's no explicit
        # namespace separation in the manifests.
        if ns == "default" and len(namespace_members) == 1:
            continue
        b_id = _safe_id(f"ns_{ns}", namespace_ids_used)
        trust_boundaries.append(TrustBoundary(
            id=b_id,
            type="tenancy",  # namespaces are tenancy boundaries in k8s
            components_inside=sorted(set(members)),
            description=f"Namespace: {ns}",
        ))

    return System(
        name=system_name or default_name,
        components=components,
        dataflows=dataflows,
        trust_boundaries=trust_boundaries,
    )


__all__ = ["kubernetes_to_system", "_KIND_MAP"]
