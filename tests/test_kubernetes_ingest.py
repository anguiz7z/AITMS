"""Regression tests for v0.18.7 Cycle W — Kubernetes manifests ingest.

Pins the contract that multi-document Kubernetes YAML files become
structured ATMS Systems: Deployments → container_runtime, Services →
load_balancer, Ingress → api_gateway, Secrets → secrets_vault,
ConfigMaps → data_source, Namespaces → trust boundaries.

Dataflows inferred from Service selectors, Ingress backends, and
container envFrom/env/volumes references.
"""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_kubernetes_ingest.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import pytest

from atms.ingest.kubernetes import _KIND_MAP, kubernetes_to_system

_K8S_SIMPLE_APP = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: app
spec:
  replicas: 2
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
        - name: web
          image: nginx:1.27
          envFrom:
            - secretRef:
                name: db-creds
            - configMapRef:
                name: web-config
          env:
            - name: API_KEY
              valueFrom:
                secretKeyRef:
                  name: stripe-key
                  key: token
          volumeMounts:
            - name: data
              mountPath: /var/data
      volumes:
        - name: data
          persistentVolumeClaim:
            claimName: web-data
---
apiVersion: v1
kind: Service
metadata:
  name: web
  namespace: app
spec:
  type: LoadBalancer
  selector:
    app: web
  ports:
    - port: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web-ingress
  namespace: app
spec:
  rules:
    - host: example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: web
                port:
                  number: 80
---
apiVersion: v1
kind: Secret
metadata:
  name: db-creds
  namespace: app
type: Opaque
---
apiVersion: v1
kind: Secret
metadata:
  name: stripe-key
  namespace: app
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: web-config
  namespace: app
---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: web-data
  namespace: app
"""


@pytest.fixture
def k8s_manifest_path(tmp_path):
    p = tmp_path / "manifest.yaml"
    p.write_text(_K8S_SIMPLE_APP, encoding="utf-8")
    return p


def test_extracts_seven_components(k8s_manifest_path):
    system = kubernetes_to_system(k8s_manifest_path)
    # Deployment + Service + Ingress + 2 Secrets + ConfigMap + PVC = 7
    assert len(system.components) == 7


def test_classification_by_kind(k8s_manifest_path):
    system = kubernetes_to_system(k8s_manifest_path)
    by_kind = {(c.metadata or {}).get("k8s_kind"): c.type for c in system.components}
    assert by_kind["Deployment"] == "container_runtime"
    assert by_kind["Service"] == "load_balancer"
    assert by_kind["Ingress"] == "api_gateway"
    assert by_kind["Secret"] == "secrets_vault"
    assert by_kind["ConfigMap"] == "data_source"
    assert by_kind["PersistentVolumeClaim"] == "block_storage"


def test_namespace_becomes_trust_boundary(k8s_manifest_path):
    system = kubernetes_to_system(k8s_manifest_path)
    assert len(system.trust_boundaries) == 1
    b = system.trust_boundaries[0]
    assert b.description == "Namespace: app"
    assert b.type == "tenancy"  # namespaces are tenancy in k8s


def test_service_to_deployment_dataflow(k8s_manifest_path):
    """Service selector{app: web} matches Deployment template label
    {app: web} → service → deployment dataflow."""
    system = kubernetes_to_system(k8s_manifest_path)
    edges = {(d.source, d.target) for d in system.dataflows}
    name_to_id = {(c.metadata or {}).get("k8s_name"): c.id for c in system.components}
    # There are two components named "web" (Service + Deployment); we
    # need to disambiguate by kind.
    svc_id = next(c.id for c in system.components
                  if (c.metadata or {}).get("k8s_kind") == "Service")
    dep_id = next(c.id for c in system.components
                  if (c.metadata or {}).get("k8s_kind") == "Deployment")
    assert (svc_id, dep_id) in edges


def test_ingress_to_service_dataflow(k8s_manifest_path):
    system = kubernetes_to_system(k8s_manifest_path)
    edges = {(d.source, d.target) for d in system.dataflows}
    ing_id = next(c.id for c in system.components
                  if (c.metadata or {}).get("k8s_kind") == "Ingress")
    svc_id = next(c.id for c in system.components
                  if (c.metadata or {}).get("k8s_kind") == "Service")
    assert (ing_id, svc_id) in edges


def test_workload_to_secret_dataflows(k8s_manifest_path):
    """Deployment.envFrom + env.valueFrom.secretKeyRef → 2 secrets."""
    system = kubernetes_to_system(k8s_manifest_path)
    edges = {(d.source, d.target) for d in system.dataflows}
    dep_id = next(c.id for c in system.components
                  if (c.metadata or {}).get("k8s_kind") == "Deployment")
    secret_ids = [c.id for c in system.components
                  if (c.metadata or {}).get("k8s_kind") == "Secret"]
    for sid in secret_ids:
        assert (dep_id, sid) in edges, f"Missing {dep_id} → {sid}"


def test_workload_to_configmap_dataflow(k8s_manifest_path):
    system = kubernetes_to_system(k8s_manifest_path)
    edges = {(d.source, d.target) for d in system.dataflows}
    dep_id = next(c.id for c in system.components
                  if (c.metadata or {}).get("k8s_kind") == "Deployment")
    cm_id = next(c.id for c in system.components
                 if (c.metadata or {}).get("k8s_kind") == "ConfigMap")
    assert (dep_id, cm_id) in edges


def test_workload_to_pvc_dataflow(k8s_manifest_path):
    system = kubernetes_to_system(k8s_manifest_path)
    edges = {(d.source, d.target) for d in system.dataflows}
    dep_id = next(c.id for c in system.components
                  if (c.metadata or {}).get("k8s_kind") == "Deployment")
    pvc_id = next(c.id for c in system.components
                  if (c.metadata or {}).get("k8s_kind") == "PersistentVolumeClaim")
    assert (dep_id, pvc_id) in edges


def test_namespace_isolation_two_namespaces(tmp_path):
    p = tmp_path / "two_ns.yaml"
    p.write_text("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: a
  namespace: frontend
spec:
  template:
    metadata:
      labels: {app: a}
    spec:
      containers:
        - name: a
          image: a:1
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: b
  namespace: backend
spec:
  template:
    metadata:
      labels: {app: b}
    spec:
      containers:
        - name: b
          image: b:1
""", encoding="utf-8")
    system = kubernetes_to_system(p)
    descs = {b.description for b in system.trust_boundaries}
    assert "Namespace: frontend" in descs
    assert "Namespace: backend" in descs


def test_unknown_kinds_are_silently_skipped(tmp_path):
    """A manifest with a CRD or HPA mixed in shouldn't crash."""
    p = tmp_path / "mixed.yaml"
    p.write_text("""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: a
  namespace: app
spec:
  template:
    metadata:
      labels: {app: a}
    spec:
      containers:
        - name: a
          image: a:1
---
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: a-hpa
  namespace: app
spec:
  scaleTargetRef:
    name: a
""", encoding="utf-8")
    system = kubernetes_to_system(p)
    assert len(system.components) == 1
    assert system.components[0].name.startswith("a (")


def test_no_documents_raises_clear_error(tmp_path):
    p = tmp_path / "empty.yaml"
    p.write_text("# just a comment\n", encoding="utf-8")
    with pytest.raises(ValueError) as exc:
        kubernetes_to_system(p)
    assert "kubernetes documents" in str(exc.value).lower()


def test_kind_map_covers_20_plus_kinds():
    assert len(_KIND_MAP) >= 20


def test_metadata_carries_k8s_fields(k8s_manifest_path):
    system = kubernetes_to_system(k8s_manifest_path)
    dep = next(c for c in system.components
               if (c.metadata or {}).get("k8s_kind") == "Deployment")
    assert dep.metadata["k8s_kind"] == "Deployment"
    assert dep.metadata["k8s_namespace"] == "app"
    assert dep.metadata["k8s_name"] == "web"
    assert dep.metadata["source"] == "kubernetes:deployment"


def test_end_to_end_through_analyze(k8s_manifest_path):
    """The parsed System runs through analyze() cleanly."""
    from atms.workflow import analyze
    system = kubernetes_to_system(k8s_manifest_path)
    tm = analyze(system, require_ai_components=False)
    assert tm.threats
