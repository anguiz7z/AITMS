"""docker-compose ingest (v0.14).

Reads a `docker-compose.yml` (or `compose.yaml`) and produces an ATMS
System YAML. Each service becomes a Component; image vendor/product is
sniffed from the image tag, the version is the image's tag suffix.

Networks become trust zones; depends_on edges become dataflows. Ports
exposed to the host map to a `user → service` flow on `0.0.0.0` so the
attack-paths engine sees the public-facing surface.

This is a pragmatic mapper, not a full Compose v3 spec parser — fields
we don't recognise are preserved on `component.metadata.compose` for
later inspection.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from ..features import gated
from ..models import Component, Dataflow, System, TrustBoundary

# Common image-name prefix → ATMS component_type
_IMAGE_HINTS: list[tuple[str, str]] = [
    ("postgres", "database"), ("mysql", "database"), ("mariadb", "database"),
    ("mongo", "database"), ("redis", "database"), ("elasticsearch", "database"),
    ("opensearch", "rag_vector_store"), ("qdrant", "rag_vector_store"),
    ("weaviate", "rag_vector_store"), ("milvus", "rag_vector_store"),
    ("chroma", "rag_vector_store"), ("pgvector", "rag_vector_store"),
    ("rabbitmq", "message_queue"), ("kafka", "message_queue"),
    ("nats", "message_queue"), ("activemq", "message_queue"),
    ("nginx", "load_balancer"), ("haproxy", "load_balancer"),
    ("traefik", "load_balancer"), ("envoy", "load_balancer"),
    ("vault", "secrets_vault"), ("hashicorp/vault", "secrets_vault"),
    ("ollama", "llm_inference"), ("vllm", "llm_inference"),
    ("ghcr.io/huggingface/text-generation-inference", "llm_inference"),
    ("nvcr.io/nvidia/tritonserver", "llm_inference"),
    ("openwebui", "web_application"), ("anythingllm", "web_application"),
    ("langfuse", "observability_stack"),
    ("grafana", "observability_stack"), ("prometheus", "observability_stack"),
    ("loki", "observability_stack"), ("jaeger", "observability_stack"),
    ("kibana", "observability_stack"), ("logstash", "observability_stack"),
    ("minio", "object_storage"),
    ("keycloak", "directory_service"), ("openldap", "directory_service"),
    ("authelia", "mfa_service"), ("authentik", "directory_service"),
    ("postfix", "email_server"),
    # NOTE: bare language base images (`python`, `node`, `openjdk`, `php`)
    # used to default to `web_application` here. That's wrong as often
    # as it's right — Python images frequently host ML training jobs,
    # agent runtimes, or one-shot batch processors. Mapping them to a
    # type silently produces the wrong threat playbook. As of v0.14.4
    # these fall through to `container_runtime` (the safe default in
    # `_classify_image`) and the user is expected to fix the type in
    # the GUI editor or YAML before running the analysis.
    ("nginx-rtmp", "web_application"),
]


def _classify_image(image: str) -> str:
    img = (image or "").lower()
    if not img:
        return "other"
    for prefix, ctype in _IMAGE_HINTS:
        if prefix in img:
            return ctype
    return "container_runtime"


def _split_image(image: str) -> tuple[str, str]:
    """Return ``(image_name, version)`` from ``repo/name:tag``.

    The naive ``rsplit(":", 1)`` mishandles registry ports —
    ``localhost:5000/myimg`` (no tag) would split into ``localhost`` /
    ``5000/myimg``. Reference: Docker reference grammar at
    https://github.com/distribution/reference/blob/main/grammar.go —
    the rightmost ``:`` is only a tag separator if it appears AFTER the
    last ``/`` in the image string.
    """
    if not image:
        return "", ""
    if "@" in image:
        # Strip digest first.
        image = image.split("@", 1)[0]
    if image.startswith(("http://", "https://")):
        return image, "latest"
    last_slash = image.rfind("/")
    last_colon = image.rfind(":")
    # Only treat the rightmost colon as a tag separator when it's AFTER
    # the last `/`. Otherwise it's a registry port.
    if last_colon > last_slash and last_colon != -1:
        return image[:last_colon], image[last_colon + 1:]
    return image, "latest"


def _sanitise_id(s: str) -> str:
    out = []
    for ch in (s or ""):
        if ch.isalnum() or ch in {"_", "-"}:
            out.append(ch)
        else:
            out.append("_")
    return ("".join(out) or "svc")[:64]


@gated("ingest_compose")
def parse_docker_compose(path: Path) -> System:
    """Parse a docker-compose YAML into an ATMS System."""
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("docker-compose file must be a YAML mapping at the top level")

    services = raw.get("services") or {}
    networks = raw.get("networks") or {}
    name = (raw.get("name") or Path(path).parent.name or "compose-import")[:200]

    # Trust zones from networks. Default network is "default".
    zone_names = list(networks.keys()) or ["default"]
    components: list[Component] = []
    component_ids: dict[str, str] = {}

    for svc_name, svc in (services or {}).items():
        if not isinstance(svc, dict):
            continue
        cid = _sanitise_id(svc_name)
        component_ids[svc_name] = cid
        image = str(svc.get("image", ""))
        ctype = _classify_image(image)
        img_name, version = _split_image(image)
        # Pick a trust zone from the service's networks list (first one)
        svc_networks = svc.get("networks") or []
        if isinstance(svc_networks, dict):
            svc_networks = list(svc_networks.keys())
        zone = (svc_networks[0] if svc_networks else "default")
        meta: dict = {"compose_service": svc_name}
        if image:
            meta["image"] = image
            if img_name:
                meta["product"] = img_name
            if version and version != "latest":
                meta["version"] = version
        ports = svc.get("ports") or []
        if isinstance(ports, list) and ports:
            meta["ports"] = [str(p) for p in ports][:8]
        components.append(Component(
            id=cid,
            name=svc_name[:200],
            type=ctype,  # type: ignore[arg-type]
            description=str(svc.get("container_name", ""))[:1000],
            trust_zone=str(zone)[:64],
            metadata=meta,
        ))

    # If any service exposes a host port, add a User component + flow.
    has_external = any(
        (svc.get("ports") or []) for svc in services.values() if isinstance(svc, dict)
    )
    user_id = ""
    if has_external:
        user_id = "user_external"
        components.append(Component(
            id=user_id, name="External user", type="user", trust_zone="internet",
            description="Synthetic actor for any service with host-mapped ports.",
        ))

    # Dataflows: depends_on relationships + (user → exposed services)
    dataflows: list[Dataflow] = []
    for svc_name, svc in (services or {}).items():
        if not isinstance(svc, dict):
            continue
        cid = component_ids.get(svc_name)
        if not cid:
            continue
        dep_list = svc.get("depends_on") or []
        if isinstance(dep_list, dict):
            dep_list = list(dep_list.keys())
        for dep in dep_list:
            tgt = component_ids.get(dep)
            if tgt:
                dataflows.append(Dataflow(source=cid, target=tgt, label="depends_on"))
        if user_id and (svc.get("ports") or []):
            dataflows.append(Dataflow(
                source=user_id, target=cid, label="exposed port",
                crosses_boundary=True,
            ))

    # Trust boundary per docker network
    trust_boundaries: list[TrustBoundary] = []
    for zone in zone_names:
        inside = [c.id for c in components if c.trust_zone == zone]
        if inside:
            trust_boundaries.append(TrustBoundary(
                id=_sanitise_id(zone),
                type="network",
                components_inside=inside,
                components_outside=[c.id for c in components if c.id not in inside],
                description=f"docker network: {zone}",
            ))

    return System(
        name=name,
        description=f"Imported from docker-compose at {Path(path).name}",
        components=components,
        dataflows=dataflows,
        trust_boundaries=trust_boundaries,
    )


__all__ = ["parse_docker_compose"]
