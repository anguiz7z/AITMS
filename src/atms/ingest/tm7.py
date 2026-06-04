"""Microsoft Threat Modeling Tool (.tm7) → ATMS System (v0.18.41 Cycle EEE).

12th input format. Closes a real enterprise gap — the Microsoft
Threat Modeling Tool is the de-facto threat-modelling tool inside
many regulated organisations (banks, healthcare, defense). Its
files have a `.tm7` extension and contain Microsoft DataContract-
serialized XML.

The format (clean-room implementation, no Microsoft code copied —
just standard XML parsing of a documented public format):

  <ThreatModel xmlns="http://schemas.datacontract.org/.../ThreatModeling.Model">
    <DrawingSurfaceList>
      <DrawingSurfaceModel>
        <Borders>
          <KeyValueOfguidanyType>
            <Key>{guid}</Key>
            <Value i:type="StencilRectangle">   <!-- external entity -->
              <GenericTypeId>GE.EI</GenericTypeId>
              <Properties>
                <a:anyType i:type="b:HeaderDisplayAttribute">
                  <b:DisplayName>User</b:DisplayName>
                </a:anyType>
              </Properties>
            </Value>
          </KeyValueOfguidanyType>
          ...
        </Borders>
        <Lines>
          <KeyValueOfguidanyType>
            <Value i:type="Connector">
              <SourceGuid>...</SourceGuid>
              <TargetGuid>...</TargetGuid>
            </Value>
          </KeyValueOfguidanyType>
        </Lines>
      </DrawingSurfaceModel>
    </DrawingSurfaceList>
  </ThreatModel>

Element-shape conventions (Microsoft DFD primitive set):
  - StencilRectangle  → external entity / actor      (default: user)
  - StencilEllipse    → process                       (default: web_application)
  - StencilParallelLines → data store                 (default: database)
  - BorderBoundary    → trust boundary
  - Connector         → dataflow

Display-name keyword refinement (the actual identity comes from
what the modeler typed in the diagram):
  - "WAF" / "firewall" / "gateway" → waf | api_gateway | firewall
  - "lambda" / "function" / "worker" → serverless_function
  - "queue" / "topic" → message_queue
  - "S3" / "blob" / "object" → object_storage
  - "secrets" / "vault" → secrets_vault

Pure stdlib + defusedxml (already a runtime dep), no Microsoft code
borrowed, no network call.
"""

from __future__ import annotations

import logging
from pathlib import Path

from defusedxml import ElementTree as _ET

from ..features import gated
from ..models import Component, Dataflow, System, TrustBoundary

log = logging.getLogger(__name__)


# Microsoft's TM7 XML uses three namespaces; the bulk lives under
# `ThreatModeling.Model.*`, the typed properties under `KnowledgeBase`,
# and the XSI type discriminator is its own namespace.
_NS_MODEL = "{http://schemas.datacontract.org/2004/07/ThreatModeling.Model}"
_NS_ABS   = "{http://schemas.datacontract.org/2004/07/ThreatModeling.Model.Abstracts}"
_NS_KB    = "{http://schemas.datacontract.org/2004/07/ThreatModeling.KnowledgeBase}"
_NS_ARR   = "{http://schemas.microsoft.com/2003/10/Serialization/Arrays}"
_NS_XSI   = "{http://www.w3.org/2001/XMLSchema-instance}"


# Stencil shape (from the `i:type` attribute on each Value node) →
# default ATMS ComponentType. Keyword-based refinement runs on top.
_SHAPE_DEFAULT: dict[str, str] = {
    "StencilRectangle":     "user",            # external interactor
    "StencilEllipse":       "web_application", # generic process
    "StencilParallelLines": "database",        # generic data store
    # `BorderBoundary` is special-cased — emits a TrustBoundary, not a Component.
}


def _display_name(properties_node) -> str:
    """Walk a `<Properties>` block looking for the `HeaderDisplayAttribute`
    entry — that's the user-visible label on the element."""
    if properties_node is None:
        return ""
    for any_type in properties_node.findall(f"{_NS_ARR}anyType"):
        xsi_type = any_type.get(f"{_NS_XSI}type", "")
        if "HeaderDisplayAttribute" in xsi_type:
            display = any_type.find(f"{_NS_KB}DisplayName")
            if display is not None and display.text:
                return display.text.strip()
    return ""


def _refine_type(default: str, name: str) -> str:
    """Refine the stencil-shape default using keywords in the display
    name. Empty / unrecognised names keep the default."""
    n = (name or "").lower()
    if default == "user":
        return "user"  # external entity stays external entity
    if default == "web_application":
        if any(k in n for k in ("waf", "web app firewall")):
            return "waf"
        if any(k in n for k in ("api gateway", "api-gateway", "apigateway")):
            return "api_gateway"
        if "firewall" in n:
            return "firewall"
        if "load balancer" in n or "lb " in n or n.endswith(" lb"):
            return "load_balancer"
        if any(k in n for k in ("lambda", "function", "worker", "background")):
            return "serverless_function"
        if any(k in n for k in ("container", "pod", "deployment")):
            return "container_runtime"
        if any(k in n for k in ("agent",)):
            return "agent"
        if any(k in n for k in ("llm", "gpt", "claude", "bedrock", "openai",
                                  "anthropic", "model")):
            return "llm_inference"
        return "web_application"
    if default == "database":
        if any(k in n for k in ("s3", "blob", "object storage")):
            return "object_storage"
        if any(k in n for k in ("queue", "sqs", "service bus")):
            return "message_queue"
        if any(k in n for k in ("topic", "kafka", "event hub", "kinesis", "pubsub")):
            return "stream_processor"
        if any(k in n for k in ("secrets manager", "secret manager", "key vault", "vault")):
            return "secrets_vault"
        if any(k in n for k in ("kms", "cmk", "hsm", "key management")):
            return "kms_key"
        if any(k in n for k in ("redis", "memcached", "elasticache")):
            return "cache_store"
        if any(k in n for k in ("dynamodb", "cosmos", "mongo", "nosql")):
            return "nosql_database"
        if any(k in n for k in ("config", "configuration")):
            return "data_source"
        return "database"
    return default


def _sanitise_id(name: str, fallback: str) -> str:
    """ATMS Component.id is bounded to 64 chars + word/dash/underscore-safe."""
    import re
    s = re.sub(r"[^A-Za-z0-9_-]", "_", (name or fallback)).strip("_")
    return (s[:64] or fallback[:64]).lower()


@gated("ingest_tm7")
def tm7_to_system(
    path: str | Path | None = None,
    text: str | None = None,
    system_name: str | None = None,
) -> System:
    """Parse a Microsoft Threat Modeling Tool (.tm7) file into an
    ATMS `System`.

    Args:
        path: Path to the .tm7 file. Mutually exclusive with `text`.
        text: Raw XML text. Use instead of `path` when the file isn't
            on disk.
        system_name: Override the System name.

    Returns:
        ATMS System with elements mapped to typed components,
        connectors to dataflows, boundaries to trust boundaries.

    Raises:
        ValueError: if the document is not a TM7 file.
    """
    if path is not None and text is None:
        p = Path(path)
        text = p.read_text(encoding="utf-8")
        default_name = p.stem
    elif text is not None:
        default_name = "tm7-import"
    else:
        raise ValueError("Provide either `path` or `text`")

    try:
        root = _ET.fromstring(text)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"TM7 XML parse error: {exc}") from exc

    # Accept only `{ThreatModeling.Model namespace}ThreatModel` — guards
    # against random XML files that just happen to end with "ThreatModel".
    if not root.tag == f"{_NS_MODEL}ThreatModel":
        raise ValueError(
            "Not a Microsoft TM7 file (root element is not "
            "<ThreatModel xmlns=ThreatModeling.Model>). If this is an "
            "OTM JSON or a System YAML, use the right ingester."
        )

    components: list[Component] = []
    dataflows: list[Dataflow] = []
    boundaries: list[TrustBoundary] = []
    guid_to_id: dict[str, str] = {}
    used_ids: set[str] = set()

    drawing_surface_list = root.find(f"{_NS_MODEL}DrawingSurfaceList")
    if drawing_surface_list is None:
        raise ValueError("TM7 missing <DrawingSurfaceList>")

    for surface in drawing_surface_list.findall(f"{_NS_MODEL}DrawingSurfaceModel"):
        borders = surface.find(f"{_NS_ABS}Borders")
        lines = surface.find(f"{_NS_ABS}Lines")

        # ─── Pass 1: typed elements + boundaries ───
        if borders is not None:
            for kv in borders.findall(f"{_NS_ARR}KeyValueOfguidanyType"):
                key_el = kv.find(f"{_NS_ARR}Key")
                val_el = kv.find(f"{_NS_ARR}Value")
                if val_el is None or key_el is None or not key_el.text:
                    continue
                guid = key_el.text.strip()
                xsi_type = val_el.get(f"{_NS_XSI}type", "")
                # `properties` may live in either the abstract or model NS
                properties = val_el.find(f"{_NS_ABS}Properties")
                if properties is None:
                    properties = val_el.find(f"{_NS_MODEL}Properties")
                display = _display_name(properties)

                if "BorderBoundary" in xsi_type:
                    boundaries.append(TrustBoundary(
                        id=_sanitise_id(display or f"tm7-bd-{guid[:8]}",
                                          fallback=f"tm7-bd-{guid[:8]}"),
                        type="network",
                        description=display or "Trust boundary",
                    ))
                    continue

                # Element default + keyword refinement.
                shape_default = None
                for shape, dflt in _SHAPE_DEFAULT.items():
                    if shape in xsi_type:
                        shape_default = dflt
                        break
                if shape_default is None:
                    continue  # unknown stencil; ignore quietly
                ctype = _refine_type(shape_default, display)

                # Build a unique sanitised id.
                base = _sanitise_id(display, fallback=f"tm7-{guid[:8]}")
                comp_id = base
                suffix = 2
                while comp_id in used_ids:
                    comp_id = f"{base}_{suffix}"[:64]
                    suffix += 1
                used_ids.add(comp_id)
                guid_to_id[guid] = comp_id

                components.append(Component(
                    id=comp_id,
                    name=(display or comp_id)[:200],
                    type=ctype,  # type: ignore[arg-type]
                    description=(
                        f"Imported from Microsoft Threat Modeling Tool "
                        f"({xsi_type.split(':')[-1]}, guid={guid})"
                    )[:1000],
                    metadata={"tm7_guid": guid, "source": "tm7",
                               "tm7_shape": xsi_type.split(":")[-1]},
                ))

        # ─── Pass 2: connectors (dataflows) ───
        if lines is not None:
            for kv in lines.findall(f"{_NS_ARR}KeyValueOfguidanyType"):
                val_el = kv.find(f"{_NS_ARR}Value")
                if val_el is None:
                    continue
                xsi_type = val_el.get(f"{_NS_XSI}type", "")
                if "Connector" not in xsi_type and "Line" not in xsi_type:
                    continue
                # Source/Target GUIDs live as direct children.
                src_el = val_el.find(f"{_NS_MODEL}SourceGuid")
                tgt_el = val_el.find(f"{_NS_MODEL}TargetGuid")
                if src_el is None or tgt_el is None:
                    continue
                src_guid = (src_el.text or "").strip()
                tgt_guid = (tgt_el.text or "").strip()
                if src_guid not in guid_to_id or tgt_guid not in guid_to_id:
                    continue
                properties = val_el.find(f"{_NS_ABS}Properties")
                if properties is None:
                    properties = val_el.find(f"{_NS_MODEL}Properties")
                label = _display_name(properties) or ""
                dataflows.append(Dataflow(
                    source=guid_to_id[src_guid],
                    target=guid_to_id[tgt_guid],
                    label=label,
                ))

    if not components:
        raise ValueError(
            "TM7 parse: no recognisable elements found. Verify the file is "
            "saved from a recent Microsoft Threat Modeling Tool (v7.x)."
        )

    return System(
        name=system_name or default_name,
        description=(
            f"Imported from Microsoft Threat Modeling Tool (.tm7) — "
            f"{len(components)} elements, {len(dataflows)} dataflows, "
            f"{len(boundaries)} boundaries."
        ),
        components=components,
        dataflows=dataflows,
        trust_boundaries=boundaries,
    )


__all__ = ["tm7_to_system"]
