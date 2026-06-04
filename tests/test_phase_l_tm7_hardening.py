"""Phase L — Microsoft TM7 parser hardening / branch-coverage closure.

Roadmap V4 Phase L. `src/atms/ingest/tm7.py` (the Microsoft Threat
Modeling Tool .tm7 ingester) sat at 74.1% line coverage — 29 missed
statements out of 149. The existing test exercises the bundled
synthetic fixture for the happy path, but never drives:

  * `_refine_type` keyword branches beyond the few used in the fixture
    (firewall / load balancer / container / agent / llm-inference /
    nosql / cache / config / kms / stream-processor)
  * `tm7_to_system` error paths (no path AND no text, malformed XML,
    wrong root element, missing DrawingSurfaceList, empty document)
  * Element with no recognised stencil type → silently skipped
  * Duplicate display-name → id-collision suffixing
  * Connector with missing source / target / both
  * Connector with unknown source-guid OR target-guid → skipped
  * `Line` xsi:type variant (not just `Connector`)
  * `BorderBoundary` xsi:type → TrustBoundary emission
  * `KeyValueOfguidanyType` with missing key / value / empty key text
  * Properties block in Model namespace fallback (not Abstract)

Why this matters: TM7 is the de-facto threat-modelling format inside
regulated enterprises (banks, defense, healthcare) on Microsoft's
tooling. ATMS imports from .tm7 as a migration path. Every uncovered
defensive branch is a parser bug that would either crash on real user
.tm7 files or silently produce a wrong threat model.

Phase L is pure test additions — no production code change.
"""

from __future__ import annotations

# v0.18.71 Hibernation Phase 4 — entire file tests a
# hibernated parser. Skipped by default; run with:
#     pytest -m hibernated tests/test_phase_l_tm7_hardening.py
import pytest as _pytest_for_marker  # noqa: E402

pytestmark = _pytest_for_marker.mark.hibernated


import pytest

from atms.ingest.tm7 import _refine_type, _sanitise_id, tm7_to_system

# ===========================================================================
# _refine_type — keyword-based component-type refinement
# ===========================================================================


def test_refine_type_user_returns_user_regardless_of_name():
    """`user` default stays `user` even if the display name contains a
    process keyword (line 111)."""
    assert _refine_type("user", "Customer (acts like an API Gateway)") == "user"
    assert _refine_type("user", "") == "user"


def test_refine_type_web_application_firewall_keyword():
    """`firewall` in display name on process default → firewall."""
    assert _refine_type("web_application", "Edge Firewall") == "firewall"


def test_refine_type_web_application_load_balancer_keyword():
    """load-balancer family keywords → load_balancer (lines 119-120)."""
    assert _refine_type("web_application", "External Load Balancer") == "load_balancer"
    # `lb ` prefix variant
    assert _refine_type("web_application", "lb tier") == "load_balancer"
    # ` lb` suffix variant
    assert _refine_type("web_application", "front lb") == "load_balancer"


def test_refine_type_web_application_container_keyword():
    """container/pod/deployment → container_runtime (lines 123-124)."""
    assert _refine_type("web_application", "API Container") == "container_runtime"
    assert _refine_type("web_application", "Login Pod") == "container_runtime"
    assert _refine_type("web_application", "checkout Deployment") == "container_runtime"


def test_refine_type_web_application_agent_keyword():
    """agent → agent (line 125-126)."""
    assert _refine_type("web_application", "Threat Intelligence Agent") == "agent"


def test_refine_type_web_application_llm_keywords():
    """llm/gpt/claude/bedrock/openai/anthropic/model → llm_inference (lines 127-129)."""
    assert _refine_type("web_application", "GPT Inference Endpoint") == "llm_inference"
    assert _refine_type("web_application", "Claude Service") == "llm_inference"
    assert _refine_type("web_application", "Bedrock Runtime") == "llm_inference"
    assert _refine_type("web_application", "OpenAI Proxy") == "llm_inference"
    assert _refine_type("web_application", "Anthropic API") == "llm_inference"
    assert _refine_type("web_application", "Recommendation Model") == "llm_inference"


def test_refine_type_web_application_generic_fallback():
    """Process with no keyword → web_application (line 130)."""
    assert _refine_type("web_application", "Some Service") == "web_application"
    assert _refine_type("web_application", "") == "web_application"


def test_refine_type_database_message_queue_variants():
    """queue/sqs/service bus → message_queue (line 134-135)."""
    assert _refine_type("database", "SQS Order Queue") == "message_queue"
    assert _refine_type("database", "Azure Service Bus") == "message_queue"


def test_refine_type_database_stream_processor_variants():
    """topic/kafka/event hub/kinesis/pubsub → stream_processor (line 136-137)."""
    assert _refine_type("database", "Kafka Cluster") == "stream_processor"
    assert _refine_type("database", "Event Hub Stream") == "stream_processor"
    assert _refine_type("database", "Kinesis Stream") == "stream_processor"
    assert _refine_type("database", "PubSub Topic") == "stream_processor"


def test_refine_type_database_kms_keyword():
    """kms/cmk/hsm/key management → kms_key (lines 140-141)."""
    assert _refine_type("database", "AWS KMS CMK") == "kms_key"
    assert _refine_type("database", "Hardware Security Module HSM") == "kms_key"
    assert _refine_type("database", "Key Management Service") == "kms_key"


def test_refine_type_database_cache_keyword():
    """redis/memcached/elasticache → cache_store (lines 142-143)."""
    assert _refine_type("database", "Redis Cache") == "cache_store"
    assert _refine_type("database", "Memcached Cluster") == "cache_store"
    assert _refine_type("database", "AWS ElastiCache") == "cache_store"


def test_refine_type_database_nosql_keyword():
    """dynamodb/cosmos/mongo/nosql → nosql_database (lines 144-145)."""
    assert _refine_type("database", "DynamoDB Table") == "nosql_database"
    assert _refine_type("database", "CosmosDB Container") == "nosql_database"
    assert _refine_type("database", "MongoDB Atlas") == "nosql_database"


def test_refine_type_database_config_keyword():
    """config/configuration → data_source (lines 146-147)."""
    assert _refine_type("database", "Config Store") == "data_source"
    assert _refine_type("database", "Application Configuration") == "data_source"


def test_refine_type_database_generic_fallback():
    """Data store with no keyword → database (line 148)."""
    assert _refine_type("database", "Orders Table") == "database"
    assert _refine_type("database", "") == "database"


def test_refine_type_unknown_default_passes_through():
    """Default value not in the known set is returned as-is (line 149)."""
    assert _refine_type("totally_unknown", "anything") == "totally_unknown"


# ===========================================================================
# _sanitise_id — id normalisation
# ===========================================================================


def test_sanitise_id_special_chars_replaced():
    """Non-alphanumerics become underscores."""
    assert _sanitise_id("Foo Bar! @#$", fallback="x") == "foo_bar"


def test_sanitise_id_empty_uses_fallback():
    """Empty name falls back to the provided fallback (lowercased)."""
    assert _sanitise_id("", fallback="default-id") == "default-id"


def test_sanitise_id_max_64_chars():
    """Truncates at 64 characters."""
    long_name = "a" * 200
    out = _sanitise_id(long_name, fallback="x")
    assert len(out) == 64


# ===========================================================================
# tm7_to_system — error paths
# ===========================================================================


def test_tm7_no_path_no_text_raises():
    """At least one of path / text must be provided (line 187)."""
    with pytest.raises(ValueError) as exc:
        tm7_to_system()
    assert "path" in str(exc.value)
    assert "text" in str(exc.value)


def test_tm7_malformed_xml_raises():
    """Garbage input raises a clear `TM7 XML parse error` ValueError
    (lines 191-192)."""
    with pytest.raises(ValueError) as exc:
        tm7_to_system(text="<<<not xml>>>")
    assert "TM7 XML parse error" in str(exc.value)


def test_tm7_wrong_root_element_raises():
    """A well-formed XML doc that's not a TM7 file is rejected (lines
    197-201)."""
    # A SARIF-shaped XML stub.
    with pytest.raises(ValueError) as exc:
        tm7_to_system(text='<?xml version="1.0"?><sarif version="2.1.0"/>')
    assert "Not a Microsoft TM7 file" in str(exc.value)


def test_tm7_missing_drawing_surface_list_raises():
    """ThreatModel root with no DrawingSurfaceList child is rejected
    (lines 210-211)."""
    xml = (
        '<?xml version="1.0"?>\n'
        '<ThreatModel xmlns="http://schemas.datacontract.org/2004/07/'
        'ThreatModeling.Model">\n'
        '</ThreatModel>\n'
    )
    with pytest.raises(ValueError) as exc:
        tm7_to_system(text=xml)
    assert "DrawingSurfaceList" in str(exc.value)


def test_tm7_empty_drawing_surface_raises_no_elements():
    """DrawingSurfaceList present but with no recognisable elements →
    `no recognisable elements found` (lines 301-305)."""
    xml = (
        '<?xml version="1.0"?>\n'
        '<ThreatModel xmlns="http://schemas.datacontract.org/2004/07/'
        'ThreatModeling.Model">\n'
        '  <DrawingSurfaceList>\n'
        '  </DrawingSurfaceList>\n'
        '</ThreatModel>\n'
    )
    with pytest.raises(ValueError) as exc:
        tm7_to_system(text=xml)
    assert "no recognisable elements" in str(exc.value)


# ===========================================================================
# tm7_to_system — happy paths exercising remaining branches
# ===========================================================================


# Builder helper — keeps the XML literal manageable.
def _tm7_xml(borders_xml: str = "", lines_xml: str = "") -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<ThreatModel xmlns="http://schemas.datacontract.org/2004/07/'
        'ThreatModeling.Model"'
        ' xmlns:abs="http://schemas.datacontract.org/2004/07/'
        'ThreatModeling.Model.Abstracts"'
        ' xmlns:kb="http://schemas.datacontract.org/2004/07/'
        'ThreatModeling.KnowledgeBase"'
        ' xmlns:arr="http://schemas.microsoft.com/2003/10/'
        'Serialization/Arrays"'
        ' xmlns:i="http://www.w3.org/2001/XMLSchema-instance">\n'
        '  <DrawingSurfaceList>\n'
        '    <DrawingSurfaceModel>\n'
        f'      <abs:Borders>\n{borders_xml}      </abs:Borders>\n'
        f'      <abs:Lines>\n{lines_xml}      </abs:Lines>\n'
        '    </DrawingSurfaceModel>\n'
        '  </DrawingSurfaceList>\n'
        '</ThreatModel>\n'
    )


def _border_kvp(guid: str, xsi_type: str, display: str = "") -> str:
    """Render one Borders KeyValueOfguidanyType element."""
    props = (
        f'<abs:Properties><arr:anyType i:type="kb:HeaderDisplayAttribute">'
        f'<kb:DisplayName>{display}</kb:DisplayName></arr:anyType>'
        f'</abs:Properties>'
    ) if display else ""
    return (
        f'        <arr:KeyValueOfguidanyType>\n'
        f'          <arr:Key>{guid}</arr:Key>\n'
        f'          <arr:Value i:type="{xsi_type}">{props}</arr:Value>\n'
        f'        </arr:KeyValueOfguidanyType>\n'
    )


def _line_kvp(src: str, tgt: str, xsi_type: str = "Connector", label: str = "") -> str:
    """Render one Lines KeyValueOfguidanyType element."""
    props = (
        f'<abs:Properties><arr:anyType i:type="kb:HeaderDisplayAttribute">'
        f'<kb:DisplayName>{label}</kb:DisplayName></arr:anyType>'
        f'</abs:Properties>'
    ) if label else ""
    src_elem = f'<SourceGuid>{src}</SourceGuid>' if src is not None else ""
    tgt_elem = f'<TargetGuid>{tgt}</TargetGuid>' if tgt is not None else ""
    return (
        f'        <arr:KeyValueOfguidanyType>\n'
        f'          <arr:Value i:type="{xsi_type}">{src_elem}{tgt_elem}{props}'
        f'</arr:Value>\n'
        f'        </arr:KeyValueOfguidanyType>\n'
    )


def test_tm7_border_boundary_becomes_trust_boundary():
    """`BorderBoundary` xsi:type → TrustBoundary (lines 232-239)."""
    borders = (
        _border_kvp("g-bd-001", "BorderBoundary", display="DMZ")
        + _border_kvp("g-user", "StencilRectangle", display="User")
    )
    lines = _line_kvp("g-user", "g-user")
    sys = tm7_to_system(text=_tm7_xml(borders, lines))
    assert len(sys.trust_boundaries) == 1
    assert sys.trust_boundaries[0].description == "DMZ"


def test_tm7_unknown_stencil_silently_skipped():
    """Element whose xsi:type isn't a known stencil and isn't a boundary
    is silently skipped (line 248)."""
    borders = (
        _border_kvp("g-weird", "StencilOctopus", display="Weird Shape")
        + _border_kvp("g-user", "StencilRectangle", display="User")
    )
    lines = _line_kvp("g-user", "g-user")
    sys = tm7_to_system(text=_tm7_xml(borders, lines))
    # Only the rectangle survives.
    assert len(sys.components) == 1
    assert sys.components[0].id == "user"


def test_tm7_duplicate_display_name_gets_unique_id():
    """Two elements with the same display name → id is suffixed (lines
    255-257)."""
    borders = (
        _border_kvp("g1", "StencilRectangle", display="User")
        + _border_kvp("g2", "StencilRectangle", display="User")
        + _border_kvp("g3", "StencilRectangle", display="User")
    )
    lines = _line_kvp("g1", "g2")
    sys = tm7_to_system(text=_tm7_xml(borders, lines))
    ids = [c.id for c in sys.components]
    # All three components present, all distinct ids.
    assert len(ids) == 3
    assert len(set(ids)) == 3
    assert "user" in ids
    assert "user_2" in ids
    assert "user_3" in ids


def test_tm7_connector_missing_value_skipped():
    """Lines entry whose Value element is missing → skipped (line 278)."""
    borders = (
        _border_kvp("g-u1", "StencilRectangle", display="UA")
        + _border_kvp("g-u2", "StencilRectangle", display="UB")
    )
    # Hand-crafted line with no <Value> child.
    lines = (
        '        <arr:KeyValueOfguidanyType>\n'
        '          <arr:Key>line-missing-value</arr:Key>\n'
        '        </arr:KeyValueOfguidanyType>\n'
    )
    sys = tm7_to_system(text=_tm7_xml(borders, lines))
    assert len(sys.dataflows) == 0


def test_tm7_connector_non_connector_type_skipped():
    """Lines entry whose xsi:type is neither Connector nor Line is
    skipped (line 281)."""
    borders = (
        _border_kvp("g-u1", "StencilRectangle", display="UA")
        + _border_kvp("g-u2", "StencilRectangle", display="UB")
    )
    lines = _line_kvp("g-u1", "g-u2", xsi_type="Annotation")
    sys = tm7_to_system(text=_tm7_xml(borders, lines))
    assert len(sys.dataflows) == 0


def test_tm7_connector_missing_source_skipped():
    """Connector with no SourceGuid → skipped (line 286)."""
    borders = (
        _border_kvp("g-u1", "StencilRectangle", display="UA")
        + _border_kvp("g-u2", "StencilRectangle", display="UB")
    )
    # Pass `None` for src so the SourceGuid element is omitted.
    lines = _line_kvp(None, "g-u2")  # type: ignore[arg-type]
    sys = tm7_to_system(text=_tm7_xml(borders, lines))
    assert len(sys.dataflows) == 0


def test_tm7_connector_unknown_guid_skipped():
    """Connector pointing to a guid not in component_ids → skipped (line 290)."""
    borders = _border_kvp("g-u1", "StencilRectangle", display="UA")
    # Target points to a guid no element exists for.
    lines = _line_kvp("g-u1", "g-ghost")
    sys = tm7_to_system(text=_tm7_xml(borders, lines))
    assert len(sys.components) == 1
    assert len(sys.dataflows) == 0


def test_tm7_line_xsi_type_variant_accepted():
    """xsi:type containing "Line" (e.g. "TrustLine") is also accepted as
    a dataflow source (line 280 alternative branch)."""
    borders = (
        _border_kvp("g-u1", "StencilRectangle", display="UA")
        + _border_kvp("g-u2", "StencilRectangle", display="UB")
    )
    lines = _line_kvp("g-u1", "g-u2", xsi_type="TrustLine", label="trust crossing")
    sys = tm7_to_system(text=_tm7_xml(borders, lines))
    assert len(sys.dataflows) == 1
    assert sys.dataflows[0].label == "trust crossing"


def test_tm7_kvp_with_empty_key_skipped():
    """KeyValueOfguidanyType with no Key text → skipped (line 222-223)."""
    # Empty Key element + a real element to ensure no crash.
    bad_kvp = (
        '        <arr:KeyValueOfguidanyType>\n'
        '          <arr:Key></arr:Key>\n'
        '          <arr:Value i:type="StencilRectangle"/>\n'
        '        </arr:KeyValueOfguidanyType>\n'
    )
    good = _border_kvp("g-u1", "StencilRectangle", display="UA")
    sys = tm7_to_system(text=_tm7_xml(bad_kvp + good))
    # Only the good one survives.
    assert len(sys.components) == 1
    assert sys.components[0].id == "ua"


def test_tm7_text_input_uses_default_system_name():
    """When called with `text=`, the System.name falls back to
    `tm7-import` (line 185)."""
    borders = _border_kvp("g1", "StencilRectangle", display="User")
    sys = tm7_to_system(text=_tm7_xml(borders))
    assert sys.name == "tm7-import"


def test_tm7_system_name_override(tmp_path):
    """Explicit `system_name=` argument overrides the auto-detected name."""
    borders = _border_kvp("g1", "StencilRectangle", display="User")
    sys = tm7_to_system(text=_tm7_xml(borders), system_name="My TM7 Model")
    assert sys.name == "My TM7 Model"


def test_tm7_properties_block_model_namespace_fallback():
    """When `<Properties>` is in the Model namespace (not Abstract), the
    fallback at line 229 picks it up.

    The default builder emits `abs:Properties`. To test the fallback,
    write the Properties element under the Model NS instead.
    """
    xml = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<ThreatModel xmlns="http://schemas.datacontract.org/2004/07/'
        'ThreatModeling.Model"'
        ' xmlns:abs="http://schemas.datacontract.org/2004/07/'
        'ThreatModeling.Model.Abstracts"'
        ' xmlns:kb="http://schemas.datacontract.org/2004/07/'
        'ThreatModeling.KnowledgeBase"'
        ' xmlns:arr="http://schemas.microsoft.com/2003/10/'
        'Serialization/Arrays"'
        ' xmlns:i="http://www.w3.org/2001/XMLSchema-instance">\n'
        '  <DrawingSurfaceList>\n'
        '    <DrawingSurfaceModel>\n'
        '      <abs:Borders>\n'
        '        <arr:KeyValueOfguidanyType>\n'
        '          <arr:Key>g-mns</arr:Key>\n'
        '          <arr:Value i:type="StencilRectangle">\n'
        # `<Properties>` directly in Model NS (no `abs:` prefix on Properties).
        '            <Properties><arr:anyType i:type="kb:HeaderDisplayAttribute">'
        '<kb:DisplayName>ModelNS Element</kb:DisplayName></arr:anyType>'
        '</Properties>\n'
        '          </arr:Value>\n'
        '        </arr:KeyValueOfguidanyType>\n'
        '      </abs:Borders>\n'
        '    </DrawingSurfaceModel>\n'
        '  </DrawingSurfaceList>\n'
        '</ThreatModel>\n'
    )
    sys = tm7_to_system(text=xml)
    assert len(sys.components) == 1
    # The display name from the Model-NS Properties block was picked up.
    assert sys.components[0].name == "ModelNS Element"


def test_tm7_path_input_reads_default_name(tmp_path):
    """When called with path=, default system name is the file stem."""
    borders = _border_kvp("g1", "StencilRectangle", display="User")
    p = tmp_path / "my_model.tm7"
    p.write_text(_tm7_xml(borders), encoding="utf-8")
    sys = tm7_to_system(path=p)
    assert sys.name == "my_model"
