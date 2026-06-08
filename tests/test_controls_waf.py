"""WAF control-crediting regression (audit F060).

A network WAF was credited with mitigating ANY threat whose text cited OWASP
(the 'owasp' substring keyword) and on ANY component type -- so it understated
LLM prompt-injection (which an HTTP WAF cannot inspect). The WAF control now
only matches web-attack keywords and only on web-tier components.
"""

from __future__ import annotations

from atms.engines.controls import apply_component_controls
from atms.models import Component, Threat


def _t(title, desc, comp_type, controls):
    t = Threat(id="c.t", component_id="c", title=title, description=desc,
               likelihood=4, impact=4, severity="high")
    c = Component(id="c", name="x", type=comp_type, controls=controls)
    apply_component_controls([t], [c])
    return t


def test_waf_does_not_credit_llm_prompt_injection():
    t = _t("Prompt injection (OWASP LLM01:2025)",
           "attacker injects text to override the system prompt",
           "llm_inference", ["waf"])
    assert t.likelihood == 4, "a network WAF must not mitigate LLM prompt injection"
    assert not any(r == "control:waf" for r in t.references)


def test_waf_still_credits_web_tier_xss():
    t = _t("Stored XSS", "persistent xss in the web app form",
           "web_application", ["waf"])
    assert t.likelihood == 3, "WAF should still credit a web-tier XSS threat"


def test_waf_owasp_mention_alone_does_not_trigger():
    """A threat that merely cites OWASP (no web-attack keyword) on a web app
    must NOT be credited -- the 'owasp' substring keyword is gone."""
    t = _t("Business logic abuse (see OWASP A04)",
           "attacker abuses a business workflow; cites owasp guidance",
           "web_application", ["waf"])
    assert t.likelihood == 4
