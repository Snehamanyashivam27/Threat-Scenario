from __future__ import annotations

from rag.scenario.evidence import ApplicabilityCheck, CandidateEvidence, StepEvidence, TruthValue
from rag.scenario.models import (
    AttackStep,
    ComponentModel,
    ScenarioBundle,
    ScenarioModel,
    StepEnrichment,
)
from rag.scenario.narrative_composer import (
    UNCONFIRMED_MECHANISM_TEXT,
    ScenarioNarrativeComposer,
)
from rag.scenario.technical_context import project_technical_context


def _step(**overrides) -> AttackStep:
    values = {
        "sequence": 5,
        "step_id": "compromise",
        "name": "Compromise of the Control Component",
        "source_component_id": "source",
        "target_component_id": "target",
        "description": "The attacker attempts to compromise the Target Controller.",
    }
    values.update(overrides)
    return AttackStep(**values)


def _component() -> ComponentModel:
    return ComponentModel(id="target", name="Target Controller", type="controller")


def _candidate(
    cve_id: str,
    *,
    product: TruthValue = TruthValue.TRUE,
    version: TruthValue = TruthValue.UNKNOWN,
    effect: TruthValue = TruthValue.UNKNOWN,
    service: ApplicabilityCheck | None = None,
    authentication: ApplicabilityCheck | None = None,
    privileges: ApplicabilityCheck | None = None,
    cwes: list[str] | None = None,
    description: str = "",
    vulnerability_phrase: str = "an applicable vulnerability",
    effect_observed: str = "",
) -> CandidateEvidence:
    checks = [
        ApplicabilityCheck("product", product),
        ApplicabilityCheck("version", version),
        ApplicabilityCheck(
            "technical_effect",
            effect,
            required="device_compromise",
            observed=effect_observed,
        ),
    ]
    if service is not None:
        checks.append(service)
    if authentication is not None:
        checks.append(authentication)
    if privileges is not None:
        checks.append(privileges)
    return CandidateEvidence(
        cve_id=cve_id,
        advisory_id=None,
        disposition="conditional" if effect != TruthValue.FALSE else "rejected",
        checks=checks,
        cwes=list(cwes or []),
        description=description,
        vulnerability_phrase=vulnerability_phrase,
    )


def _web_service(status: TruthValue) -> ApplicabilityCheck:
    return ApplicabilityCheck(
        "service",
        status,
        required="the device's web interface is reachable",
        provenance="description:web interface",
    )


def _ssh_service(status: TruthValue) -> ApplicabilityCheck:
    return ApplicabilityCheck(
        "service",
        status,
        required="the required ssh service is available and reachable",
        provenance="description:ssh service",
    )


def _project(candidates: list[CandidateEvidence], step: AttackStep | None = None):
    return project_technical_context(step or _step(), _component(), candidates)


def test_confirmed_service_with_unknown_effect():
    facts = _project(
        [
            _candidate(
                "CVE-2030-1",
                effect=TruthValue.UNKNOWN,
                service=_web_service(TruthValue.TRUE),
                cwes=["CWE-78"],
                description="UNIQUE_LEAK_TOKEN command injection in firmware blob",
            )
        ]
    )

    assert len(facts) == 1
    assert facts[0].category == "affected_functionality"
    assert facts[0].polarity == "confirmed"
    assert facts[0].statement == "through a reachable web management function"
    assert "CVE-" not in facts[0].statement
    assert "UNIQUE_LEAK_TOKEN" not in facts[0].statement


def test_effect_mismatch_isolation():
    facts = _project(
        [
            _candidate(
                "CVE-2030-2",
                effect=TruthValue.FALSE,
                service=_web_service(TruthValue.TRUE),
                cwes=["CWE-78"],
                vulnerability_phrase="a command-injection vulnerability in the device's web interface",
                description="UNIQUE_LEAK_TOKEN",
                effect_observed="denial_of_service",
            )
        ]
    )

    assert facts == []


def test_cwe_only_exclusion():
    facts = _project(
        [
            _candidate(
                "CVE-2030-3",
                effect=TruthValue.UNKNOWN,
                cwes=["CWE-787"],
            )
        ]
    )

    assert facts == []


def test_conditional_unknown_wording():
    facts = _project(
        [
            _candidate(
                "CVE-2030-4",
                effect=TruthValue.UNKNOWN,
                service=_web_service(TruthValue.UNKNOWN),
            )
        ]
    )

    assert len(facts) == 1
    assert facts[0].polarity == "conditional"
    assert facts[0].evidence_state == "unknown"
    assert facts[0].statement == "This would require that a web management function is reachable."
    assert not facts[0].statement.lower().startswith("through ")


def test_merge_agreement():
    facts = _project(
        [
            _candidate("CVE-2030-5", service=_web_service(TruthValue.TRUE)),
            _candidate("CVE-2030-6", service=_web_service(TruthValue.TRUE)),
        ]
    )

    assert len(facts) == 1
    assert facts[0].statement == "through a reachable web management function"


def test_merge_conflict():
    facts = _project(
        [
            _candidate("CVE-2030-7", service=_web_service(TruthValue.TRUE)),
            _candidate("CVE-2030-8", service=_ssh_service(TruthValue.TRUE)),
        ]
    )

    assert facts == []


def test_cap_at_two_facts():
    facts = _project(
        [
            _candidate(
                "CVE-2030-9",
                effect=TruthValue.TRUE,
                service=_web_service(TruthValue.TRUE),
                privileges=ApplicabilityCheck(
                    "privileges",
                    TruthValue.TRUE,
                    required="the attacker has authenticated access to the device's web interface",
                ),
                cwes=["CWE-78"],
                effect_observed="command_injection",
            )
        ]
    )

    assert len(facts) == 2
    assert [fact.category for fact in facts] == ["affected_functionality", "access_category"]


def test_false_access_does_not_contribute():
    facts = _project(
        [
            _candidate(
                "CVE-2030-10",
                privileges=ApplicabilityCheck(
                    "privileges",
                    TruthValue.FALSE,
                    required="the attacker has authenticated access to the affected service",
                ),
                service=_web_service(TruthValue.TRUE),
            )
        ]
    )

    assert facts == []


def test_constrained_shaped_candidates_yield_empty_context():
    facts = _project(
        [
            _candidate("CVE-2030-11", effect=TruthValue.UNKNOWN, cwes=["CWE-602"]),
            _candidate(
                "CVE-2030-12",
                effect=TruthValue.FALSE,
                cwes=["CWE-770"],
                vulnerability_phrase="the affected application contains denial-of-service (DoS) vulnerability",
                effect_observed="denial_of_service",
            ),
        ]
    )

    assert facts == []


def _bundle(step: AttackStep) -> ScenarioBundle:
    return ScenarioBundle(
        scenario=ScenarioModel(
            scenario_id="SYNTHETIC-CONTEXT",
            title="Synthetic technical context",
            attack_path=[step],
        ),
        components_by_id={"target": _component()},
    )


def _enrichment(step: AttackStep, *, narrator_evidence: list[dict], candidates: list[CandidateEvidence] | None = None):
    return StepEnrichment(
        step=step,
        primary_query="q",
        primary_answer="UNIQUE_LEAK_TOKEN from retrieval",
        evidence=StepEvidence(
            step_id=step.step_id,
            sequence=step.sequence,
            candidates=list(candidates or []),
            selected_cve=None,
            narrator_evidence=narrator_evidence,
        ),
    )


def test_composer_uses_confirmed_context_and_keeps_abstention():
    step = _step()
    enrichment = _enrichment(
        step,
        narrator_evidence=[
            {
                "cve_id": None,
                "technical_context": [
                    {
                        "category": "affected_functionality",
                        "polarity": "confirmed",
                        "statement": "through a reachable web management function",
                        "evidence_state": "known_true",
                    }
                ],
            }
        ],
        candidates=[
            _candidate(
                "CVE-2030-99",
                description="UNIQUE_LEAK_TOKEN",
                vulnerability_phrase="a command-injection vulnerability in UNIQUE_LEAK_TOKEN",
            )
        ],
    )

    narrative = ScenarioNarrativeComposer().compose(_bundle(step), [enrichment])

    assert "through a reachable web management function" in narrative
    assert UNCONFIRMED_MECHANISM_TEXT in narrative
    assert "CVE-2030-99" not in narrative
    assert "UNIQUE_LEAK_TOKEN" not in narrative
    assert "command-injection" not in narrative


def test_composer_conditional_wording():
    step = _step()
    enrichment = _enrichment(
        step,
        narrator_evidence=[
            {
                "cve_id": None,
                "technical_context": [
                    {
                        "category": "affected_functionality",
                        "polarity": "conditional",
                        "statement": "This would require that a web management function is reachable.",
                        "evidence_state": "unknown",
                    }
                ],
            }
        ],
    )

    narrative = ScenarioNarrativeComposer().compose(_bundle(step), [enrichment])

    assert "This would require that a web management function is reachable." in narrative
    assert "through a reachable web management function" not in narrative
    assert UNCONFIRMED_MECHANISM_TEXT in narrative


def test_composer_isolation_from_candidates():
    step = _step()
    enrichment = _enrichment(
        step,
        narrator_evidence=[{"cve_id": None, "technical_context": []}],
        candidates=[
            _candidate(
                "CVE-2030-77",
                service=_web_service(TruthValue.TRUE),
                description="UNIQUE_LEAK_TOKEN",
                vulnerability_phrase="a command-injection vulnerability in the device's web interface",
            )
        ],
    )

    narrative = ScenarioNarrativeComposer().compose(_bundle(step), [enrichment])

    assert "web management function" not in narrative
    assert "UNIQUE_LEAK_TOKEN" not in narrative
    assert "CVE-2030-77" not in narrative
    assert UNCONFIRMED_MECHANISM_TEXT in narrative
    assert "The attacker then attempts to compromise the Target Controller." in narrative


def test_selected_cve_narration_unchanged():
    step = _step(description="The attacker exploits an applicable vulnerability to compromise the controller.")
    selected = _candidate(
        "CVE-2030-10001",
        effect=TruthValue.TRUE,
        effect_observed="command_injection",
        vulnerability_phrase="a command-injection vulnerability",
    )
    selected.disposition = "conditional"
    selected.unresolved_conditions = ["the deployed firmware version is earlier than V2.0"]
    enrichment = StepEnrichment(
        step=step,
        primary_query="q",
        primary_answer="UNIQUE_LEAK_TOKEN",
        evidence=StepEvidence(
            step_id=step.step_id,
            sequence=step.sequence,
            candidates=[selected],
            selected_cve="CVE-2030-10001",
            selected_cves=["CVE-2030-10001"],
            narrator_evidence=[
                {
                    "cve_id": "CVE-2030-10001",
                    "advisory_id": None,
                    "disposition": "conditional",
                    "final_status": "conditional_version_unknown",
                    "unresolved_conditions": ["the deployed firmware version is earlier than V2.0"],
                    "vulnerability_phrase": "a command-injection vulnerability",
                    "technical_context": [
                        {
                            "category": "affected_functionality",
                            "polarity": "confirmed",
                            "statement": "through a reachable web management function",
                            "evidence_state": "known_true",
                        }
                    ],
                }
            ],
        ),
    )

    narrative = ScenarioNarrativeComposer().compose(_bundle(step), [enrichment])

    assert "CVE-2030-10001" in narrative
    assert "through a reachable web management function" not in narrative
    assert UNCONFIRMED_MECHANISM_TEXT not in narrative
    assert "UNIQUE_LEAK_TOKEN" not in narrative


def test_no_retrieval_leak_in_projection():
    leak = "UNIQUE_LEAK_TOKEN raw retrieval sentence about SSH daemon root shell"
    facts = _project(
        [
            _candidate(
                "CVE-2030-13",
                effect=TruthValue.UNKNOWN,
                service=_web_service(TruthValue.TRUE),
                description=leak,
                vulnerability_phrase=leak,
            )
        ]
    )

    blob = " ".join(fact.statement for fact in facts)
    assert leak not in blob
    assert "root shell" not in blob
    assert "UNIQUE_LEAK_TOKEN" not in blob
