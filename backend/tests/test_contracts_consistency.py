"""Cross-module invariants.

Several modules deliberately avoid importing app.models.enums, because that
pulls in the whole SQLAlchemy layer and the scanner and context engine are meant
to run without a database. The cost of that choice is duplicated string
constants, so these tests fail the moment a copy drifts from the enum.
"""

import app.context.pii_flow as pii_flow
from app.models.enums import EdgeType, RuleStatus, ScanStatus, Sensitivity
from app.pii import taxonomy
from app.rules import engine
from app.scorecard import scorer


class TestEdgeTypeMirrors:
    def test_pii_flow_edge_constants_match_the_enum(self):
        assert pii_flow.EDGE_DB_WRITE == EdgeType.DB_WRITE.value
        assert pii_flow.EDGE_API_SEND == EdgeType.API_SEND.value
        assert pii_flow.EDGE_LOG_OUTPUT == EdgeType.LOG_OUTPUT.value

    def test_terminal_sinks_are_all_real_edge_types(self):
        valid = {e.value for e in EdgeType}
        assert pii_flow.TERMINAL_SINK_TYPES <= valid

    def test_every_terminal_sink_has_a_verb_for_rendering(self):
        assert set(pii_flow.SINK_VERBS) == set(pii_flow.TERMINAL_SINK_TYPES)


class TestSensitivityMirrors:
    def test_taxonomy_tiers_match_the_enum(self):
        assert taxonomy.CRITICAL == Sensitivity.CRITICAL.value
        assert taxonomy.HIGH == Sensitivity.HIGH.value
        assert taxonomy.MEDIUM == Sensitivity.MEDIUM.value
        assert taxonomy.LOW == Sensitivity.LOW.value

    def test_every_category_declares_a_valid_tier(self):
        valid = {s.value for s in Sensitivity}
        for category, entry in taxonomy.PII_TAXONOMY.items():
            assert entry["sensitivity"] in valid, category


class TestRuleWeights:
    def test_engine_and_scorer_agree_on_weights(self):
        """Two copies exist because the scorer must not import the rules engine.

        If they disagree, the grade shown to the user stops matching the weights
        the rules engine reports per rule.
        """
        assert engine.RULE_WEIGHTS == scorer.RULE_WEIGHTS

    def test_weights_sum_to_one(self):
        assert abs(sum(scorer.RULE_WEIGHTS.values()) - 1.0) < 1e-9

    def test_every_registered_checker_has_a_weight(self):
        for checker in engine.RULE_CHECKERS:
            rule_id = getattr(checker, "RULE_ID", None)
            assert rule_id, f"{checker} does not declare RULE_ID"
            assert rule_id in scorer.RULE_WEIGHTS, rule_id

    def test_every_weighted_rule_has_a_checker(self):
        registered = {getattr(c, "RULE_ID", None) for c in engine.RULE_CHECKERS}
        assert set(scorer.RULE_WEIGHTS) == registered


class TestCheckerInterface:
    def test_every_checker_exposes_the_fields_the_pipeline_reads(self):
        for checker in engine.RULE_CHECKERS:
            assert hasattr(checker, "RULE_ID")
            assert hasattr(checker, "RULE_NAME")
            assert hasattr(checker, "check")
            # The pipeline pins RAG retrieval per rule using this list, so a
            # missing one would let a finding cite an unrelated provision.
            assert hasattr(checker, "RETRIEVAL_SECTION_IDS")

    def test_retrieval_ids_use_the_corpus_format(self):
        import re

        pattern = re.compile(r"^(s\.\d+(\(\d+\))?(\([a-z]\))?|rule_\d+)$")
        for checker in engine.RULE_CHECKERS:
            for section_id in checker.RETRIEVAL_SECTION_IDS:
                assert pattern.match(section_id), (
                    f"{checker.RULE_ID} declares '{section_id}', which "
                    "guardrail.normalise_section_ids would never produce"
                )

    def test_every_retrieval_id_exists_in_the_corpus(self):
        """A dangling id retrieves nothing and the finding loses its citation.

        This catches two mistakes that look identical in review. Pinning to a
        parent section like "s.8" when the corpus stores subsections, and using
        the draft Rules numbering: SDF duties moved from draft rule 11 to
        notified rule 13, and data principal rights from draft 12 to notified
        14, so the draft numbers now point at disability consent and child-data
        exemptions instead.
        """
        from app.corpus import dpdp_act, dpdp_rules

        corpus = {s.section_id for s in dpdp_act.ACT_SECTIONS}
        corpus |= {r.section_id for r in dpdp_rules.RULES}

        dangling = {
            checker.RULE_ID: [
                i for i in checker.RETRIEVAL_SECTION_IDS if i not in corpus
            ]
            for checker in engine.RULE_CHECKERS
        }
        dangling = {k: v for k, v in dangling.items() if v}
        assert not dangling, f"retrieval ids absent from the corpus: {dangling}"

    def test_every_checker_pins_retrieval(self):
        """Unpinned retrieval lets a finding cite any provision in the corpus."""
        unpinned = [
            c.RULE_ID for c in engine.RULE_CHECKERS if not c.RETRIEVAL_SECTION_IDS
        ]
        assert not unpinned, f"rules with no pinned provisions: {unpinned}"


class TestStatusValues:
    def test_status_from_score_returns_real_enum_values(self):
        valid = {s.value for s in RuleStatus}
        assert engine.status_from_score(1.0) in valid
        assert engine.status_from_score(0.5) in valid
        assert engine.status_from_score(0.0) in valid

    def test_scan_status_values_used_by_the_api_exist(self):
        for name in ("PENDING", "SCANNING", "ANALYZING", "COMPLETE", "FAILED"):
            assert hasattr(ScanStatus, name)
