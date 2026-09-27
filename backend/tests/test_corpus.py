"""Corpus integrity tests.

These are not style checks. The corpus is the ground truth the AI layer cites
from, and the faithfulness guardrail verifies citations against it, so a
malformed section_id or a chunk that drifted from its source provision turns
into a fabricated citation shown to a compliance officer.
"""

import re

import pytest

from app.corpus.chunker import SOURCE_ACT, SOURCE_RULES, build_chunks
from app.corpus.dpdp_act import ACT_SECTIONS
from app.corpus.dpdp_act import by_id as act_by_id
from app.corpus.dpdp_rules import RULES
from app.corpus.dpdp_rules import by_id as rule_by_id

# The canonical forms guardrail.normalise_section_ids produces: "s.5", "s.8(5)",
# "s.2(t)", "rule_6". Anything else breaks citation grounding.
ACT_ID = re.compile(r"^s\.\d{1,2}(\(\d{1,2}\)|\([a-z]{1,3}\))?$")
RULE_ID = re.compile(r"^rule_\d{1,2}$")

# Provisions the rules engine cites by name. If one of these disappears, the
# checker that cites it silently loses its grounding.
REQUIRED_ACT_IDS = [
    "s.5",       # r03_notice
    "s.6",       # r04_consent
    "s.7",       # r04_consent
    "s.8(1)",    # r12_verification, accountability
    "s.8(5)",    # r06_security
    "s.8(6)",    # r07_breach
    "s.8(7)",    # retention
    "s.9",       # r05_children
    "s.10(2)",   # r08_dpia
    "s.11",      # r10_rights, access
    "s.12",      # r10_rights, correction and erasure
    "s.13",      # r10_rights, grievance, and r11_dpb
    "s.14",      # r10_rights, nomination
    "s.2(t)",    # definition of personal data
    "s.2(x)",    # definition of processing
    "s.2(i)",    # definition of Data Fiduciary
    "s.2(j)",    # definition of Data Principal
]


# --------------------------------------------------------------- identifiers


@pytest.mark.parametrize("section", ACT_SECTIONS, ids=lambda s: s.section_id)
def test_act_section_id_matches_canonical_format(section):
    assert ACT_ID.match(section.section_id), (
        f"{section.section_id!r} is not a form guardrail.normalise_section_ids "
        f"produces, so citation grounding would reject it"
    )


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.section_id)
def test_rule_section_id_matches_canonical_format(rule):
    assert RULE_ID.match(rule.section_id)
    assert rule.section_id == f"rule_{rule.number}"


def test_section_ids_are_unique():
    ids = [s.section_id for s in ACT_SECTIONS] + [r.section_id for r in RULES]
    duplicates = {i for i in ids if ids.count(i) > 1}
    assert not duplicates, f"duplicate section_id: {sorted(duplicates)}"


def test_required_provisions_are_present():
    available = {s.section_id for s in ACT_SECTIONS}
    missing = [i for i in REQUIRED_ACT_IDS if i not in available]
    assert not missing, f"rules engine cites these but the corpus lacks them: {missing}"


def test_rules_are_numbered_contiguously_from_one():
    assert [r.number for r in RULES] == list(range(1, len(RULES) + 1))


# -------------------------------------------------------------------- lookup


def test_act_by_id_round_trips():
    for section in ACT_SECTIONS:
        assert act_by_id(section.section_id) is section
    assert act_by_id("s.99") is None
    assert act_by_id("") is None


def test_rule_by_id_round_trips():
    for rule in RULES:
        assert rule_by_id(rule.section_id) is rule
    assert rule_by_id("rule_99") is None


def test_citation_labels_read_the_way_a_lawyer_writes_them():
    assert act_by_id("s.8(5)").citation_label == "DPDP Act 2023, Section 8(5)"
    assert act_by_id("s.5").citation_label == "DPDP Act 2023, Section 5"
    assert rule_by_id("rule_6").citation_label == "DPDP Rules 2025, Rule 6"


# ---------------------------------------------------------------------- text


@pytest.mark.parametrize("section", ACT_SECTIONS, ids=lambda s: s.section_id)
def test_act_text_is_present_and_clean(section):
    assert section.text.strip(), f"{section.section_id} has no text"
    assert section.title.strip()
    for artefact in ("GAZETTE", "[PART II", "SEC. 1]", "CHAPTER "):
        assert artefact not in section.text, (
            f"{section.section_id} carries gazette furniture: {artefact!r}"
        )


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.section_id)
def test_rule_text_is_present_and_clean(rule):
    assert rule.text.strip(), f"{rule.section_id} has no text"
    assert rule.title.strip()
    for artefact in ("GAZETTE", "[PART II", "SEC. 3(i)]"):
        assert artefact not in rule.text


# --------------------------------------------------------------- spot checks


def test_spot_check_section_8_5_is_the_security_safeguards_duty():
    text = act_by_id("s.8(5)").text
    for phrase in (
        "reasonable security safeguards",
        "prevent personal data breach",
        "in its possession or under its control",
    ):
        assert phrase in text, f"s.8(5) is missing {phrase!r}"


def test_spot_check_section_8_6_is_the_breach_intimation_duty():
    text = act_by_id("s.8(6)").text
    assert "personal data breach" in text
    assert "intimation" in text
    assert "the Board and each affected Data Principal" in text


def test_spot_check_section_6_1_consent_standard():
    text = act_by_id("s.6").text
    assert "free, specific, informed, unconditional and unambiguous" in text
    assert "clear affirmative action" in text


def test_spot_check_section_9_children():
    text = act_by_id("s.9").text
    assert "verifiable consent of the parent" in text
    assert "tracking or behavioural monitoring of children" in text
    assert "targeted advertising directed at children" in text


def test_spot_check_rule_6_security_safeguards_enumerates_controls():
    text = rule_by_id("rule_6").text
    for phrase in ("encryption", "obfuscation", "masking", "virtual tokens", "logs"):
        assert phrase in text, f"rule_6 is missing {phrase!r}"


def test_spot_check_rule_7_breach_reporting_window():
    text = rule_by_id("rule_7").text
    assert "seventy-two hours" in text
    assert "without delay" in text


def test_significant_data_fiduciary_duties_live_at_rule_13_not_rule_11():
    """The notified 2025 Rules renumbered this away from the draft's rule 11."""
    assert "Significant Data Fiduciary" in rule_by_id("rule_13").title
    assert "Data Protection Impact Assessment" in rule_by_id("rule_13").text
    assert "disability" in rule_by_id("rule_11").title


def test_data_principal_rights_live_at_rule_14_not_rule_12():
    assert "Rights of Data Principals" == rule_by_id("rule_14").title
    assert "Exemptions" in rule_by_id("rule_12").title


# -------------------------------------------------------------------- chunks


@pytest.fixture(scope="module")
def chunks():
    return build_chunks()


def test_chunks_exist(chunks):
    assert len(chunks) >= len(ACT_SECTIONS) + len(RULES)


def test_no_chunk_is_empty(chunks):
    empty = [(c.section_id, c.chunk_index) for c in chunks if not c.text.strip()]
    assert not empty, f"empty chunks: {empty}"


def test_every_chunk_carries_its_own_citation(chunks):
    for chunk in chunks:
        assert chunk.citation_label.strip()
        assert chunk.section_title.strip()
        assert chunk.source in {SOURCE_ACT, SOURCE_RULES}


def test_chunk_index_is_unique_per_section_id(chunks):
    seen: set[tuple[str, int]] = set()
    for chunk in chunks:
        key = (chunk.section_id, chunk.chunk_index)
        assert key not in seen, (
            f"duplicate {key}, which violates the unique constraint on "
            f"(section_id, chunk_index)"
        )
        seen.add(key)


def test_chunk_index_starts_at_zero_and_is_contiguous(chunks):
    by_section: dict[str, list[int]] = {}
    for chunk in chunks:
        by_section.setdefault(chunk.section_id, []).append(chunk.chunk_index)
    for section_id, indexes in by_section.items():
        assert sorted(indexes) == list(range(len(indexes))), (
            f"{section_id} has non-contiguous chunk_index {sorted(indexes)}"
        )


def test_chunk_index_is_stable_across_runs():
    first = [(c.section_id, c.chunk_index, c.text) for c in build_chunks()]
    second = [(c.section_id, c.chunk_index, c.text) for c in build_chunks()]
    assert first == second


def test_chunk_text_is_a_verbatim_slice_of_its_provision(chunks):
    """Chunking may split text. It may never alter it."""
    bodies = {s.section_id: s.text for s in ACT_SECTIONS}
    bodies.update({r.section_id: r.text for r in RULES})
    for chunk in chunks:
        assert chunk.text in bodies[chunk.section_id], (
            f"{chunk.section_id} chunk {chunk.chunk_index} is not a verbatim "
            f"slice of its provision"
        )


def test_chunks_reassemble_into_the_whole_provision(chunks):
    """No provision may lose text on the way into the corpus."""
    assembled: dict[str, list[str]] = {}
    for chunk in sorted(chunks, key=lambda c: (c.section_id, c.chunk_index)):
        assembled.setdefault(chunk.section_id, []).append(chunk.text)

    bodies = {s.section_id: s.text for s in ACT_SECTIONS}
    bodies.update({r.section_id: r.text for r in RULES})
    for section_id, parts in assembled.items():
        assert " ".join(parts) == bodies[section_id].strip(), (
            f"{section_id} does not round-trip through the chunker"
        )


def test_chunks_respect_the_size_budget(chunks):
    """Oversize is tolerated only where the provision is one long sentence."""
    max_chars = 1200
    for chunk in chunks:
        if len(chunk.text) <= max_chars:
            continue
        sentences = re.split(r"(?<=[.;])\s+(?=[A-Z(“])", chunk.text)
        assert len(sentences) == 1, (
            f"{chunk.section_id} chunk {chunk.chunk_index} is "
            f"{len(chunk.text)} chars and was splittable"
        )


def test_no_chunk_begins_mid_sentence(chunks):
    """A chunk starting inside a sentence retrieves badly and quotes worse."""
    for chunk in chunks:
        head = chunk.text.lstrip()
        assert head[0].isupper() or head[0] in "(“", (
            f"{chunk.section_id} chunk {chunk.chunk_index} begins mid-sentence: "
            f"{head[:60]!r}"
        )


def test_max_chars_is_honoured_when_tightened():
    """A smaller budget must produce more chunks, not silently ignore itself."""
    default = build_chunks()
    tighter = build_chunks(max_chars=400)
    assert len(tighter) > len(default)
    for chunk in tighter:
        assert chunk.text.strip()
