"""Faithfulness guardrail.

Three checks run on every AI-generated explanation before it is stored:

  1. Citation grounding, every section the model cited must exist in the corpus
     chunks that were actually retrieved for this finding. A model cannot cite a
     provision it was not shown.
  2. Quote verification, the quoted statutory text must really appear in the
     cited provision, matched with a normalised fuzzy ratio.
  3. Entailment, the claim must share substantive vocabulary with the provision
     it leans on, and must not invert the provision's obligation.

A finding that fails is kept but flagged. Hiding it would be worse: the user
would not know the tool was uncertain.
"""

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from app.config import settings
from app.contracts import GroundedExplanation, RetrievedProvision

_SECTION_PATTERN = re.compile(
    r"(?:section|sec\.?|s\.)\s*(\d+(?:\(\d+\))?(?:\([a-z]\))?)|(?:rule)\s*(\d+)",
    re.IGNORECASE,
)

_STOPWORDS = frozenset(
    """a an and or the of to in for on by with without shall may must not no any
    such this that these those is are be been being as at from its it their which
    who whom where when what how all each every other than then there here also
    if unless until while whereas provided under upon have has had will would
    """.split()
)

_NEGATION_TOKENS = frozenset({"not", "no", "never", "without", "nor", "cannot"})

# Negation bound to the duty rather than to the target's conduct. "The site does
# not encrypt" describes a failure to comply. "The Act does not require
# encryption" tells the reader the duty is absent, which is the dangerous
# inversion, so only the second shape is rejected.
_OBLIGATION_DENIAL = re.compile(
    r"\b(?:"
    r"(?:does|do|did|is|are|was|were|shall|will|would|need)\s+not\s+"
    r"(?:\w+\s+){0,2}?(?:require|mandate|oblige|obligate|prohibit|apply|impose)"
    r"|no\s+(?:such\s+)?(?:legal\s+|statutory\s+)?(?:obligation|requirement|duty)"
    r"|not\s+(?:legally\s+)?(?:required|mandated|obliged|obligated|applicable)"
    r"|exempt\s+from\s+(?:this|the|any)\s+(?:obligation|requirement|duty)"
    r")\b",
    re.IGNORECASE,
)


def _denies_the_obligation(text: str) -> bool:
    return bool(_OBLIGATION_DENIAL.search(text or ""))

_ENTAILMENT_MIN_OVERLAP = 0.12


@dataclass
class GuardrailReport:
    citation_grounded: bool
    quote_verified: bool
    entailment_ok: bool
    notes: list[str]

    @property
    def passed(self) -> bool:
        return self.citation_grounded and self.quote_verified and self.entailment_ok


def normalise_section_ids(text: str) -> set[str]:
    """Pull section and rule identifiers out of free text into canonical form.

    "Section 8(5)" and "s.8(5)" both become "s.8(5)". "Rule 6" becomes "rule_6".
    Must match the section_id format used in the dpdp_corpus table, or check 1
    rejects every valid citation.
    """
    found: set[str] = set()
    for section_match, rule_match in _SECTION_PATTERN.findall(text or ""):
        if section_match:
            found.add(f"s.{section_match.strip()}")
        if rule_match:
            found.add(f"rule_{rule_match.strip()}")
    return found


_SUBSECTION_SUFFIX = re.compile(r"\((?:\d+|[a-z])\)$")


def parent_section_id(section_id: str) -> str | None:
    """Drop one level of sub-section, so "s.12(1)" yields "s.12".

    Returns None when there is nothing left to drop.
    """
    stripped = _SUBSECTION_SUFFIX.sub("", section_id or "")
    return stripped if stripped and stripped != section_id else None


def _is_grounded(section_id: str, allowed: set[str]) -> bool:
    """Whether a cited id is covered by what the model was actually shown.

    An exact match is obviously fine. A sub-section of a retrieved section is
    too: shown s.12, a model citing s.12(1) has narrowed the reference, not
    invented one, and rejecting that would train the prompt toward vaguer
    citations. The reverse is not accepted. Shown s.8(5), a model citing s.8
    has widened to a section with eleven sub-sections, most of which it was
    never given, so the specific obligation it names cannot be checked.
    """
    if section_id in allowed:
        return True
    candidate: str | None = section_id
    while (candidate := parent_section_id(candidate)) is not None:
        if candidate in allowed:
            return True
    return False


def _covers(provision_id: str, claimed: set[str]) -> bool:
    """Whether a retrieved provision backs any of the claimed ids."""
    return any(
        claim == provision_id or _is_grounded(claim, {provision_id})
        for claim in claimed
    )


def _normalise_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "").lower().strip())


def _content_tokens(text: str) -> set[str]:
    words = re.findall(r"[a-z]{4,}", (text or "").lower())
    return {w for w in words if w not in _STOPWORDS}


def _best_quote_ratio(quote: str, provisions: list[RetrievedProvision]) -> float:
    """Highest similarity between the quote and any window of the provision texts."""
    target = _normalise_text(quote)
    if not target:
        return 0.0

    best = 0.0
    for provision in provisions:
        body = _normalise_text(provision.text)
        if not body:
            continue
        if target in body:
            return 1.0
        best = max(best, SequenceMatcher(None, target, body).ratio())

        # A short quote pulled from a long section scores badly against the whole
        # body, so also slide a window the size of the quote across the section.
        window = len(target)
        if window < len(body):
            step = max(window // 2, 1)
            for start in range(0, len(body) - window + 1, step):
                ratio = SequenceMatcher(None, target, body[start : start + window]).ratio()
                if ratio > best:
                    best = ratio
                    if best >= 0.99:
                        return best
    return best


def check(
    explanation: GroundedExplanation, provisions: list[RetrievedProvision]
) -> GuardrailReport:
    notes: list[str] = []
    allowed_ids = {p.section_id for p in provisions}

    # --- check 1: citation grounding -------------------------------------
    claimed_ids = normalise_section_ids(explanation.citation)
    claimed_ids.update(explanation.cited_section_ids or [])

    if not provisions:
        citation_grounded = False
        notes.append("No statutory provisions were retrieved, so no citation can be grounded.")
    elif not claimed_ids:
        citation_grounded = False
        notes.append("Explanation contains no parseable statutory citation.")
    else:
        ungrounded = {i for i in claimed_ids if not _is_grounded(i, allowed_ids)}
        citation_grounded = not ungrounded
        if ungrounded:
            notes.append(
                "Cited provisions not present in retrieved corpus: "
                + ", ".join(sorted(ungrounded))
            )

    # --- check 2: quote verification -------------------------------------
    if not (explanation.citation_text or "").strip():
        quote_verified = False
        notes.append("No statutory text was quoted.")
    else:
        ratio = _best_quote_ratio(explanation.citation_text, provisions)
        quote_verified = ratio >= settings.guardrail_quote_threshold
        if not quote_verified:
            notes.append(
                f"Quoted text does not match the cited provision "
                f"(best match {ratio:.2f}, threshold {settings.guardrail_quote_threshold})."
            )

    # --- check 3: entailment ---------------------------------------------
    claim_tokens = _content_tokens(explanation.description)
    relevant = [
        p for p in provisions if not claimed_ids or _covers(p.section_id, claimed_ids)
    ]
    provision_tokens: set[str] = set()
    for provision in relevant:
        provision_tokens |= _content_tokens(provision.text)

    if not claim_tokens or not provision_tokens:
        entailment_ok = False
        notes.append("Not enough substantive text to test entailment.")
    else:
        overlap = len(claim_tokens & provision_tokens) / len(claim_tokens)
        entailment_ok = overlap >= _ENTAILMENT_MIN_OVERLAP
        if not entailment_ok:
            notes.append(
                f"Claim shares little vocabulary with the cited provision "
                f"(overlap {overlap:.2f})."
            )

        # Catch a model telling the reader the law does not require something.
        #
        # This deliberately does NOT fire on ordinary absence findings. Nearly
        # every finding this tool produces says something is missing, so
        # counting negation words flagged correct output: "the notice names no
        # way to complain" and "CSP and X-Content-Type-Options are missing" were
        # both rejected against provisions they cited accurately. What matters
        # is not whether the claim contains a negation, but whether the negation
        # attaches to the obligation itself.
        if _denies_the_obligation(explanation.description):
            entailment_ok = False
            notes.append(
                "Claim states the cited provision imposes no obligation, which "
                "contradicts the retrieved text."
            )

    return GuardrailReport(
        citation_grounded=citation_grounded,
        quote_verified=quote_verified,
        entailment_ok=entailment_ok,
        notes=notes,
    )


def apply(
    explanation: GroundedExplanation, provisions: list[RetrievedProvision]
) -> GroundedExplanation:
    """Run the checks and stamp the result onto the explanation."""
    report = check(explanation, provisions)
    explanation.guardrail_passed = report.passed
    explanation.guardrail_notes = "; ".join(report.notes) if report.notes else None

    if not report.quote_verified:
        explanation.citation_text = ""
    if not report.citation_grounded:
        explanation.citation = "Requires manual verification, citation not grounded"
        explanation.cited_section_ids = []
    if not report.passed:
        explanation.confidence = min(explanation.confidence, 0.4)

    return explanation
