"""Reading a site's published policies against the statutory checklist.

Pure by construction: no network, no clock, no randomness. Everything it knows
comes from the PolicyDocument list it is handed, which is what lets it be tested
against fixture prose rather than against a live site, and what lets the same
documents be re-analysed later without refetching them.

Three commitments shape the whole module.

A marker never decides a check on its own. Every requirement carries phrases
that evidence it, but a phrase is only a place to start reading. The sentence it
sits in has to be read for whether it asserts the thing, denies it, or merely
mentions the words in passing, and a link row in a footer asserts nothing at
all. Deciding on presence alone is how "board of directors" becomes a route to
the Data Protection Board.

A denial is not always a gap. "We do not share your personal data with third
parties" is a complete answer to the sharing question and satisfies it, while
"we do not knowingly collect personal data from children" is a disclaimer and
not the children's procedure section 9 asks for. Which of the two a negative
sentence is depends on the requirement, so each one says.

A policy nobody could read says nothing about the organisation. If the notice
was unreachable or came back empty, its requirements are unassessed, which is
recorded as such rather than as fifteen failures the site did not earn. That
distinction is the difference between a finding and an artefact of a fetch.

Confidence and requires_human_validation follow the convention the earlier
ruleset settled on: evidence read out of structure is worth more than evidence
read out of prose, absence in a long document is worth more than absence in a
stub, and a requirement flagged needs_human_check is never reported as settled.
"""

import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.contracts import PolicyClaim, PolicyDocument, PolicyRequirementCheck
from app.policy.requirements import (
    CHILDREN,
    COOKIE,
    EXPECTED_POLICY_KINDS,
    GRIEVANCE,
    NOTICE,
    REQUIREMENTS,
    PolicyRequirement,
)
from app.scanner.trackers import DPO_KEYWORDS, escape_phrase
# Pure string work, despite living next to the SSRF guard. Reimplementing
# registrable domain parsing here is exactly the duplication this stage removed
# from the web scanner.
from app.scanner.url_guard import brand_label

# Kinds whose prose is read for claims. A retention promise in a cookie notice
# counts; a capitalised vendor name in a terms of service is noise.
CLAIM_DOCUMENT_KINDS: tuple[str, ...] = (NOTICE, COOKIE, GRIEVANCE, CHILDREN)

# An unassessed requirement is recorded as a check so it stays visible, but it is
# not a gap. The contract carries a single satisfied flag, so the distinction
# lives in this prefix and is read back through is_unassessed().
UNASSESSED_PREFIX = "not assessed: "

# --------------------------------------------------------------- shape of prose

# A sentence has to hold at least this much to be read as an assertion.
_MIN_EVIDENCE_WORDS = 5
# Past this a line is a heading or a label, not a sentence.
_MAX_STRUCTURAL_WORDS = 8
# Below this a readable document is a stub, and absence in it means less.
_SUBSTANTIAL_DOC_WORDS = 400

SHAPE_STRUCTURAL = "structural"
SHAPE_PROSE = "prose"
SHAPE_NAV = "nav"

_SENTENCE_CAP = 600

# Evidence from a negative statement, and whether that is enough.
DISCLOSURE = "disclosure"  # a denial still answers the question the Act asks
PROCEDURE = "procedure"  # the notice must describe something it does

# Only these are answered by a denial. Everything else defaults to PROCEDURE,
# because "we do not" is a disclaimer wherever the Act wants a mechanism.
_NEGATION_POLICY: dict[str, str] = {
    "notice.third_party_sharing": DISCLOSURE,
    "notice.cross_border": DISCLOSURE,
    "notice.consent_manager": DISCLOSURE,
}

_NEGATORS: tuple[str, ...] = (
    "do not", "does not", "did not", "don't", "doesn't",
    "will not", "won't", "shall not", "would not", "wouldn't",
    "cannot", "can not", "can't", "is not", "are not", "isn't", "aren't",
    "was not", "were not", "have not", "has not", "haven't", "hasn't",
    "never", "neither", "nor", "no", "none of", "without",
    "refrain from", "at no point", "in no event", "not",
)

# A negator that only limits is not a denial of the concept. "We do not retain
# personal data for longer than 90 days" is a retention period, not a refusal to
# retain, and "we do not share without your consent" is a sharing disclosure.
_LIMITERS: tuple[str, ...] = (
    "longer than", "more than", "beyond", "in excess of", "unless", "except",
    "other than", "without your", "without prior", "without explicit",
    "without obtaining", "without first", "without the", "for longer",
    "than is necessary", "than necessary", "save where", "save as",
    "apart from", "besides",
)

# Words that hand the sentence over to a new predicate, so a negator sitting
# before one of them is negating something else. "If you are not satisfied you
# may complain to the Board" publishes a route to the Board; reading the "not"
# as governing "complain" turns the clearest compliance in the notice into a gap.
_NEGATION_PIVOTS: tuple[str, ...] = (
    "may", "can", "could", "should", "must", "will", "shall", "please", "then",
    "want", "wish", "wishes", "prefer", "choose", "agree", "object",
    "entitled", "able to", "free to", "right to", "in order to",
)

_CLAUSE_BOUNDARY_RE = re.compile(r"[;:]|\s(?:but|however|although|though|whereas)\s")
# How far back a negator can sit and still govern the marker.
_NEGATOR_REACH = 80
# How far forward to look for the limiter that takes a negator back.
_LIMITER_REACH = 130


# Markers are matched with a leading word boundary and a short tail, so the
# deliberate stem "third part" reaches "third parties" and "child" reaches
# "children" while "the board" still stops short of "the boardroom".
_MARKER_TAIL = r"(?=\w{0,3}\b)"


def _alternation(phrases: tuple[str, ...], *, trailing: str = r"\b") -> re.Pattern[str]:
    """A word bounded alternation over phrases, longest alternative first.

    The trailing boundary is not optional. Without it "usa" matches inside
    "usage measurement" and a sentence about analytics becomes a claim that
    personal data is transferred to the United States, which is the kind of
    false positive a reviewer cannot tell from a real finding.
    """
    alts = sorted((escape_phrase(p) for p in phrases if p.strip()), key=len, reverse=True)
    return re.compile(r"\b(?:" + "|".join(alts) + r")" + trailing)


_NEGATOR_RE = _alternation(_NEGATORS)
_LIMITER_RE = _alternation(_LIMITERS)
_PIVOT_RE = _alternation(_NEGATION_PIVOTS)


# --------------------------------------------------------- false positive guards
#
# Taken from the earlier ruleset's discipline rather than its code: every phrase
# below is a place a marker matched something that was never a statement about
# personal data. A hit is dropped when one of these appears beside it.

_EXCLUSIONS: dict[str, tuple[str, ...]] = {
    "notice.complain_to_board": (
        r"\bboard of directors\b", r"\bboard of management\b", r"\bboard of trustees\b",
        r"\bboard meeting\b", r"\bboard resolution\b", r"\bboard approv",
        r"\bboard member", r"\badvisory board\b", r"\bschool board\b",
        r"\bon board\b", r"\bboard game", r"\bmessage board\b", r"\bjob board\b",
        r"\bboard of the company\b", r"\bexecutive board\b",
    ),
    "notice.children": (
        r"\bminor (?:change|amendment|modification|update|revision|edit|error|issue|correction|discrepanc)",
        r"\bminorit",
        r"\bchild (?:element|node|process|theme|page|component|window|window|table)\b",
        r"\bminor (?:version|release|bug)\b",
    ),
    "notice.third_party_sharing": (
        r"\bresponsible disclosure\b", r"\bvulnerability disclosure\b",
        r"\bshare (?:this|the) (?:page|article|post|link|story)\b",
        r"\bsocial (?:media )?shar", r"\bshare button\b",
        r"\bdisclosure of this (?:document|policy|notice)\b",
    ),
    "notice.security_measures": (
        r"\bprotect your (?:rights|interests|legal|intellectual|investment)\b",
    ),
    "notice.exercise_rights": (
        r"\ball rights reserved\b", r"\bintellectual property rights\b",
        r"\bour rights\b", r"\breserve(?:s|d)? the right\b",
        r"\bcopyright\b", r"\btrademark\b", r"\bmoral rights\b",
    ),
    "notice.retention_period": (
        r"\bretain(?:s|ed)? (?:the |full |sole )?(?:right|discretion|ownership|title)\b",
        r"\berase (?:this|the) (?:page|drawing|canvas|selection)\b",
    ),
    "notice.contact_point": (
        r"\bcontact us at any time for (?:sales|pricing|a quote|a demo)\b",
    ),
    "notice.withdraw_consent": (
        r"\bopt out of (?:this|the) (?:test|experiment|beta|preview)\b",
    ),
}

_EXCLUSION_PATTERNS: dict[str, tuple[re.Pattern[str], ...]] = {
    key: tuple(re.compile(p) for p in patterns) for key, patterns in _EXCLUSIONS.items()
}
# How much of the sentence around a hit the exclusions look at.
_EXCLUSION_WINDOW = 70


# ------------------------------------------------------------------- confidence

_CONF_STRUCTURAL = 0.9
_CONF_PROSE = 0.78
_CONF_NEGATIVE_DISCLOSURE = 0.7
_CONF_CORROBORATED_BONUS = 0.05
_CONF_ABSENT_SUBSTANTIAL = 0.85
_CONF_ABSENT_THIN = 0.55
_CONF_HUMAN_CHECK_CAP = 0.7
_CONF_UNASSESSED = 0.0
_CONF_READABILITY = 0.55
# Two independent sentences saying the same thing is worth a little more than one.
_CORROBORATION_AT = 2


# -------------------------------------------------------------- plain language

_LEGALESE: tuple[str, ...] = (
    "herein", "hereto", "hereinafter", "hereof", "hereunder", "heretofore",
    "thereof", "thereto", "thereunder", "therein", "thereafter", "whereas",
    "aforesaid", "aforementioned", "notwithstanding", "pursuant to",
    "inter alia", "mutatis mutandis", "in perpetuity", "shall be deemed",
    "without prejudice", "the foregoing", "save as", "ipso facto",
    "for the avoidance of doubt", "sub-clause", "in witness whereof",
    "wheresoever", "howsoever", "whatsoever", "hereby", "thereby",
)
_LEGALESE_RE = _alternation(_LEGALESE)

_MAX_AVG_SENTENCE_WORDS = 25.0
_MAX_CLAUSES_PER_SENTENCE = 2.0
_MAX_LEGALESE_PER_1000 = 2.0
_MIN_SENTENCES_TO_JUDGE_READABILITY = 3


# ------------------------------------------------------------- quote hygiene
#
# A quote is always a contiguous substring of the document it came from, so a
# reader can find it, and it never carries an email address or a telephone
# number. The second rule is why an excerpt is built around the marker rather
# than taken whole: a published grievance address is still a value this tool has
# no business keeping a copy of.

_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.]{2,}")
_PHONE_CANDIDATE_RE = re.compile(r"\+?\d[\d\s().-]{8,18}\d")
_QUOTE_LIMIT = 320
_MIN_QUOTE_WORDS = 3


def _contact_spans(text: str) -> list[tuple[int, int]]:
    spans = [m.span() for m in _EMAIL_RE.finditer(text)]
    for match in _PHONE_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if 10 <= len(digits) <= 13:
            spans.append(match.span())
    return sorted(spans)


_WHITESPACE_RE = re.compile(r"\s")


def _trim_to_words(text: str, lo: int, hi: int) -> tuple[int, int]:
    """Pull the bounds onto whitespace so the excerpt holds no half words.

    Any whitespace, not just a space: a wrapped sentence carries newlines and
    trimming only at spaces would leave a fragment mid word.
    """
    if lo > 0 and not text[lo - 1].isspace():
        nxt = _WHITESPACE_RE.search(text, lo)
        lo = len(text) if nxt is None else nxt.end()
    if hi < len(text) and not text[hi].isspace():
        prev = max(
            (m.start() for m in _WHITESPACE_RE.finditer(text[lo:hi])), default=None
        )
        hi = lo if prev is None else lo + prev
    return lo, hi


def excerpt(text: str, focus: tuple[int, int], limit: int = _QUOTE_LIMIT) -> str | None:
    """A verbatim window of text around focus, holding no contact value.

    Returns None when the focus itself sits inside an address, or when what is
    left is too short to read as a statement.
    """
    start, end = focus
    spans = _contact_spans(text)
    if any(s < end and start < e for s, e in spans):
        return None

    lo, hi = 0, len(text)
    for s, e in spans:
        if e <= start:
            lo = max(lo, e)
        elif s >= end:
            hi = min(hi, s)

    if hi - lo > limit:
        slack = limit - (end - start)
        if slack < 0:
            lo, hi = start, min(hi, start + limit)
        else:
            lo = max(lo, start - slack // 2)
            hi = min(hi, lo + limit)

    lo, hi = _trim_to_words(text, lo, hi)
    piece = text[lo:hi].strip()
    return piece if len(piece.split()) >= _MIN_QUOTE_WORDS else None


# ------------------------------------------------------------------- sentences


@dataclass(frozen=True)
class Sentence:
    """One readable line of a policy, kept verbatim so a quote can be taken."""

    text: str
    lowered: str
    shape: str
    doc_url: str
    doc_kind: str


# A footer rendered without separators comes through as one long line of link
# labels: "Home Our Story Our Products Our Solutions Blogs Legal Glossary Contact
# Us Terms and Conditions Privacy Policy". Long, unpunctuated and almost entirely
# capitalised, which no real sentence is, and a live read turned three of those
# labels into named recipients of personal data before this test existed.
_NAV_MIN_WORDS = 12
_NAV_CAPITALISED_SHARE = 0.7


def _shape_of(sentence: str) -> str:
    if sentence.count("|") >= 2 or sentence.count("•") >= 2:
        return SHAPE_NAV
    words = sentence.split()
    if len(words) <= _MAX_STRUCTURAL_WORDS and _looks_like_label(sentence, words):
        return SHAPE_STRUCTURAL
    if len(words) < _MIN_EVIDENCE_WORDS:
        return SHAPE_NAV
    if len(words) >= _NAV_MIN_WORDS and not sentence.rstrip().endswith((".", "!", "?")):
        capitalised = sum(1 for w in words if w[:1].isupper())
        if capitalised >= len(words) * _NAV_CAPITALISED_SHARE:
            return SHAPE_NAV
    return SHAPE_PROSE


def _looks_like_label(sentence: str, words: list[str]) -> bool:
    """A heading or a field label: short, unterminated, mostly capitalised.

    Worth separating out because a heading is stronger evidence than a sentence.
    A document with a "Data We Collect" heading has organised itself around the
    disclosure; one that mentions collection in passing has not.
    """
    if not words:
        return False
    if sentence.rstrip().endswith(":"):
        return True
    if sentence.rstrip().endswith((".", "!", "?")):
        return False
    capitalised = sum(1 for w in words if w[:1].isupper())
    return capitalised * 2 >= len(words)


def segment_spans(body: str) -> list[tuple[int, int]]:
    """Where each readable unit of a policy starts and ends.

    Spans rather than pieces, so every sentence stays a contiguous substring of
    the body and a quote taken from one can be found on the page.

    The hard part is a line break. Published HTML is routinely hard wrapped, and
    breaking at every newline cuts "with Google\\nAnalytics" in half, which loses
    the processor, the destination two lines further down and the sentence
    lengths the readability judgement is made of. So a lone newline ends a unit
    only after terminal punctuation, after a colon, or when what came before it
    was short enough to be a heading. Otherwise it is a wrap and reading carries
    on through it.
    """
    spans: list[tuple[int, int]] = []
    start = index = 0
    length = len(body)

    def skip_space(pos: int) -> int:
        while pos < length and body[pos].isspace():
            pos += 1
        return pos

    while index < length:
        char = body[index]
        if char in ".!?":
            after = index + 1
            if after >= length or body[after].isspace():
                spans.append((start, after))
                start = index = skip_space(after)
                continue
        elif char in ":;" and index + 1 < length and body[index + 1] in "\n\r":
            spans.append((start, index + 1))
            start = index = skip_space(index + 1)
            continue
        elif char in "\n\r":
            stop = index
            breaks = 0
            while stop < length and body[stop].isspace():
                if body[stop] in "\n\r":
                    breaks += 1
                stop += 1
            # Short is not enough to make a heading. "We retain\ntransaction
            # records for seven years" opens with two words and is a wrapped
            # sentence, so the line after has to start something new as well.
            heading = (
                len(body[start:index].split()) <= _MAX_STRUCTURAL_WORDS
                and (stop >= length or body[stop][:1].isupper() or body[stop][:1].isdigit())
            )
            if breaks >= 2 or heading:
                spans.append((start, index))
                start = index = stop
                continue
            index = stop
            continue
        index += 1

    if start < length:
        spans.append((start, length))
    return [(a, b) for a, b in spans if body[a:b].strip()]


def sentences_of(document: PolicyDocument) -> list[Sentence]:
    """A policy's prose, split into units that can each be quoted verbatim."""
    body = document.body_text or ""
    out: list[Sentence] = []
    for lo, hi in segment_spans(body):
        piece = body[lo:hi].strip()[:_SENTENCE_CAP]
        if not piece:
            continue
        out.append(
            Sentence(
                text=piece,
                lowered=piece.lower(),
                shape=_shape_of(piece),
                doc_url=document.url,
                doc_kind=document.kind,
            )
        )
    return out


# -------------------------------------------------------------------- negation


def is_denial(lowered: str, marker_start: int) -> bool:
    """Whether a negator governs the marker, rather than sitting near it.

    Three things have to hold. The negator must be in the same clause, so "We
    share data with processors; we do not sell it" is not a refusal to share. It
    must be the nearest one, with no pivot between it and the marker handing the
    sentence to another predicate. And it must not be a limit rather than a
    refusal: "we do not retain personal data for longer than 90 days" is a
    retention period, not a claim that nothing is retained.
    """
    clause_start = 0
    for boundary in _CLAUSE_BOUNDARY_RE.finditer(lowered[:marker_start]):
        clause_start = boundary.end()

    window_start = max(clause_start, marker_start - _NEGATOR_REACH)
    window = lowered[window_start:marker_start]
    negators = list(_NEGATOR_RE.finditer(window))
    if not negators:
        return False
    if _PIVOT_RE.search(window[negators[-1].end() :]):
        return False

    tail = lowered[window_start : min(len(lowered), marker_start + _LIMITER_REACH)]
    return not _LIMITER_RE.search(tail)


# ---------------------------------------------------------------- requirements


@dataclass(frozen=True)
class _Hit:
    sentence: Sentence
    span: tuple[int, int]
    denied: bool


def _marker_pattern(markers: tuple[str, ...]) -> re.Pattern[str] | None:
    if not markers:
        return None
    return _alternation(markers, trailing=_MARKER_TAIL)


_MARKER_PATTERNS: dict[str, re.Pattern[str] | None] = {
    r.requirement_id: _marker_pattern(r.markers) for r in REQUIREMENTS
}


def _excluded(requirement_id: str, sentence: Sentence, span: tuple[int, int]) -> bool:
    patterns = _EXCLUSION_PATTERNS.get(requirement_id)
    if not patterns:
        return False
    lo = max(0, span[0] - _EXCLUSION_WINDOW)
    hi = min(len(sentence.lowered), span[1] + _EXCLUSION_WINDOW)
    window = sentence.lowered[lo:hi]
    return any(p.search(window) for p in patterns)


def _hits_for(requirement: PolicyRequirement, sentences: list[Sentence]) -> list[_Hit]:
    pattern = _MARKER_PATTERNS.get(requirement.requirement_id)
    if pattern is None:
        return []
    hits: list[_Hit] = []
    for sentence in sentences:
        if sentence.shape == SHAPE_NAV:
            continue
        for match in pattern.finditer(sentence.lowered):
            if _excluded(requirement.requirement_id, sentence, match.span()):
                continue
            hits.append(
                _Hit(
                    sentence=sentence,
                    span=match.span(),
                    denied=is_denial(sentence.lowered, match.start()),
                )
            )
    return hits


def _rank(hit: _Hit) -> tuple[int, int, int]:
    """Best evidence first: asserted over denied, structural over prose."""
    return (
        0 if not hit.denied else 1,
        0 if hit.sentence.shape == SHAPE_STRUCTURAL else 1,
        -len(hit.sentence.text),
    )


def _cap(confidence: float, requirement: PolicyRequirement) -> float:
    if requirement.needs_human_check:
        return min(confidence, _CONF_HUMAN_CHECK_CAP)
    return round(confidence, 2)


def _unassessed(
    requirement: PolicyRequirement, documents: list[PolicyDocument]
) -> PolicyRequirementCheck:
    """The requirement could not be looked at, which is not the same as failing.

    Named out loud because the alternative is a report that grades a site on a
    document nobody managed to open.
    """
    kinds = ", ".join(requirement.applies_to)
    found = [d for d in documents if d.kind in requirement.applies_to]
    if not found:
        reason = f"no {kinds} document was found, so there was nothing to read"
        source = None
    else:
        unreadable = found[0]
        source = unreadable.url
        if not unreadable.reachable:
            reason = (
                f"the {unreadable.kind} document at {unreadable.url} could not be "
                "fetched, so its contents are unknown"
            )
        else:
            reason = (
                f"the {unreadable.kind} document at {unreadable.url} came back with "
                f"{unreadable.word_count} words of readable text, which is too little "
                "to read as a policy"
            )
    return PolicyRequirementCheck(
        requirement_id=requirement.requirement_id,
        title=requirement.title,
        dpdp_section=requirement.dpdp_section,
        dpdp_rule=requirement.dpdp_rule,
        satisfied=False,
        unassessed=True,
        evidence=UNASSESSED_PREFIX + reason,
        source_url=source,
        requires_human_validation=True,
        confidence=_CONF_UNASSESSED,
    )


def is_unassessed(check: PolicyRequirementCheck) -> bool:
    """True when nothing was read, so the check is neither met nor a gap.

    Reads the flag, falling back to the evidence prefix so a check built before
    the flag existed still reports correctly.
    """
    return check.unassessed or check.evidence.startswith(UNASSESSED_PREFIX)


def unassessed_checks(
    checks: list[PolicyRequirementCheck],
) -> list[PolicyRequirementCheck]:
    return [c for c in checks if is_unassessed(c)]


def gap_checks(checks: list[PolicyRequirementCheck]) -> list[PolicyRequirementCheck]:
    """Requirements the documents were read for and found not to address."""
    return [c for c in checks if not c.satisfied and not is_unassessed(c)]


def _check_for(
    requirement: PolicyRequirement,
    readable: list[PolicyDocument],
    by_kind: dict[str, list[Sentence]],
) -> PolicyRequirementCheck:
    applicable = [d for d in readable if d.kind in requirement.applies_to]
    sentences: list[Sentence] = []
    for kind in requirement.applies_to:
        sentences.extend(by_kind.get(kind, []))

    hits = sorted(_hits_for(requirement, sentences), key=_rank)
    policy = _NEGATION_POLICY.get(requirement.requirement_id, PROCEDURE)

    asserted = [h for h in hits if not h.denied]
    denied = [h for h in hits if h.denied]

    if asserted:
        best = asserted[0]
        structural = best.sentence.shape == SHAPE_STRUCTURAL
        confidence = _CONF_STRUCTURAL if structural else _CONF_PROSE
        distinct = len({h.sentence.text for h in asserted})
        if distinct >= _CORROBORATION_AT:
            confidence += _CONF_CORROBORATED_BONUS
        corroboration = (
            f", corroborated across {distinct} statements" if distinct >= _CORROBORATION_AT else ""
        )
        evidence = (
            f"the {best.sentence.doc_kind} document addresses this in "
            f"{'a heading or label' if structural else 'prose'}{corroboration}"
        )
        return PolicyRequirementCheck(
            requirement_id=requirement.requirement_id,
            title=requirement.title,
            dpdp_section=requirement.dpdp_section,
            dpdp_rule=requirement.dpdp_rule,
            satisfied=True,
            evidence=evidence,
            quote=excerpt(best.sentence.text, best.span),
            source_url=best.sentence.doc_url,
            requires_human_validation=requirement.needs_human_check or not structural,
            confidence=_cap(min(confidence, 0.95), requirement),
        )

    if denied and policy == DISCLOSURE:
        best = denied[0]
        evidence = (
            f"the {best.sentence.doc_kind} document answers this in the negative, which "
            "is a disclosure in its own right and a claim a later stage can test"
        )
        return PolicyRequirementCheck(
            requirement_id=requirement.requirement_id,
            title=requirement.title,
            dpdp_section=requirement.dpdp_section,
            dpdp_rule=requirement.dpdp_rule,
            satisfied=True,
            evidence=evidence,
            quote=excerpt(best.sentence.text, best.span),
            source_url=best.sentence.doc_url,
            requires_human_validation=True,
            confidence=_cap(_CONF_NEGATIVE_DISCLOSURE, requirement),
        )

    source = applicable[0].url if applicable else None
    longest = max((d.word_count for d in applicable), default=0)
    substantial = longest >= _SUBSTANTIAL_DOC_WORDS
    confidence = _CONF_ABSENT_SUBSTANTIAL if substantial else _CONF_ABSENT_THIN

    if denied:
        best = denied[0]
        evidence = (
            f"{requirement.absence_detail}; the only mention is a disclaimer rather "
            "than a description of what is done"
        )
        return PolicyRequirementCheck(
            requirement_id=requirement.requirement_id,
            title=requirement.title,
            dpdp_section=requirement.dpdp_section,
            dpdp_rule=requirement.dpdp_rule,
            satisfied=False,
            evidence=evidence,
            quote=excerpt(best.sentence.text, best.span),
            source_url=best.sentence.doc_url,
            requires_human_validation=True,
            confidence=_cap(confidence, requirement),
        )

    scale = "a substantial" if substantial else "a short"
    evidence = (
        f"{requirement.absence_detail}; nothing in {scale} "
        f"{'/'.join(requirement.applies_to)} document ({longest} words) addresses it"
    )
    return PolicyRequirementCheck(
        requirement_id=requirement.requirement_id,
        title=requirement.title,
        dpdp_section=requirement.dpdp_section,
        dpdp_rule=requirement.dpdp_rule,
        satisfied=False,
        evidence=evidence,
        source_url=source,
        requires_human_validation=requirement.needs_human_check or not substantial,
        confidence=_cap(confidence, requirement),
    )


# ----------------------------------------------------------- readability check


def readability(sentences: list[Sentence]) -> dict[str, float]:
    """Average sentence length, clause density and legalese rate.

    Rule 3(b) wants an account a Data Principal can act on, and there is no
    phrase to match for that. These three are the measurable part of it: a
    notice built from 60 word sentences carrying four subordinate clauses each
    has not given a fair account of anything, whatever it contains.
    """
    prose = [s for s in sentences if s.shape == SHAPE_PROSE]
    if not prose:
        return {"sentences": 0.0, "avg_words": 0.0, "clauses": 0.0, "legalese": 0.0}

    words = sum(len(s.text.split()) for s in prose)
    clauses = sum(s.text.count(",") + s.text.count(";") for s in prose)
    legal = sum(len(_LEGALESE_RE.findall(s.lowered)) for s in prose)
    return {
        "sentences": float(len(prose)),
        "avg_words": round(words / len(prose), 1),
        "clauses": round(clauses / len(prose), 2),
        "legalese": round(legal * 1000 / words, 2) if words else 0.0,
    }


def _plain_language_check(
    requirement: PolicyRequirement,
    readable: list[PolicyDocument],
    by_kind: dict[str, list[Sentence]],
) -> PolicyRequirementCheck:
    notices = [d for d in readable if d.kind in requirement.applies_to]
    sentences = [s for k in requirement.applies_to for s in by_kind.get(k, [])]
    stats = readability(sentences)

    if stats["sentences"] < _MIN_SENTENCES_TO_JUDGE_READABILITY:
        return _unassessed(requirement, notices)

    failures: list[str] = []
    if stats["avg_words"] > _MAX_AVG_SENTENCE_WORDS:
        failures.append(
            f"sentences average {stats['avg_words']} words against a {_MAX_AVG_SENTENCE_WORDS:.0f} word guide"
        )
    if stats["clauses"] > _MAX_CLAUSES_PER_SENTENCE:
        failures.append(
            f"each sentence carries {stats['clauses']} clause breaks on average"
        )
    if stats["legalese"] > _MAX_LEGALESE_PER_1000:
        failures.append(
            f"legalese appears {stats['legalese']} times per thousand words"
        )

    longest = max(
        (s for s in sentences if s.shape == SHAPE_PROSE),
        key=lambda s: len(s.text.split()),
        default=None,
    )
    quote = excerpt(longest.text, (0, 0)) if longest is not None else None

    if failures:
        evidence = f"{requirement.absence_detail}; " + ", and ".join(failures)
    else:
        evidence = (
            f"readability is within guide: sentences average {stats['avg_words']} words "
            f"with {stats['clauses']} clause breaks and {stats['legalese']} legalese "
            "terms per thousand words"
        )

    return PolicyRequirementCheck(
        requirement_id=requirement.requirement_id,
        title=requirement.title,
        dpdp_section=requirement.dpdp_section,
        dpdp_rule=requirement.dpdp_rule,
        satisfied=not failures,
        evidence=evidence,
        quote=quote,
        source_url=notices[0].url if notices else None,
        # Readability is a proxy for a judgement only a reader can make, so this
        # one is never reported as settled either way.
        requires_human_validation=True,
        confidence=_CONF_READABILITY,
    )


# --------------------------------------------------------------- claim helpers

_WORD_NUMBERS: dict[str, int] = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7,
    "eight": 8, "nine": 9, "ten": 10, "eleven": 11, "twelve": 12,
    "fourteen": 14, "fifteen": 15, "eighteen": 18, "twenty": 20,
    "twenty-four": 24, "thirty": 30, "forty-five": 45, "sixty": 60,
    "seventy-two": 72, "ninety": 90, "hundred": 100,
}
_NUMBER_ALT = "|".join(
    sorted((re.escape(w) for w in _WORD_NUMBERS), key=len, reverse=True)
)
_DURATION_RE = re.compile(
    r"\b(\d{1,4}|" + _NUMBER_ALT + r")[\s-]+(hour|hours|day|days|week|weeks|"
    r"month|months|year|years)\b",
    re.I,
)
_UNQUANTIFIED_RETENTION_RE = re.compile(
    r"\b(?:indefinitely|in perpetuity|for as long as (?:is )?(?:reasonably )?necessary|"
    r"as long as (?:is )?(?:reasonably )?necessary|for the duration of|"
    r"until you (?:delete|close|deactivate)|no longer than (?:is )?necessary)\b"
)

_RETENTION_CONTEXT_RE = _alternation(
    (
        "retain", "retention", "keep", "kept", "store", "storage", "hold",
        "held", "archive", "delete", "deletion", "erase", "erasure", "dispose",
        "disposal", "purge", "anonymise", "anonymize",
    ),
    trailing=_MARKER_TAIL,
)
_RESPONSE_CONTEXT_RE = _alternation(
    (
        "respond", "responds", "response", "reply", "replies", "resolve",
        "resolves", "resolution", "acknowledge", "acknowledges", "revert",
        "address your request", "turnaround", "processed within",
    )
)
_BREACH_CONTEXT_RE = _alternation(
    (
        "data breach", "personal data breach", "security incident",
        "security breach", "unauthorised access", "unauthorized access",
        "data leak", "breach notification", "breach of security",
    )
)
_DATA_CATEGORIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("payment data", ("payment", "card details", "billing data")),
    ("log data", ("log data", "server logs", "access logs", "logs")),
    ("backups", ("backup", "backups")),
    ("cookies", ("cookie", "cookies")),
    ("account data", ("account data", "account information", "your account")),
    ("transaction records", ("transaction", "invoices", "order history")),
    ("usage data", ("usage data", "analytics data", "telemetry")),
)


def _duration_label(raw_number: str, unit: str) -> str | None:
    key = raw_number.strip().lower()
    if key.isdigit():
        count = int(key)
    else:
        count = _WORD_NUMBERS.get(key, 0)
    if count <= 0:
        return None
    singular = unit.lower().rstrip("s")
    return f"{count} {singular}" if count == 1 else f"{count} {singular}s"


# How far either side of a duration to look for the category it applies to. A
# sentence can hold two promises ("account data for 90 days, transaction records
# for seven years") and filing both under the first category would misreport one.
_CATEGORY_REACH = 90


def _category_near(lowered: str, span: tuple[int, int]) -> str:
    window = lowered[max(0, span[0] - _CATEGORY_REACH) : span[1] + 20]
    for label, phrases in _DATA_CATEGORIES:
        if any(p in window for p in phrases):
            return label
    for label, phrases in _DATA_CATEGORIES:
        if any(p in lowered for p in phrases):
            return label
    return "personal data"


def _claim(
    claim_type: str,
    subject: str,
    value: str | None,
    sentence: Sentence,
    span: tuple[int, int],
    confidence: float,
) -> PolicyClaim | None:
    quote = excerpt(sentence.text, span)
    if quote is None:
        return None
    return PolicyClaim(
        claim_type=claim_type,
        subject=_normalise(subject),
        # Normalised, unlike the quote: a value read off a hard wrapped line
        # comes back as "Google\nAnalytics", and a later stage matching on it
        # would never find the processor it is looking for.
        value=_normalise(value) if value else value,
        quote=quote,
        source_url=sentence.doc_url,
        confidence=confidence,
    )


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


# ------------------------------------------------------------ claim extractors


def _retention_claims(sentence: Sentence) -> list[PolicyClaim]:
    if not _RETENTION_CONTEXT_RE.search(sentence.lowered):
        return []
    claims: list[PolicyClaim] = []
    responding = bool(_RESPONSE_CONTEXT_RE.search(sentence.lowered))
    breaching = bool(_BREACH_CONTEXT_RE.search(sentence.lowered))

    if not responding and not breaching:
        for match in _DURATION_RE.finditer(sentence.text):
            label = _duration_label(match.group(1), match.group(2))
            if label is None:
                continue
            claim = _claim(
                "retention",
                _category_near(sentence.lowered, match.span()),
                label,
                sentence,
                match.span(),
                0.85,
            )
            if claim is not None:
                claims.append(claim)

    if not claims:
        vague = _UNQUANTIFIED_RETENTION_RE.search(sentence.lowered)
        if vague is not None:
            claim = _claim(
                "retention",
                _category_near(sentence.lowered, vague.span()),
                None,
                sentence,
                vague.span(),
                0.6,
            )
            if claim is not None:
                claims.append(claim)
    return claims


_KNOWN_PROCESSORS: tuple[str, ...] = (
    "google analytics", "google ads", "google adsense", "google tag manager",
    "google cloud", "google workspace", "google fonts", "firebase",
    "youtube", "doubleclick", "recaptcha",
    "meta platforms", "meta pixel", "facebook pixel", "facebook", "instagram",
    "whatsapp business", "linkedin", "twitter", "tiktok", "snapchat",
    "pinterest", "reddit ads",
    "microsoft clarity", "microsoft azure", "microsoft advertising", "bing ads",
    "adobe analytics", "adobe experience", "hotjar", "mixpanel", "amplitude",
    "posthog", "fullstory", "logrocket", "smartlook", "clevertap", "moengage",
    "webengage", "appsflyer", "matomo", "plausible", "fathom analytics",
    "hubspot", "salesforce", "marketo", "mailchimp", "klaviyo", "brevo",
    "sendinblue", "activecampaign", "sendgrid", "mailgun", "postmark",
    "customer.io", "zoho campaigns",
    "twilio", "msg91", "gupshup", "exotel", "knowlarity", "kaleyra",
    "intercom", "zendesk", "freshdesk", "freshworks", "crisp", "tawk.to",
    "drift", "help scout",
    "sentry", "bugsnag", "rollbar", "datadog", "new relic", "grafana cloud",
    "elastic cloud",
    "stripe", "razorpay", "payu", "cashfree", "ccavenue", "billdesk",
    "phonepe", "paytm", "instamojo", "braintree", "paypal", "juspay",
    "amazon web services", "aws", "cloudflare", "akamai", "fastly",
    "vercel", "netlify", "heroku", "digitalocean", "linode", "hetzner",
    "zoho", "slack", "notion", "airtable", "hubspot crm",
    "auth0", "okta", "amazon cognito", "clerk.com", "supabase",
    "mongodb atlas", "snowflake", "databricks",
    "digio", "karza", "signzy", "hyperverge", "idfy", "perfios",
    "transunion cibil", "experian", "equifax",
)
_PROCESSOR_RE = _alternation(_KNOWN_PROCESSORS)

# Stemmed, because "third part" has to reach "third parties" and "processor"
# has to reach "processors" without every inflection being spelled out.
_SHARING_CONTEXT_RE = _alternation(
    (
        "share", "shared", "sharing", "disclose", "disclosure", "transfer",
        "provide to", "provided to", "third part", "service provider",
        "processor", "sub-processor", "subprocessor", "vendor", "partner",
        "recipient", "we use", "we work with", "we engage", "powered by",
        "integrate", "integration", "rely on", "onward transfer",
    ),
    trailing=_MARKER_TAIL,
)

_CORPORATE_SUFFIXES: tuple[str, ...] = (
    "Pvt", "Pvt.", "Private", "Ltd", "Ltd.", "Limited", "LLP", "Inc", "Inc.",
    "LLC", "PLC", "GmbH", "Corp", "Corp.", "Corporation", "Technologies",
    "Technology", "Systems", "Solutions", "Labs", "Bank", "Insurance",
    "Holdings", "Ventures", "Networks", "Consulting",
)
_PARTY_INTRODUCERS: tuple[str, ...] = (
    "with", "to", "including", "include", "includes", "such as", "namely",
    "like", "e.g.", "eg.", "from", "by", "through", "via",
)
_CAPITALISED_RUN_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9&.'’-]{1,}(?:\s+(?:of|and|&|[A-Z][A-Za-z0-9&.'’-]{1,})){0,3})"
)
_PARTY_STOPWORDS: frozenset[str] = frozenset(
    w.lower()
    for w in (
        "We", "Our", "Ours", "Us", "You", "Your", "Yours", "The", "This",
        "That", "These", "Those", "It", "If", "In", "On", "At", "For", "And",
        "Or", "But", "As", "By", "An", "A", "I", "He", "She", "They", "Their",
        "India", "Indian", "Government", "Act", "Rules", "Rule", "Section",
        "DPDP", "DPDPA", "GDPR", "Digital", "Personal", "Data", "Protection",
        "Board", "Privacy", "Policy", "Notice", "Cookie", "Cookies", "Terms",
        "Service", "Services", "Company", "User", "Users", "Customer",
        "Customers", "Website", "Site", "App", "Application", "Platform",
        "Account", "Email", "Please", "However", "Where", "When", "While",
        "Under", "Pursuant", "Subject", "Except", "Such", "Any", "All", "No",
        "Not", "Further", "Additionally", "Also", "Moreover", "Therefore",
        "Hence", "Thus", "Note", "Important", "Effective", "Last", "Updated",
        "Version", "Contact", "Fiduciary", "Principal", "Consent", "Manager",
        "European", "Union", "United", "States", "Kingdom", "Information",
        "Technology", "Officer", "Grievance", "Nodal", "Sensitive", "Security",
        "Processing", "Purpose", "Purposes", "Legitimate", "Consequences",
        "Rights", "Right", "Children", "Child", "Guardian", "Parent",
        "Retention", "Period", "Third", "Parties", "Party", "Legal", "Law",
        "Court", "Authority", "Republic", "Chapter", "Schedule", "Annexure",
        "January", "February", "March", "April", "May", "June", "July",
        "August", "September", "October", "November", "December",
    )
)
# Named parties are the noisiest thing here, so the number kept per document is
# bounded and every one of them is flagged for human validation downstream by
# carrying a low confidence.
_MAX_NAMED_PARTIES = 40


# Capitalised phrases a notice is full of that are not organisations. The
# introducer test alone is far too weak on its own: "the right to Object" ends
# in "to", so Object was being recorded as a company personal data is shared
# with. Live run against a real notice produced Withdraw Consent, Object,
# Products Our Solutions Blogs, Redacto.io Powered and AI as named recipients,
# five false positives out of eight claims.
_RIGHTS_VOCABULARY: frozenset[str] = frozenset(
    w.lower()
    for w in (
        "object", "objection", "access", "correction", "correct", "erasure",
        "erase", "deletion", "delete", "nomination", "nominate", "nominee",
        "portability", "withdraw", "withdrawal", "consent", "grievance",
        "redressal", "rectification", "restriction", "restrict", "opt",
        "unsubscribe", "complaint", "complain",
    )
)

# Section names from a navigation bar, which a hard wrapped footer turns into
# one long capitalised run.
_NAVIGATION_VOCABULARY: frozenset[str] = frozenset(
    w.lower()
    for w in (
        "products", "product", "solutions", "solution", "blogs", "blog",
        "resources", "pricing", "about", "careers", "contact", "support",
        "docs", "documentation", "home", "login", "signup", "demo", "powered",
        "features", "integrations", "partners", "customers", "company",
    )
)

# Below this a run is an acronym or a fragment, not a name worth reporting,
# unless a corporate suffix sits beside it.
_MIN_ENTITY_CHARS = 4


def _is_the_publisher(run: str, source_url: str) -> bool:
    """Whether a capitalised run is the site's own name.

    A notice names its publisher constantly, and the publisher is the first party
    rather than a recipient of anything. A live read recorded Redacto and
    Redacto.io Powered as organisations personal data is shared with, off a notice
    published at redacto.ai.
    """
    brand = brand_label(urlparse(source_url).hostname)
    if not brand:
        return False
    for token in run.split():
        stem = token.strip(" .,;:").split(".")[0].lower()
        if stem == brand:
            return True
    return False


def _could_be_an_organisation(run: str, tokens: list[str]) -> bool:
    """Whether a capitalised run is plausibly the name of a recipient.

    Deliberately conservative. A missed processor still shows up in the web
    stage's third party hosts, where it is observed rather than inferred, but an
    invented recipient is a claim about the site that nothing supports and that
    a later stage would then try to verify.
    """
    lowered = [t.strip(" .,;:").lower() for t in tokens]
    lowered = [t for t in lowered if t]
    if not lowered:
        return False

    # The disqualifiers run first, before the corporate suffix is allowed to
    # vouch for anything. "Products Our Solutions Blogs" is a navigation bar
    # that lost its line breaks, and "Solutions" is a perfectly ordinary word in
    # a company name, so letting the suffix decide first admitted the menu.
    if all(t in _RIGHTS_VOCABULARY | _PARTY_STOPWORDS for t in lowered):
        return False
    if lowered[0] in _RIGHTS_VOCABULARY:
        return False

    # A footer credit, not a recipient.
    if "powered" in lowered:
        return False

    # Two or more section words in one run is furniture, never a company name.
    if sum(1 for t in lowered if t in _NAVIGATION_VOCABULARY) >= 2:
        return False
    if len(lowered) == 1 and lowered[0] in _NAVIGATION_VOCABULARY:
        return False

    if len(run.replace(" ", "")) < _MIN_ENTITY_CHARS:
        return False

    return True


def _third_party_claims(sentence: Sentence) -> list[PolicyClaim]:
    claims: list[PolicyClaim] = []
    sharing = bool(_SHARING_CONTEXT_RE.search(sentence.lowered))

    for match in _PROCESSOR_RE.finditer(sentence.lowered):
        if is_denial(sentence.lowered, match.start()):
            continue
        name = sentence.text[match.start() : match.end()].strip()
        claim = _claim(
            "third_party", "named recipient", name, sentence, match.span(), 0.8
        )
        if claim is not None:
            claims.append(claim)

    if not sharing:
        return claims

    # A flat refusal to share is the most testable claim in the whole notice:
    # the web and code stages can contradict it directly.
    for match in _SHARING_CONTEXT_RE.finditer(sentence.lowered):
        if not is_denial(sentence.lowered, match.start()):
            continue
        claim = _claim(
            "third_party", "no onward sharing", "none", sentence, match.span(), 0.7
        )
        if claim is not None:
            claims.append(claim)
        break

    for match in _CAPITALISED_RUN_RE.finditer(sentence.text):
        if match.start() == 0:
            continue
        run = match.group(1).strip(" .,;")
        tokens = run.split()
        if not tokens or tokens[0].lower() in _PARTY_STOPWORDS:
            continue
        if all(t.lower() in _PARTY_STOPWORDS for t in tokens):
            continue
        if not _could_be_an_organisation(run, tokens):
            continue
        if _is_the_publisher(run, sentence.doc_url):
            continue
        has_suffix = len(tokens) >= 2 and any(t in _CORPORATE_SUFFIXES for t in tokens)
        prefix = sentence.lowered[max(0, match.start() - 24) : match.start()]
        introduced = any(prefix.rstrip().endswith(i) for i in _PARTY_INTRODUCERS)
        if not (has_suffix or introduced):
            continue
        if _PROCESSOR_RE.search(run.lower()):
            continue
        claim = _claim(
            "third_party",
            "named recipient",
            run,
            sentence,
            match.span(),
            0.75 if has_suffix else 0.5,
        )
        if claim is not None:
            claims.append(claim)
    return claims


_RIGHTS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    (
        "access",
        "right to access",
        (
            "right to access", "right of access", "access your personal data",
            "obtain a copy", "request a copy", "summary of personal data",
            "summary of the personal data",
        ),
    ),
    (
        "correction",
        "right to correction",
        (
            "right to correction", "right to correct", "correct your personal data",
            "rectification", "rectify", "update your personal data",
            "correction and erasure",
        ),
    ),
    (
        "erasure",
        "right to erasure",
        (
            "right to erasure", "right to erase", "right to deletion",
            "request deletion", "request erasure", "request the deletion",
            "delete your personal data", "delete your account", "right to be forgotten",
        ),
    ),
    (
        "nomination",
        "right to nominate",
        ("right to nominate", "right of nomination", "nominate another individual", "nomination"),
    ),
    (
        "withdraw_consent",
        "right to withdraw consent",
        (
            "withdraw your consent", "withdraw consent", "revoke consent",
            "revoke your consent", "withdrawal of consent",
        ),
    ),
    (
        "grievance",
        "right to grievance redressal",
        (
            "grievance redressal", "raise a grievance", "lodge a grievance",
            "lodge a complaint", "file a complaint", "register a complaint",
        ),
    ),
    (
        "opt_out_marketing",
        "right to opt out of marketing",
        (
            "unsubscribe", "opt out of marketing", "opt-out of marketing",
            "stop receiving marketing", "opt out of promotional",
        ),
    ),
    (
        "portability",
        "right to data portability",
        ("data portability", "portable format", "machine-readable format", "export your data"),
    ),
)
_RIGHTS_PATTERNS: tuple[tuple[str, str, re.Pattern[str]], ...] = tuple(
    (key, label, _alternation(phrases)) for key, label, phrases in _RIGHTS
)


def _rights_claims(sentence: Sentence) -> list[PolicyClaim]:
    claims: list[PolicyClaim] = []
    for key, label, pattern in _RIGHTS_PATTERNS:
        match = pattern.search(sentence.lowered)
        if match is None or is_denial(sentence.lowered, match.start()):
            continue
        claim = _claim("rights", label, key, sentence, match.span(), 0.8)
        if claim is not None:
            claims.append(claim)

    if _RESPONSE_CONTEXT_RE.search(sentence.lowered):
        for match in _DURATION_RE.finditer(sentence.text):
            label = _duration_label(match.group(1), match.group(2))
            if label is None:
                continue
            claim = _claim(
                "rights", "response timeline", label, sentence, match.span(), 0.8
            )
            if claim is not None:
                claims.append(claim)
            break
    return claims


_DESTINATIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("United States", ("united states", "usa", "u.s.a", "u.s. servers", "american servers")),
    ("European Union", ("european union", "european economic area", "eea")),
    ("United Kingdom", ("united kingdom",)),
    ("Singapore", ("singapore",)),
    ("Ireland", ("ireland",)),
    ("Germany", ("germany",)),
    ("Netherlands", ("netherlands",)),
    ("France", ("france",)),
    ("Japan", ("japan",)),
    ("Australia", ("australia",)),
    ("Canada", ("canada",)),
    ("United Arab Emirates", ("united arab emirates",)),
    ("Hong Kong", ("hong kong",)),
    ("Switzerland", ("switzerland",)),
    ("Brazil", ("brazil",)),
    ("South Korea", ("south korea",)),
    ("Indonesia", ("indonesia",)),
    ("Bahrain", ("bahrain",)),
)
_DESTINATION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, _alternation(phrases)) for name, phrases in _DESTINATIONS
)
# Deliberately narrow. "Depending on your jurisdiction, including under the GDPR
# in the European Union" names where the reader lives, not where their data goes,
# and a live read recorded the European Union as a transfer destination out of it.
# The words dropped for that reason were jurisdiction, location and bare
# processing, all of which a notice uses about the law far more often than about
# a transfer.
_TRANSFER_CONTEXT_RE = _alternation(
    (
        "transfer", "transfers", "transferred", "transmit", "transmitted",
        "store", "stored", "storage", "host", "hosted", "hosting",
        "located", "server", "servers", "data centre", "data center",
        "outside india", "cross-border", "cross border", "abroad",
        "outside the territory of india", "onward transfer", "processed in",
        "processed outside", "processed and stored",
    )
)
_OUTSIDE_INDIA_RE = _alternation(
    ("outside india", "outside the territory of india", "outside of india", "beyond india")
)


def _cross_border_claims(sentence: Sentence) -> list[PolicyClaim]:
    if not _TRANSFER_CONTEXT_RE.search(sentence.lowered):
        return []
    claims: list[PolicyClaim] = []

    outside = _OUTSIDE_INDIA_RE.search(sentence.lowered)
    if outside is not None:
        denied = is_denial(sentence.lowered, outside.start())
        claim = _claim(
            "cross_border",
            "no transfer outside India" if denied else "transfer outside India",
            "none" if denied else "unspecified destination",
            sentence,
            outside.span(),
            0.75,
        )
        if claim is not None:
            claims.append(claim)

    for name, pattern in _DESTINATION_PATTERNS:
        match = pattern.search(sentence.lowered)
        if match is None or is_denial(sentence.lowered, match.start()):
            continue
        claim = _claim("cross_border", "destination", name, sentence, match.span(), 0.7)
        if claim is not None:
            claims.append(claim)
    return claims


# Officer titles the Rules expect, plus the phrasings a notice uses when it
# publishes a route without naming a title. "Customer support" is deliberately
# absent: "to provide customer support" is a purpose, not a contact point, and
# reading it as one credits the notice with a route it never published.
_CONTACT_TITLES: tuple[str, ...] = (
    *DPO_KEYWORDS,
    "privacy team",
    "data protection team",
    "contact us at",
    "write to us at",
    "reach out to us at",
)
_CONTACT_TITLE_RE = _alternation(_CONTACT_TITLES)
_CHANNEL_TESTS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("web form", ("form", "portal", "dashboard", "submit a request", "self-service", "ticket")),
    ("postal address", ("registered office", "postal address", "pin code", "pincode", "address:")),
)


def _contact_claims(sentence: Sentence) -> list[PolicyClaim]:
    match = _CONTACT_TITLE_RE.search(sentence.lowered)
    if match is None or is_denial(sentence.lowered, match.start()):
        return []

    channels: list[str] = []
    if _EMAIL_RE.search(sentence.text):
        channels.append("email")
    for label, phrases in _CHANNEL_TESTS:
        if any(p in sentence.lowered for p in phrases):
            channels.append(label)
    spans = _contact_spans(sentence.text)
    if any(not _EMAIL_RE.match(sentence.text[s:e]) for s, e in spans):
        channels.append("telephone")

    claim = _claim(
        "contact",
        sentence.lowered[match.start() : match.end()].strip(),
        ", ".join(sorted(set(channels))) or None,
        sentence,
        match.span(),
        0.8 if channels else 0.6,
    )
    return [claim] if claim is not None else []


_CHILD_CONTEXT_RE = _alternation(
    ("child", "children", "minor", "minors", "parental", "guardian", "kids", "teen")
)
_AGE_THRESHOLD_RE = re.compile(
    r"\b(?:under|below|less than|younger than|beneath)\s+(?:the age of\s+)?(\d{1,2})\b"
    r"|\bage of\s+(\d{1,2})\b"
    r"|\b(\d{1,2})\s*(?:years?|yrs?)\s*(?:of age|old)\b",
    re.I,
)
_PARENTAL_CONSENT_RE = _alternation(
    (
        "verifiable parental consent", "verifiable consent of the parent",
        "parental consent", "consent of a parent", "consent of the parent",
        "consent of the lawful guardian", "guardian consent",
    )
)


def _children_claims(sentence: Sentence) -> list[PolicyClaim]:
    if not _CHILD_CONTEXT_RE.search(sentence.lowered):
        return []
    claims: list[PolicyClaim] = []

    for match in _AGE_THRESHOLD_RE.finditer(sentence.text):
        age = next((g for g in match.groups() if g), None)
        if age is None or not 1 <= int(age) <= 25:
            continue
        claim = _claim(
            "children", "age threshold", f"under {int(age)}", sentence, match.span(), 0.85
        )
        if claim is not None:
            claims.append(claim)

    parental = _PARENTAL_CONSENT_RE.search(sentence.lowered)
    if parental is not None and not is_denial(sentence.lowered, parental.start()):
        claim = _claim(
            "children",
            "parental consent",
            sentence.lowered[parental.start() : parental.end()].strip(),
            sentence,
            parental.span(),
            0.8,
        )
        if claim is not None:
            claims.append(claim)
    return claims


_SECURITY_CONTROLS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("AES-256", ("aes-256", "aes 256")),
    ("AES-128", ("aes-128", "aes 128")),
    ("TLS", ("tls 1.3", "tls 1.2", "tls", "transport layer security")),
    ("RSA-2048", ("rsa-2048", "rsa 2048")),
    ("SHA-256", ("sha-256", "sha 256")),
    ("password hashing", ("bcrypt", "argon2", "scrypt", "pbkdf2", "hashed and salted")),
    ("encryption at rest", ("encrypted at rest", "encryption at rest")),
    ("encryption in transit", ("encrypted in transit", "encryption in transit")),
    ("end-to-end encryption", ("end-to-end encryption", "end to end encryption")),
    ("multi-factor authentication", ("multi-factor authentication", "two-factor authentication", "2fa", "mfa")),
    ("ISO 27001", ("iso 27001", "iso/iec 27001")),
    ("SOC 2", ("soc 2", "soc2")),
    ("PCI DSS", ("pci dss", "pci-dss")),
    ("pseudonymisation", ("pseudonymise", "pseudonymize", "pseudonymised", "pseudonymized")),
    ("access control", ("role-based access", "access control", "least privilege")),
    ("audit logging", ("audit log", "audit logs", "audit trail")),
)
_SECURITY_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, _alternation(phrases)) for name, phrases in _SECURITY_CONTROLS
)


def _security_claims(sentence: Sentence) -> list[PolicyClaim]:
    claims: list[PolicyClaim] = []
    for name, pattern in _SECURITY_PATTERNS:
        match = pattern.search(sentence.lowered)
        if match is None or is_denial(sentence.lowered, match.start()):
            continue
        claim = _claim("security", "security control", name, sentence, match.span(), 0.75)
        if claim is not None:
            claims.append(claim)
    return claims


_BOARD_INTIMATION_RE = _alternation(
    (
        "notify the board", "inform the board", "intimate the board",
        "report to the board", "notify the data protection board",
        "inform the data protection board",
    )
)


def _breach_claims(sentence: Sentence) -> list[PolicyClaim]:
    if not _BREACH_CONTEXT_RE.search(sentence.lowered):
        return []
    claims: list[PolicyClaim] = []

    for match in _DURATION_RE.finditer(sentence.text):
        label = _duration_label(match.group(1), match.group(2))
        if label is None:
            continue
        claim = _claim(
            "breach", "notification timeline", label, sentence, match.span(), 0.8
        )
        if claim is not None:
            claims.append(claim)
        break

    board = _BOARD_INTIMATION_RE.search(sentence.lowered)
    if board is not None and not is_denial(sentence.lowered, board.start()):
        claim = _claim(
            "breach",
            "board intimation",
            "notifies the Data Protection Board",
            sentence,
            board.span(),
            0.8,
        )
        if claim is not None:
            claims.append(claim)
    return claims


_EXTRACTORS = (
    _retention_claims,
    _third_party_claims,
    _rights_claims,
    _cross_border_claims,
    _contact_claims,
    _children_claims,
    _security_claims,
    _breach_claims,
)


def extract_claims(documents: list[PolicyDocument]) -> list[PolicyClaim]:
    """Every assertion in the documents that a later stage could test.

    verified_by and verification are deliberately left None. None means nobody
    has looked, which is a different state from looked and found nothing, and
    collapsing the two would turn an unrun check into a clean result.
    """
    claims: list[PolicyClaim] = []
    seen: set[tuple[str, str, str | None, str]] = set()
    # One officer published once is one claim. The same title turning up again
    # with a route attached should sharpen the claim, not sit beside it.
    contacts: dict[tuple[str, str], PolicyClaim] = {}
    named_parties: dict[str, int] = {}

    for document in documents:
        if document.kind not in CLAIM_DOCUMENT_KINDS:
            continue
        for sentence in sentences_of(document):
            if sentence.shape == SHAPE_NAV:
                continue
            for extractor in _EXTRACTORS:
                for claim in extractor(sentence):
                    if claim.claim_type == "contact":
                        key2 = (claim.subject, claim.source_url)
                        held = contacts.get(key2)
                        if held is None:
                            contacts[key2] = claim
                            claims.append(claim)
                        elif held.value is None and claim.value is not None:
                            claims[claims.index(held)] = claim
                            contacts[key2] = claim
                        continue
                    key = (claim.claim_type, claim.subject, claim.value, claim.source_url)
                    if key in seen:
                        continue
                    if claim.subject == "named recipient":
                        count = named_parties.get(document.url, 0)
                        if count >= _MAX_NAMED_PARTIES:
                            continue
                        named_parties[document.url] = count + 1
                    seen.add(key)
                    claims.append(claim)
    return claims


# ---------------------------------------------------------------- the analysis


def missing_kinds(documents: list[PolicyDocument]) -> list[str]:
    """Expected policy kinds no readable document was found for.

    Readable rather than merely present, because the text is the point: a
    document that could not be opened tells us nothing the Act asks about. Which
    of the two happened is spelled out in the unassessed checks.
    """
    readable = {d.kind for d in documents if d.reachable and d.word_count > 0}
    return [k for k in EXPECTED_POLICY_KINDS if k not in readable]


def analyse(
    documents: list[PolicyDocument],
) -> tuple[list[PolicyRequirementCheck], list[PolicyClaim]]:
    """Read the documents against the checklist and pull out their claims.

    Satisfied checks are returned alongside the failures. A requirement the
    notice does meet is evidence in its own right: the aggregate should credit
    it, and a later stage that finds the implementation doing otherwise has a
    contradiction rather than a second opinion.
    """
    readable = [d for d in documents if d.reachable and d.word_count > 0]
    by_kind: dict[str, list[Sentence]] = {}
    for document in readable:
        by_kind.setdefault(document.kind, []).extend(sentences_of(document))

    checks: list[PolicyRequirementCheck] = []
    for requirement in REQUIREMENTS:
        applicable = [d for d in readable if d.kind in requirement.applies_to]
        if not applicable:
            checks.append(
                _unassessed(
                    requirement,
                    [d for d in documents if d.kind in requirement.applies_to],
                )
            )
            continue
        if not requirement.markers:
            checks.append(_plain_language_check(requirement, readable, by_kind))
            continue
        checks.append(_check_for(requirement, readable, by_kind))

    return checks, extract_claims(readable)
