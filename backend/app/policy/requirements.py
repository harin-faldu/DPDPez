"""What the Act and the Rules require a published notice or policy to contain.

This is the checklist the policy stage reads a site's own documents against. It
is deliberately about what the notice SAYS, not about what the system does. A
notice promising erasure is a claim; whether anything deletes is the code
stage's question, and the two disagreeing is the finding neither reaches alone.

Every requirement cites a provision that exists in the corpus, so a finding can
always be grounded. A test enforces that, because a citation to a provision we
do not hold is a citation nobody can check.

Cross-border transfer is cited to rule 15 rather than s.16 because the corpus
holds the notified Rules in full but not that section of the Act. The rule is
the operative text for what a notice must disclose, so nothing is lost.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyRequirement:
    requirement_id: str
    title: str
    dpdp_section: str
    dpdp_rule: str
    # Corpus ids the AI layer may cite for this requirement, same contract as
    # RETRIEVAL_SECTION_IDS on the rule checkers.
    retrieval_section_ids: tuple[str, ...]
    # Which policy kinds may satisfy it. A retention promise in a cookie notice
    # counts; a grievance contact buried in terms of service does not.
    applies_to: tuple[str, ...]
    # Phrases that evidence the requirement is addressed. Presence is necessary
    # and never sufficient: the analyser still has to find them in a sentence
    # that asserts rather than denies.
    markers: tuple[str, ...]
    # What to tell the reader when it is absent.
    absence_detail: str
    # True where prose alone is weak evidence and a human should confirm.
    needs_human_check: bool = False


NOTICE = "privacy"
COOKIE = "cookie"
GRIEVANCE = "grievance"
CHILDREN = "children"
TERMS = "terms"

REQUIREMENTS: tuple[PolicyRequirement, ...] = (
    PolicyRequirement(
        requirement_id="notice.itemised_data",
        title="Itemised description of the personal data collected",
        dpdp_section="s.5(1)",
        dpdp_rule="Rule 3",
        retrieval_section_ids=("s.5", "rule_3"),
        applies_to=(NOTICE,),
        markers=(
            "personal data we collect", "information we collect", "data we collect",
            "categories of personal data", "types of personal data", "what we collect",
            "personal data collected", "details we collect",
        ),
        absence_detail=(
            "the notice does not itemise the personal data collected; rule 3(b)(i) "
            "requires an itemised description rather than a general statement"
        ),
    ),
    PolicyRequirement(
        requirement_id="notice.specified_purpose",
        title="The specified purpose of processing, with the goods or services enabled",
        dpdp_section="s.5(1)",
        dpdp_rule="Rule 3",
        retrieval_section_ids=("s.5", "rule_3", "s.6"),
        applies_to=(NOTICE,),
        markers=(
            "purpose", "why we collect", "how we use", "we use your", "used for",
            "processing is necessary for",
        ),
        absence_detail=(
            "the notice states no specified purpose; consent under s.6(1) must be "
            "specific, which it cannot be if the purpose is never named"
        ),
    ),
    PolicyRequirement(
        requirement_id="notice.withdraw_consent",
        title="How to withdraw consent, as easily as it was given",
        dpdp_section="s.6(4)",
        dpdp_rule="Rule 3",
        retrieval_section_ids=("s.6", "rule_3"),
        applies_to=(NOTICE, COOKIE),
        markers=(
            "withdraw your consent", "withdraw consent", "revoke consent",
            "withdrawal of consent", "opt out", "opt-out", "manage preferences",
            "change your preferences",
        ),
        absence_detail=(
            "the notice does not say how to withdraw consent; s.6(4) requires "
            "withdrawal to be as easy as giving it was"
        ),
    ),
    PolicyRequirement(
        requirement_id="notice.exercise_rights",
        title="How to exercise Data Principal rights",
        dpdp_section="s.11 to s.14",
        dpdp_rule="Rule 14",
        retrieval_section_ids=("s.11", "s.12", "s.13", "s.14", "rule_14"),
        applies_to=(NOTICE,),
        markers=(
            "your rights", "rights as a data principal", "data principal rights",
            "right to access", "right to correction", "right to erasure",
            "exercise your rights", "request a copy",
        ),
        absence_detail=(
            "the notice does not explain how to exercise rights; rule 14 sets the "
            "procedure a Data Fiduciary must publish"
        ),
    ),
    PolicyRequirement(
        requirement_id="notice.complain_to_board",
        title="How to complain to the Data Protection Board",
        dpdp_section="s.13",
        dpdp_rule="Rule 3",
        retrieval_section_ids=("s.13", "s.27", "rule_3"),
        applies_to=(NOTICE, GRIEVANCE),
        markers=(
            "data protection board", "complain to the board", "the board",
            "file a complaint with", "escalate to the board",
        ),
        absence_detail=(
            "the notice gives no route to the Data Protection Board; rule 3(c)(iii) "
            "requires the means of making a complaint to be stated"
        ),
    ),
    PolicyRequirement(
        requirement_id="notice.contact_point",
        title="Contact details of the person who answers questions about processing",
        dpdp_section="s.5(1)",
        dpdp_rule="Rule 9",
        retrieval_section_ids=("rule_9", "s.5"),
        applies_to=(NOTICE, GRIEVANCE),
        markers=(
            "data protection officer", "grievance officer", "nodal officer",
            "contact us at", "privacy officer", "dpo", "write to us at",
        ),
        absence_detail=(
            "no contact point is published for questions about processing; rule 9 "
            "requires the business contact information to be displayed"
        ),
    ),
    PolicyRequirement(
        requirement_id="notice.retention_period",
        title="How long personal data is kept",
        dpdp_section="s.8(7)",
        dpdp_rule="Rule 8",
        retrieval_section_ids=("s.8(7)", "rule_8"),
        applies_to=(NOTICE,),
        markers=(
            "retention", "retain", "how long we keep", "storage period",
            "keep your data for", "retention period", "erase",
        ),
        absence_detail=(
            "the notice states no retention period; s.8(7) requires erasure once "
            "the purpose is no longer served, which presupposes a stated period"
        ),
    ),
    PolicyRequirement(
        requirement_id="notice.third_party_sharing",
        title="Who personal data is shared with",
        dpdp_section="s.8(2)",
        dpdp_rule="Rule 3",
        retrieval_section_ids=("s.8(2)", "rule_3"),
        applies_to=(NOTICE,),
        markers=(
            "share your", "we share", "third part", "service providers",
            "processors", "disclose", "vendors", "partners",
        ),
        absence_detail=(
            "the notice does not say who personal data is shared with, so a Data "
            "Principal cannot know who holds it"
        ),
    ),
    PolicyRequirement(
        requirement_id="notice.cross_border",
        title="Whether personal data is transferred outside India",
        dpdp_section="s.16",
        dpdp_rule="Rule 15",
        retrieval_section_ids=("rule_15",),
        applies_to=(NOTICE,),
        markers=(
            "outside india", "transfer abroad", "international transfer",
            "cross-border", "cross border", "outside the territory of india",
            "stored outside", "servers located",
        ),
        absence_detail=(
            "the notice is silent on transfer outside India; rule 15 governs such "
            "transfers and a Data Principal cannot assess them from this notice"
        ),
        needs_human_check=True,
    ),
    PolicyRequirement(
        requirement_id="notice.security_measures",
        title="The security safeguards applied to personal data",
        dpdp_section="s.8(5)",
        dpdp_rule="Rule 6",
        retrieval_section_ids=("s.8(5)", "rule_6"),
        applies_to=(NOTICE,),
        markers=(
            "security measures", "safeguards", "encryption", "encrypted",
            "protect your", "security practices", "technical and organisational",
        ),
        absence_detail=(
            "the notice describes no security safeguards, though s.8(5) requires "
            "reasonable safeguards to be taken"
        ),
    ),
    PolicyRequirement(
        requirement_id="notice.breach_intimation",
        title="What happens on a personal data breach",
        dpdp_section="s.8(6)",
        dpdp_rule="Rule 7",
        retrieval_section_ids=("s.8(6)", "rule_7"),
        applies_to=(NOTICE,),
        markers=(
            "data breach", "security incident", "breach notification",
            "notify you", "inform you of any breach", "personal data breach",
        ),
        absence_detail=(
            "the notice does not say what happens on a breach; s.8(6) requires "
            "intimation to affected Data Principals and to the Board"
        ),
    ),
    PolicyRequirement(
        requirement_id="notice.children",
        title="How children's personal data is handled",
        dpdp_section="s.9",
        dpdp_rule="Rule 10",
        retrieval_section_ids=("s.9", "rule_10"),
        applies_to=(NOTICE, CHILDREN),
        markers=(
            "children", "child", "under 18", "under the age of 18", "minor",
            "parental consent", "guardian",
        ),
        absence_detail=(
            "the notice does not address children's data; s.9 requires verifiable "
            "parental consent before processing a child's personal data"
        ),
        needs_human_check=True,
    ),
    PolicyRequirement(
        requirement_id="notice.grievance_mechanism",
        title="A grievance redressal mechanism with a route and a timeline",
        dpdp_section="s.13",
        dpdp_rule="Rule 14",
        retrieval_section_ids=("s.13", "rule_14"),
        applies_to=(NOTICE, GRIEVANCE),
        markers=(
            "grievance", "complaint", "raise a concern", "redressal",
            "respond within", "resolution time",
        ),
        absence_detail=(
            "no grievance redressal route is published; s.13 gives the Data "
            "Principal a right to it before approaching the Board"
        ),
    ),
    PolicyRequirement(
        requirement_id="notice.consent_manager",
        title="Whether consent is managed through a registered Consent Manager",
        dpdp_section="s.6(7)",
        dpdp_rule="Rule 4",
        retrieval_section_ids=("s.6", "rule_4"),
        applies_to=(NOTICE, COOKIE),
        markers=("consent manager", "consent management", "registered with the board"),
        absence_detail=(
            "the notice does not mention a Consent Manager; rule 4 provides for "
            "consent to be given through one, which is optional rather than required"
        ),
        needs_human_check=True,
    ),
    PolicyRequirement(
        requirement_id="notice.plain_language",
        title="The notice is available in clear and plain language",
        dpdp_section="s.5(3)",
        dpdp_rule="Rule 3",
        retrieval_section_ids=("s.5", "rule_3"),
        applies_to=(NOTICE,),
        markers=(),  # judged by readability, not by phrase matching
        absence_detail=(
            "the notice is not in clear and plain language; rule 3(b) requires a "
            "fair account a Data Principal can act on"
        ),
        needs_human_check=True,
    ),
)

# Policy kinds the Act expects a Data Fiduciary to publish. A missing privacy
# notice is a different order of finding from a missing refund policy, so only
# the ones with a statutory basis are listed.
EXPECTED_POLICY_KINDS: tuple[str, ...] = (NOTICE, COOKIE, GRIEVANCE)


def requirements_for(kind: str) -> tuple[PolicyRequirement, ...]:
    return tuple(r for r in REQUIREMENTS if kind in r.applies_to)


def by_id(requirement_id: str) -> PolicyRequirement | None:
    return next((r for r in REQUIREMENTS if r.requirement_id == requirement_id), None)
