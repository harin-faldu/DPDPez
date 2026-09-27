"""R5 Children's Data, DPDP Act s.9; Rule 5.  OWNER: Prerana"""

from app.contracts import (
    CodeScanResult,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "R5"
RULE_NAME = "Children's Data"
DPDP_SECTION = "s.9"
DPDP_RULE = "Rule 5"

# Pin retrieval for this rule so the AI layer cannot cite an unrelated provision.
# Verifiable parental consent is Rules 2025 rule_10, not rule_5, which covers
# processing by the State.
# rule_10 is verifiable parental consent; rule_12 lists the exemptions from
# it.
RETRIEVAL_SECTION_IDS: list[str] = ["s.9", "rule_10", "rule_12"]

_AGE_FIELD_KEYWORDS: tuple[str, ...] = (
    "age",
    "dob",
    "date_of_birth",
    "birth_date",
    "birthdate",
    "birth_year",
    "year_of_birth",
)

_AGE_LOGIC_KEYWORDS: tuple[str, ...] = (
    "verify_age",
    "check_age",
    "validate_age",
    "calculate_age",
    "age_check",
    "age_gate",
    "is_minor",
    "is_child",
    "is_adult",
    "under_18",
    "under_eighteen",
)

# parent_id is deliberately absent. It is a foreign key on a comment thread, a
# category tree or a task list far more often than it is anything to do with a
# parent as a person, and reading it as a parental consent record both invents
# a control the fiduciary does not have and drags the whole rule into scope on
# a service with no children anywhere near it. See evidence.TECHNICAL_AGE_TERMS.
_PARENTAL_KEYWORDS: tuple[str, ...] = (
    "parental_consent",
    "parent_consent",
    "guardian_consent",
    "guardian",
    "verifiable_consent",
    "parental_verification",
)

_ADULT_ONLY_KEYWORDS: tuple[str, ...] = (
    "adults_only",
    "adult_only",
    "require_adult",
    "enforce_adult",
    "reject_minor",
    "block_minor",
    "deny_minor",
)

_TRACKING_GATE_KEYWORDS: tuple[str, ...] = (
    "tracking_allowed",
    "can_track",
    "suppress_tracking",
    "disable_tracking",
    "child_safe_mode",
    "no_track_minor",
)

# Words in a page title that mean the audience is children. Read from the title
# only, never from a match anywhere on the page: "children" appears in the
# privacy policy of every general audience site in the country, usually in the
# sentence saying the service is not for them.
#
# "student", "school", "college", "university", "campus", "academy" and
# "admission" are deliberately absent. A student is not a child, higher
# education is an adult service, and a university that was graded in breach of
# s.9 for teaching people is the false positive this list exists to prevent.
_CHILD_AUDIENCE_TITLE_MARKERS: tuple[str, ...] = (
    "kids",
    "children",
    "childcare",
    "child care",
    "toddler",
    "preschool",
    "pre school",
    "playschool",
    "play school",
    "nursery",
    "kindergarten",
    "creche",
)

# Notice prose that describes taking a parent's consent for a child's data. A
# fiduciary that has built this has told you children are in scope.
_PARENTAL_NOTICE_MARKERS: tuple[str, ...] = (
    "verifiable parental consent",
    "verifiable consent of a parent",
    "parental consent",
    "guardian consent",
    "consent of a parent",
    "consent of the parent",
    "consent of a guardian",
    "consent of the guardian",
    "consent of the lawful guardian",
)

# The standard general audience disclaimer. It usually sits in the same
# paragraph as the words "parental consent", so without this the boilerplate
# sentence that says children are NOT users would be read as proof that they
# are. Where the notice says both, the disclaimer wins and the prose counts for
# nothing, because the affirmative wording is then plainly generic.
_NOT_FOR_CHILDREN_MARKERS: tuple[str, ...] = (
    "not knowingly collect",
    "do not knowingly",
    "does not knowingly",
    "not intended for children",
    "not intended for use by children",
    "not intended for minors",
    "not directed to children",
    "not directed at children",
    "not aimed at children",
    "is not for children",
)

# What the gate looks for, quoted in the evidence when none of it is found so a
# reviewer can see the method rather than take the conclusion on trust.
_SIGNALS_LOOKED_FOR: tuple[str, ...] = (
    "an age or date of birth field collected on the page",
    "an age or date of birth column in the repository",
    "age being evaluated anywhere in the code",
    "a parental or guardian consent mechanism, which would show the fiduciary "
    "knows children are users",
    "a children's section in the published privacy policy",
    "a page title indicating the service is aimed at children",
)


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> RuleVerdict:
    """Evaluate R5 and return a deterministic verdict.

    The rule is assessed only where a child directed signal exists. s.9(1)
    obligations bite "before processing any personal data of a child", so they
    are conditional on a child's data actually being processed, and Rules 2025
    rule 10 sets out verifiable parental consent for a child's personal data on
    the same footing. GDPR Article 8(1), the closest comparator, reaches
    information society services "offered directly to a child". So s.9 engages
    where the service is directed at children, or where the fiduciary collects
    data that would reveal the user is a child. Absent both, a general audience
    service is not in breach of s.9 for having no age gate, and grading a bike
    taxi booking site 0/2 on the children's provision is a finding that cannot
    be defended.

    The gate is not a free pass. A fiduciary cannot escape s.9 by declining to
    ask for age, so the outcome is not_applicable carrying an explicit stated
    assumption rather than compliant, and the score is None so the scorecard
    excludes the rule from the weighted average instead of awarding marks for
    it.

    Checks, once a signal is found:
      - an age gate or date of birth field exists
      - age is actually evaluated in code, not just collected
      - a verifiable parental consent path exists for under-18 users
      - no behavioural tracking or targeted advertising for users flagged as children

    Note: s.9 bans tracking and targeted advertising directed at children
    outright, not merely without consent, so the tracking check is a
    violation and not a gap when it fails. Return not_applicable only
    when the service is adult-only AND that is enforced in code, never
    just because a terms page says 18+.
    """
    flows = flows or []

    if web_result is None and code_result is None:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason="No web or code evidence was supplied.",
        )

    web_seen = ev.web_observable(web_result)
    crawl_blocked = ev.crawl_was_blocked(web_result)
    if crawl_blocked and code_result is None:
        # An age gate the crawler never reached looks exactly like no age gate,
        # and a tracker it never saw looks exactly like a clean site. Both would
        # be reported the wrong way round.
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=ev.crawl_blocked_reason(web_result),
        )

    age_logic = ev.find_symbols(code_result, _AGE_LOGIC_KEYWORDS, exclude_technical=True)
    adult_only = ev.find_symbols(code_result, _ADULT_ONLY_KEYWORDS, exclude_technical=True)
    if adult_only and age_logic:
        # Adult only is a defence only when the code turns minors away. A terms
        # page saying 18+ proves nothing, so both signals are required here.
        gate = adult_only[0]
        logic = age_logic[0]
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=(
                f"Service is adult only and enforces it in code: {gate.name} at "
                f"{ev.loc(gate.file_path, gate.line_number)} rejects minors and {logic.name} at "
                f"{ev.loc(logic.file_path, logic.line_number)} evaluates age, so the s.9 "
                "obligations towards children are not engaged."
            ),
        )

    checks: list[RuleCheck] = []
    notes: list[str] = []

    # A form field or column called max_age, parent_id or age_rating is a cache
    # directive, a foreign key and a content rating. None of them says anything
    # about how old a user is, so none of them may pull s.9 into scope.
    age_fields = [
        field
        for field in (web_result.age_gate_fields if web_seen else [])
        if not ev.is_technical_term(field.name)
    ]
    age_columns = ev.find_columns(code_result, _AGE_FIELD_KEYWORDS, exclude_technical=True)
    children_in_scope = bool(age_fields or age_columns)

    parental = _parental_evidence(code_result)
    signals = _child_directed_signals(
        web_result=web_result,
        web_seen=web_seen,
        age_fields=age_fields,
        age_columns=age_columns,
        age_logic=age_logic,
        parental=parental,
    )
    if not signals:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=_not_assessed_reason(web_result, web_seen, code_result),
        )

    observed = bool(age_fields or age_columns or age_logic or parental)
    if not observed:
        # The only thing putting this service in scope is wording on a page. It
        # is enough to assess the rule, and nowhere near enough to assert a
        # breach on, so the verdict carries the weakness of its own trigger.
        notes.append(
            f"The only child directed signal is read from published text ({signals[0]}) rather "
            "than from a field, a column or a code path, so this verdict requires human "
            "validation of the audience before it is relied on."
        )

    age_gate_check = _age_gate_check(age_fields, age_columns, web_result, crawl_blocked)
    if age_gate_check is not None:
        checks.append(age_gate_check)
    else:
        notes.append(
            "The crawl was blocked and the repository records no age or date of birth column, so "
            "whether an age gate exists could not be assessed either way."
        )

    if code_result is not None:
        checks.append(_age_logic_check(age_logic, children_in_scope))
        checks.append(_parental_consent_check(parental))
    else:
        notes.append(
            "No code scan was supplied, so whether age is evaluated and whether a verifiable "
            "parental consent path exists were not assessed."
        )

    tracking_check = _tracking_check(
        web_result, code_result, flows, age_logic, children_in_scope, crawl_blocked
    )
    if tracking_check is not None:
        checks.append(tracking_check)
    else:
        notes.append(
            "The crawl was blocked and no personal data flow was traced, so whether children are "
            "tracked could not be assessed and is excluded rather than reported as clean."
        )

    override = None
    if tracking_check is not None and not tracking_check.passed and children_in_scope:
        # s.9(3) is an outright prohibition on tracking children rather than a
        # duty to obtain consent first, so a breach is not offset by the other
        # checks passing. Restricted to services that actually collect age or
        # date of birth, because otherwise the scan cannot show a child is in
        # scope and calling it a violation would overstate the finding.
        override = (
            "s.9(3) prohibits behavioural tracking and targeted advertising directed at "
            "children outright, and this service collects age or date of birth while running "
            "tracking."
        )

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=checks,
        notes=notes,
        override_reason=override,
    )


def _child_directed_signals(
    *, web_result, web_seen, age_fields, age_columns, age_logic, parental
) -> list[str]:
    """Reasons to think s.9 is engaged at all, strongest evidence first.

    Two limbs, following s.9(1) read with rule 10 and GDPR Article 8(1): the
    fiduciary collects data that would reveal the user is a child, or the
    service is directed at children. A parental consent mechanism sits in the
    second limb, because building one is an admission that children are
    expected.
    """
    signals: list[str] = []
    if age_fields:
        field = age_fields[0]
        signals.append(f'the page collects "{field.name}", an age or date of birth field')
    if age_columns:
        model, column = age_columns[0]
        signals.append(
            f"the repository stores age or date of birth as {model.class_name}.{column.name}"
        )
    if age_logic:
        signals.append(f"the code evaluates a user's age in {age_logic[0].name}")
    if parental is not None:
        signals.append(f"a parental or guardian consent path exists, {parental[0]}")

    if not web_seen:
        return signals

    policy = ev.policy_document(web_result, "children")
    if policy is not None:
        signals.append(f"the site publishes a children's privacy policy at {policy.url}")
    title = _child_audience_title(web_result)
    if title is not None:
        signals.append(f'the page title "{title}" indicates the service is aimed at children')
    if _notice_describes_parental_consent(web_result):
        signals.append(
            "the privacy notice describes taking the consent of a parent or guardian for a "
            "child's personal data"
        )
    return signals


def _child_audience_title(web_result) -> str | None:
    """A page title that says the audience is children.

    Titles and nothing else. Scanning body text for "child" matches the privacy
    policy of every general audience site in the country, and usually matches
    the sentence saying the service is not for children, which is the inverse of
    the truth. A title is the one piece of page text a publisher writes to say
    what the page is.
    """
    for page in web_result.pages:
        if ev.matches(page.title, _CHILD_AUDIENCE_TITLE_MARKERS):
            return page.title
    return None


def _notice_describes_parental_consent(web_result) -> bool:
    """True where the notice describes parental consent and does not disclaim it."""
    body = ev.notice_text(web_result).lower()
    if not body:
        return False
    if any(marker in body for marker in _NOT_FOR_CHILDREN_MARKERS):
        return False
    return any(marker in body for marker in _PARENTAL_NOTICE_MARKERS)


def _not_assessed_reason(web_result, web_seen, code_result) -> str:
    """The stated assumption, in the words a reviewer has to be able to test."""
    if web_seen:
        where = web_result.entry_url
    elif code_result is not None:
        where = "the scanned repository"
    else:
        where = "the scanned surface"
    looked_for = "; ".join(_SIGNALS_LOOKED_FOR)
    return (
        f"Not assessed. No child directed signal was found on {where}. The scan looked for and "
        f"did not find: {looked_for}. s.9(1) bites before processing any personal data of a "
        "child, and Rules 2025 rule 10 sets out verifiable parental consent for a child's "
        "personal data on the same footing, so the obligation is conditional on a child's data "
        "actually being processed. Nothing observed here shows the service is offered to "
        "children or that it collects data capable of revealing a user is a child, so the "
        "absence of an age gate is not graded as a breach of s.9 and this rule is excluded "
        "from the score rather than marked zero. This result rests on a stated assumption: "
        "that the service is not offered to children. That is an assumption, not a finding of "
        "compliance. A Data Fiduciary that knows, or ought to know, that children use the "
        "service carries the full s.9 duties regardless, including verifiable parental consent "
        "under rule 10 and the s.9(3) prohibition on tracking, behavioural monitoring and "
        "targeted advertising directed at children, and cannot escape them by declining to ask "
        "for age. Confirm the intended audience with the fiduciary before relying on this "
        "result."
    )


def _age_gate_check(age_fields, age_columns, web_result, crawl_blocked) -> RuleCheck | None:
    if age_fields:
        field = age_fields[0]
        where = web_result.entry_url if web_result is not None else "the scanned site"
        return RuleCheck(
            name="age_gate_present",
            passed=True,
            detail=f'age gate field "{field.name}" of type {field.input_type} collected at {where}',
        )
    if crawl_blocked and not age_columns:
        # The crawl never loaded a form, so a missing age gate would be a finding
        # about the bot wall rather than about the site. A code scan that finds no
        # age column is different: that is real evidence, and it still reports.
        return None
    if age_columns:
        model, column = age_columns[0]
        # A code scan has no interface to look at, so it must not claim the age
        # gate was absent from one.
        interface = (
            "even though no age gate was seen in the interface"
            if web_result is not None and not crawl_blocked
            else "this scan covered the repository only, so whether an age gate is shown to the "
            "visitor was not observed"
        )
        return RuleCheck(
            name="age_gate_present",
            passed=True,
            detail=(
                f"age is recorded as {model.class_name}.{column.name} at "
                f"{ev.loc(model.file_path, column.line_number)}; {interface}"
            ),
            file_path=model.file_path,
            line_number=column.line_number,
        )
    where = (
        web_result.entry_url
        if web_result is not None and not crawl_blocked
        else "the scanned repository"
    )
    return RuleCheck(
        name="age_gate_present",
        passed=False,
        detail=(
            f"no age gate or date of birth field found at {where}, so the service cannot tell a "
            "child from an adult before collecting personal data"
        ),
    )


def _age_logic_check(age_logic, children_in_scope) -> RuleCheck:
    if age_logic:
        symbol = age_logic[0]
        return RuleCheck(
            name="age_evaluated_in_code",
            passed=True,
            detail=(
                f"age is evaluated by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )
    collected = "collected but" if children_in_scope else "not collected and"
    return RuleCheck(
        name="age_evaluated_in_code",
        passed=False,
        detail=(
            f"age is {collected} never evaluated in code; no age comparison, minor flag or age "
            "gate function was found, so the age field is stored rather than acted on"
        ),
    )


def _parental_evidence(code_result) -> tuple[str, str | None, int | None] | None:
    """Where verifiable parental consent is handled, if it is handled anywhere.

    Doubles as an applicability signal. A fiduciary that has built a parental
    consent path has told you it expects children to be users, so the rule is
    assessed on its own admission even where no age is collected.

    Technical terms are excluded, so a comment thread's parent_id and a category
    tree's parentNode stop reading as a consent record the fiduciary never built.
    """
    symbols = ev.find_symbols(code_result, _PARENTAL_KEYWORDS, exclude_technical=True)
    if symbols:
        symbol = symbols[0]
        return (
            f"verifiable parental consent handled by {symbol.name} at "
            f"{ev.loc(symbol.file_path, symbol.line_number)}",
            symbol.file_path,
            symbol.line_number,
        )
    models = ev.find_models(code_result, _PARENTAL_KEYWORDS, exclude_technical=True)
    if models:
        model = models[0]
        return (
            f"parental consent stored in {model.class_name} at "
            f"{ev.loc(model.file_path, model.line_number)}",
            model.file_path,
            model.line_number,
        )
    routes = ev.find_routes(code_result, _PARENTAL_KEYWORDS, exclude_technical=True)
    if routes:
        route = routes[0]
        return (
            f"parental consent endpoint {route.http_method} {route.path} at "
            f"{ev.loc(route.file_path, route.line_number)}",
            route.file_path,
            route.line_number,
        )
    return None


def _parental_consent_check(parental) -> RuleCheck:
    if parental is not None:
        detail, file_path, line_number = parental
        return RuleCheck(
            name="parental_consent_path",
            passed=True,
            detail=detail,
            file_path=file_path,
            line_number=line_number,
        )
    return RuleCheck(
        name="parental_consent_path",
        passed=False,
        detail=(
            "no parental or guardian consent handler, table or endpoint found; s.9(1) requires "
            "verifiable consent of a parent before processing a child's personal data"
        ),
    )


def _tracking_check(
    web_result, code_result, flows, age_logic, children_in_scope, crawl_blocked
) -> RuleCheck | None:
    scripts = ev.trackers(web_result)
    # Script tags are only part of the picture. A tag manager loads its payload
    # after the HTML is parsed, and pixels and beacons never appear as a script
    # element at all, so the network evidence is what actually shows profiling.
    requests = ev.behavioural_requests(web_result)
    third_party = ev.third_party_flows(flows)
    gate = ev.find_symbols(code_result, _TRACKING_GATE_KEYWORDS, exclude_technical=True)

    if crawl_blocked and not flows:
        # Nothing was observed that could show tracking either way, and "no
        # tracker found" off a blocked crawl is the false clean bill of health
        # this rule exists to avoid.
        return None

    if not scripts and not requests and not third_party:
        surface = (
            "in the traced data flows; the crawl was blocked, so the published pages were "
            "not examined"
            if crawl_blocked
            else "on the scanned surface"
        )
        return RuleCheck(
            name="no_child_tracking",
            passed=True,
            detail=(
                "no behavioural tracking or advertising script and no personal data flow to a "
                f"third party was found {surface}"
            ),
        )

    if gate and age_logic:
        symbol = gate[0]
        return RuleCheck(
            name="no_child_tracking",
            passed=True,
            detail=(
                f"tracking is gated on age by {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)}, with age evaluated by "
                f"{age_logic[0].name}"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )

    sources: list[str] = [script.domain for script in scripts]
    sources.extend(f"{request.host} ({request.tracker_category})" for request in requests)
    sources.extend(ev.flow_label(flow) for flow in third_party)
    if children_in_scope:
        detail = (
            f"behavioural tracking present ({ev.join_names(sources)}) on a service that collects "
            "age or date of birth, with no code path that suppresses tracking for users flagged "
            "as children"
        )
    else:
        detail = (
            f"behavioural tracking present ({ev.join_names(sources)}) with no age gate at all, so "
            "the fiduciary cannot establish that the user being tracked is not a child"
        )
    return RuleCheck(name="no_child_tracking", passed=False, detail=detail)
