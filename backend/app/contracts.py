"""Interface contracts between the four modules.

Every module codes against these dataclasses, not against each other's internals.
Scanner (Harin) produces ScanResult. Rules engine (Prerana) consumes it and
produces RuleResult. AI layer (Aryan) consumes RuleResult plus AnalysisContext.
Scorecard (Manan) consumes RuleResult.

Changing a field here breaks other people's code. Announce before editing.
"""

from dataclasses import dataclass, field

# ---------------------------------------------------------------- web scanner


@dataclass
class FormField:
    name: str
    input_type: str
    label: str | None = None
    required: bool = False
    autocomplete: str | None = None


@dataclass
class ConsentElement:
    field_name: str
    label_text: str
    pre_checked: bool
    near_submit: bool


@dataclass
class FormInfo:
    action: str
    method: str
    fields: list[FormField] = field(default_factory=list)
    consent_elements: list[ConsentElement] = field(default_factory=list)
    submits_over_https: bool = False


@dataclass
class NoticeInfo:
    url: str
    link_text: str
    in_footer_only: bool
    reachable: bool
    body_text: str | None = None


@dataclass
class ScriptInfo:
    src: str
    domain: str
    is_third_party: bool


@dataclass
class CookieInfo:
    name: str
    domain: str
    secure: bool
    http_only: bool
    same_site: str | None = None
    # A cookie written before the visitor did anything is, by definition, not
    # consented to. Everything else about a cookie is secondary to this.
    set_before_consent: bool = False
    is_third_party: bool = False
    expiry_days: float | None = None
    classification: str | None = None  # necessary|analytics|advertising|unknown
    # Written while the entry page loaded, then gone by the end of the crawl.
    # Typically a consent manager clearing what the first page set once it finds
    # no stored choice. It was still written before any choice was offered, so
    # it is a finding, but a materially weaker one than a cookie that persists.
    withdrawn_during_crawl: bool = False


@dataclass
class PayloadPII:
    """A category of personal data seen in a request body. Never the value.

    The raw value is deliberately absent and must stay absent. A tool that
    audits how personal data is handled cannot become another copy of that data,
    so a payload finding carries the category, how often it appeared, the
    parameter name it sat under and a redacted indicator, and nothing else.
    """

    pii_category: str
    sensitivity: str
    occurrences: int = 1
    # The parameter or JSON key the match sat under, sanitised. A key is a name,
    # not a value, so it is safe to keep and is what makes a finding actionable.
    field_hint: str | None = None
    detected_via: str = "value"  # value|field_name
    # Says a value was there and how long it was, never what it was.
    redacted: str = ""


@dataclass
class NetworkRequest:
    """One request the page made.

    Script tags miss most tracking. Beacons, XHR, pixel images and iframes all
    carry personal data off-site, and a tag manager loads its payload after the
    HTML is parsed, so only the network layer sees the full picture.
    """

    url: str
    host: str
    resource_type: str  # script|xhr|fetch|image|beacon|iframe|stylesheet|font|other
    method: str = "GET"
    is_third_party: bool = False
    before_consent: bool = False
    tracker_category: str | None = None  # analytics|advertising|social|replay|tag_manager
    # The host carries the entry site's brand under a different public suffix,
    # redacto.io against redacto.ai. Evidence of a probable common operator,
    # never proof of one, so the request stays third party and the rules layer
    # reports it as probable rather than folding it into the first party.
    shares_entry_brand: bool = False

    # --- CNAME cloaking -------------------------------------------------
    # A tracker served from a first party subdomain whose DNS chain ends at a
    # third party is first party in name only. Without the chain, the
    # registrable domain says example.com and the request disappears from the
    # third party and pre-consent evidence entirely.
    cname_chain: list[str] = field(default_factory=list)
    cname_cloaked: bool = False
    cname_target: str | None = None

    # --- request payload ------------------------------------------------
    # The body is read, classified and dropped. Only its size, the categories of
    # personal data found in it and the parameter names that shaped it are kept.
    payload_captured: bool = False
    payload_bytes: int = 0
    payload_pii: list[PayloadPII] = field(default_factory=list)
    # Which tracking parameter names the body carried, for example "tid, cid".
    payload_shape: str | None = None


@dataclass
class PolicyDocument:
    """A policy page, found by link or by probing a conventional path."""

    url: str
    kind: str  # privacy|terms|cookie|grievance|children|refund|security
    reachable: bool
    discovered_via: str  # link|well_known_path
    body_text: str | None = None
    word_count: int = 0
    linked_from_homepage: bool = False
    in_footer_only: bool = False
    # What the fetch actually returned. 404 and 410 say the document is not
    # published; 403, 429, a timeout or a client rendered shell say we could not
    # read one that may well exist. Both leave reachable False, and collapsing
    # them loses the difference between a finding and an absence of evidence.
    status_code: int = 0

    @property
    def definitively_absent(self) -> bool:
        """The server said this document does not exist."""
        return self.status_code in (404, 410)


@dataclass
class ConsentBanner:
    """A cookie or consent banner, and whether refusing is as easy as accepting."""

    present: bool = False
    has_accept: bool = False
    has_reject: bool = False
    has_granular_options: bool = False
    has_manage_link: bool = False
    blocks_page_until_choice: bool = False
    accept_label: str | None = None
    reject_label: str | None = None
    selector: str | None = None


@dataclass
class ServerSideTagEndpoint:
    """A first party endpoint that receives measurement traffic.

    Server-side tagging moves the onward hop off the page: the browser posts to
    the site's own domain and the site's server forwards to the analytics or
    advertising vendor. No browser based scanner can follow that hop, by design,
    which is exactly why it has to be disclosed rather than passed over. Silence
    would let the absence of a third party request read as a clean site.
    """

    host: str
    path: str
    url: str
    method: str
    resource_type: str
    matched_on: str  # path|payload|path and payload
    marker: str
    request_count: int = 1
    before_consent: bool = False
    payload_categories: list[str] = field(default_factory=list)


@dataclass
class PageInfo:
    url: str
    title: str
    status_code: int
    text_content: str = ""


@dataclass
class WebScanResult:
    entry_url: str
    pages: list[PageInfo] = field(default_factory=list)
    forms: list[FormInfo] = field(default_factory=list)
    privacy_notice: NoticeInfo | None = None
    security_headers: dict[str, str] = field(default_factory=dict)
    third_party_scripts: list[ScriptInfo] = field(default_factory=list)
    cookies: list[CookieInfo] = field(default_factory=list)
    age_gate_fields: list[FormField] = field(default_factory=list)
    rights_links: list[str] = field(default_factory=list)
    grievance_contact: str | None = None
    served_over_https: bool = False

    # --- expanded coverage ---------------------------------------------
    network_requests: list[NetworkRequest] = field(default_factory=list)
    policy_documents: list[PolicyDocument] = field(default_factory=list)
    consent_banner: ConsentBanner | None = None
    dpo_contact: str | None = None
    # Form fields that collect data the Act treats as needing extra care.
    sensitive_fields: list[FormField] = field(default_factory=list)
    # Marketing or newsletter opt-ins, which need their own consent under s.6.
    marketing_optins: list[ConsentElement] = field(default_factory=list)
    crawl_blocked: bool = False
    crawl_note: str | None = None
    # First party endpoints receiving measurement traffic they forward onward
    # from the server, where this scan can see the first hop and nothing after.
    server_side_tag_endpoints: list[ServerSideTagEndpoint] = field(default_factory=list)

    @property
    def trackers_before_consent(self) -> list[NetworkRequest]:
        """Third-party trackers that fired before the visitor chose anything.

        The single most load-bearing web signal under the Act: s.6(1) requires
        consent to precede processing, so a tracker that has already fired
        cannot have been consented to.
        """
        return [
            r
            for r in self.network_requests
            if r.before_consent and r.is_third_party and r.tracker_category
        ]

    @property
    def cookies_before_consent(self) -> list[CookieInfo]:
        return [c for c in self.cookies if c.set_before_consent]

    @property
    def third_party_hosts(self) -> list[str]:
        return sorted({r.host for r in self.network_requests if r.is_third_party})

    @property
    def cloaked_hosts(self) -> list[str]:
        """Hosts that are first party in name and resolve to a tracker.

        A request from one of these was reclassified as third party and carries
        the tracker's category, so it reaches the pre-consent and sharing
        evidence the way an openly third party request would.
        """
        return sorted({r.host for r in self.network_requests if r.cname_cloaked})

    @property
    def requests_with_payload_pii(self) -> list[NetworkRequest]:
        """Requests whose body carried a recognised category of personal data."""
        return [r for r in self.network_requests if r.payload_pii]

    def policy_of(self, kind: str) -> PolicyDocument | None:
        return next(
            (p for p in self.policy_documents if p.kind == kind and p.reachable), None
        )


# --------------------------------------------------------------- code scanner


@dataclass
class PIIFieldRef:
    field_name: str
    pii_category: str
    sensitivity: str
    file_path: str | None = None
    line_number: int | None = None
    location_kind: str | None = None
    context: str | None = None


@dataclass
class SymbolInfo:
    name: str
    kind: str
    file_path: str
    line_number: int
    end_line: int | None = None
    source: str | None = None


@dataclass
class ColumnInfo:
    name: str
    column_type: str
    line_number: int
    is_encrypted: bool = False
    is_hashed: bool = False
    has_expiry: bool = False


@dataclass
class ModelInfo:
    class_name: str
    table_name: str | None
    file_path: str
    line_number: int
    columns: list[ColumnInfo] = field(default_factory=list)


@dataclass
class RouteInfo:
    http_method: str
    path: str
    handler_name: str
    file_path: str
    line_number: int
    has_auth: bool = False
    framework: str | None = None


@dataclass
class DataFlowEdgeInfo:
    source_symbol: str
    source_file: str
    source_line: int
    sink_symbol: str
    sink_file: str
    sink_line: int
    edge_type: str
    pii_categories: list[str] = field(default_factory=list)


@dataclass
class FileInfo:
    path: str
    language: str
    line_count: int


@dataclass
class CodeScanResult:
    root_path: str
    files: list[FileInfo] = field(default_factory=list)
    symbols: list[SymbolInfo] = field(default_factory=list)
    db_models: list[ModelInfo] = field(default_factory=list)
    routes: list[RouteInfo] = field(default_factory=list)
    pii_fields: list[PIIFieldRef] = field(default_factory=list)
    data_flow_edges: list[DataFlowEdgeInfo] = field(default_factory=list)


# ------------------------------------------------------------- context engine


@dataclass
class PIIFlowPathInfo:
    pii_category: str
    source_description: str
    transforms: list[str] = field(default_factory=list)
    sink_description: str = ""
    has_consent_check: bool = False
    has_encryption: bool = False
    has_retention_policy: bool = False
    crosses_third_party: bool = False


@dataclass
class AnalysisContext:
    """What the AI layer receives. Never the whole codebase, only what is relevant."""

    focus_file: str | None = None
    focus_line: int | None = None
    code_snippet: str | None = None
    callers: list[SymbolInfo] = field(default_factory=list)
    callees: list[SymbolInfo] = field(default_factory=list)
    pii_flows: list[PIIFlowPathInfo] = field(default_factory=list)
    related_models: list[ModelInfo] = field(default_factory=list)
    related_routes: list[RouteInfo] = field(default_factory=list)
    web_evidence: dict[str, str] = field(default_factory=dict)

    def render(self) -> str:
        """Flatten into the text block that goes in the Gemini prompt."""
        parts: list[str] = []
        if self.focus_file:
            loc = self.focus_file
            if self.focus_line:
                loc = f"{loc}:{self.focus_line}"
            parts.append(f"LOCATION: {loc}")
        if self.code_snippet:
            parts.append(f"CODE:\n{self.code_snippet}")
        if self.callers:
            names = ", ".join(f"{c.name} ({c.file_path}:{c.line_number})" for c in self.callers)
            parts.append(f"CALLED BY: {names}")
        if self.callees:
            names = ", ".join(f"{c.name} ({c.file_path}:{c.line_number})" for c in self.callees)
            parts.append(f"CALLS INTO: {names}")
        for flow in self.pii_flows:
            chain = " -> ".join([flow.source_description, *flow.transforms, flow.sink_description])
            flags = []
            if not flow.has_consent_check:
                flags.append("no consent check")
            if not flow.has_encryption:
                flags.append("not encrypted")
            if not flow.has_retention_policy:
                flags.append("no retention policy")
            if flow.crosses_third_party:
                flags.append("reaches third party")
            suffix = f"  [{', '.join(flags)}]" if flags else ""
            parts.append(f"DATA FLOW ({flow.pii_category}): {chain}{suffix}")
        for key, value in self.web_evidence.items():
            parts.append(f"WEB EVIDENCE [{key}]: {value}")
        return "\n\n".join(parts) if parts else "No additional context available."


# --------------------------------------------------------------- rules engine


@dataclass
class RuleCheck:
    """One concrete yes/no check inside a rule. This is what makes a verdict auditable."""

    name: str
    passed: bool
    detail: str
    file_path: str | None = None
    line_number: int | None = None


@dataclass
class RuleVerdict:
    """Deterministic output of one rule checker. No AI involved in producing this."""

    rule_id: str
    rule_name: str
    status: str
    score: float | None
    evidence: str
    dpdp_section: str
    dpdp_rule: str
    checks: list[RuleCheck] = field(default_factory=list)
    # Set when a bright-line prohibition forced the status. Recorded rather than
    # implied, because with it the status no longer follows arithmetically from
    # the score, and a reviewer recomputing a verdict by hand needs to see why.
    bright_line_reason: str | None = None

    @property
    def checks_passed(self) -> int:
        return sum(1 for c in self.checks if c.passed)

    @property
    def failed_checks(self) -> list[RuleCheck]:
        return [c for c in self.checks if not c.passed]


# ------------------------------------------------------------------ RAG / AI


@dataclass
class RetrievedProvision:
    section_id: str
    citation_label: str
    section_title: str
    text: str
    similarity: float


@dataclass
class GroundedExplanation:
    """AI output. The verdict is NOT here, that comes from RuleVerdict."""

    title: str
    description: str
    citation: str
    citation_text: str
    cited_section_ids: list[str]
    suggested_fix: str
    data_flow_summary: str
    confidence: float
    guardrail_passed: bool = True
    guardrail_notes: str | None = None


# ------------------------------------------------------- stage 1: policy scan
#
# The policy stage runs first and alone. It reads what an organisation has
# published about itself and turns it into two things: gaps, where the Act
# requires the notice to say something it does not, and claims, where the notice
# asserts something testable.
#
# Claims are the reason the stages are ordered this way. A policy promising
# erasure within 90 days is a hypothesis. The web stage can see whether an
# erasure path is reachable, and the code stage can see whether anything
# actually deletes. A promise contradicted by the implementation is a stronger
# finding than either stage produces alone, and neither could reach it without
# the other's context.


@dataclass
class PolicyClaim:
    """An assertion the policy makes that a later stage can test."""

    claim_type: str  # retention|third_party|rights|cross_border|contact|security|children|breach|purpose
    subject: str
    # Normalised where it can be, for example "90 days" or "Google Analytics".
    value: str | None
    quote: str
    source_url: str
    confidence: float = 1.0

    # Filled in by a later stage. None means nobody has looked yet, which is
    # different from looked and found nothing.
    verified_by: str | None = None  # web|code
    verification: str | None = None  # supported|contradicted|not_observable
    verification_detail: str | None = None


@dataclass
class PolicyRequirementCheck:
    """One thing the Act or the Rules require a notice or policy to contain.

    Recorded whether or not it is satisfied. A satisfied requirement is evidence
    in its own right and belongs in the context, both because the aggregate
    grade should credit it and because a later stage may contradict it.
    """

    requirement_id: str
    title: str
    dpdp_section: str
    dpdp_rule: str
    satisfied: bool
    evidence: str
    # Nothing could be read, so the requirement was never tested. A third state,
    # not a shade of failure. Without it, satisfied=False carries both "the
    # notice does not say this" and "we could not open the notice", and a
    # blocked fetch publishes fifteen failures the site never earned.
    unassessed: bool = False
    quote: str | None = None
    source_url: str | None = None
    # Borrowed from the earlier ruleset: a hit read out of prose is weaker than
    # one read out of structure, and saying so beats asserting either way.
    requires_human_validation: bool = False
    confidence: float = 1.0


@dataclass
class PolicyScanResult:
    entry_url: str
    documents: list[PolicyDocument] = field(default_factory=list)
    checks: list[PolicyRequirementCheck] = field(default_factory=list)
    claims: list[PolicyClaim] = field(default_factory=list)
    # Policy kinds the Act expects and the scan could not find anywhere.
    missing_policies: list[str] = field(default_factory=list)
    crawl_blocked: bool = False
    crawl_note: str | None = None

    @property
    def satisfied_checks(self) -> list[PolicyRequirementCheck]:
        return [c for c in self.checks if c.satisfied and not c.unassessed]

    @property
    def failed_checks(self) -> list[PolicyRequirementCheck]:
        """Requirements the documents were read and found not to meet.

        Excludes the unassessed. A live scan of a site behind a bot wall
        reported fifteen failures against a notice nobody had managed to open,
        because this returned everything that was not satisfied.
        """
        return [c for c in self.checks if not c.satisfied and not c.unassessed]

    @property
    def unassessed_checks(self) -> list[PolicyRequirementCheck]:
        return [c for c in self.checks if c.unassessed]

    @property
    def readable_documents(self) -> list[PolicyDocument]:
        """Policies with enough text to have been analysed at all.

        A policy that exists but could not be read is not a policy that says
        nothing, and the two must not collapse into the same finding.
        """
        return [d for d in self.documents if d.reachable and d.word_count > 0]

    def claims_of(self, claim_type: str) -> list[PolicyClaim]:
        return [c for c in self.claims if c.claim_type == claim_type]

# ------------------------------------------- CERT-In Directions, 28 April 2022


@dataclass
class CertInHit:
    """One place in a checkout where a CERT-In obligation is decided.

    Carries a location and a description, never a value. A secret found in a
    repository is reported as present and redacted, because a compliance report
    that quotes the credential it found is a second copy of the leak.
    """

    file_path: str
    line_number: int
    detail: str
    value: str = ""


@dataclass
class CertInEvidence:
    """Infrastructure facts the Directions turn on.

    Gathered from Dockerfiles, Terraform, Helm, CI config and logging setup:
    files the AST scanner never opens, which is why a tool that reads only
    application source cannot assess any of this.
    """

    ntp_servers: list[CertInHit] = field(default_factory=list)
    uses_approved_ntp: bool = False
    log_retention: list[CertInHit] = field(default_factory=list)
    storage_regions: list[CertInHit] = field(default_factory=list)
    has_indian_region: bool = False
    logging_frameworks: list[CertInHit] = field(default_factory=list)
    alert_sinks: list[CertInHit] = field(default_factory=list)
    swallowed_errors: list[CertInHit] = field(default_factory=list)
    hardcoded_secrets: list[CertInHit] = field(default_factory=list)
    weak_tls: list[CertInHit] = field(default_factory=list)
    credentials_logged: list[CertInHit] = field(default_factory=list)
    files_examined: int = 0

    @property
    def examined(self) -> bool:
        """Whether anything was read. Nothing read is not a clean result."""
        return self.files_examined > 0

    def shortest_retention(self) -> CertInHit | None:
        numeric = [h for h in self.log_retention if h.value.isdigit()]
        return min(numeric, key=lambda h: int(h.value)) if numeric else None

    def foreign_regions(self) -> list[CertInHit]:
        from app.scanner.certin_scanner import INDIAN_REGIONS

        return [
            h
            for h in self.storage_regions
            if not any(r in h.value for r in INDIAN_REGIONS)
        ]
