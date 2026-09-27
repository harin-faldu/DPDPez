"""Tests for the deterministic DPDP rules engine.

The point of these tests is not coverage for its own sake. Every compliance
verdict this product reports has to be reproducible by hand from the evidence,
so the suite pins the three tier grading, the not_applicable behaviour that
keeps a web only scan from being marked down for what a crawl cannot see, and
the determinism of every checker.
"""

import pytest

from app.contracts import (
    CodeScanResult,
    ColumnInfo,
    ConsentBanner,
    ConsentElement,
    CookieInfo,
    DataFlowEdgeInfo,
    FileInfo,
    FormField,
    FormInfo,
    ModelInfo,
    NetworkRequest,
    NoticeInfo,
    PageInfo,
    PIIFieldRef,
    PIIFlowPathInfo,
    RouteInfo,
    ScriptInfo,
    SymbolInfo,
    WebScanResult,
)
from app.rules import engine, r04_consent, r06_security, r08_dpia

COMPLIANT = "compliant"
GAP = "gap"
VIOLATION = "violation"
NOT_APPLICABLE = "not_applicable"

NOTICE_BODY = (
    "This notice explains the purpose of every kind of processing we carry out. "
    "We process your data for account creation, for billing and payment, for "
    "marketing where you have opted in, and for analytics. We share delivery "
    "addresses with our logistics partners and with no other third parties. "
    "We retain your account data for 24 months after your last order and erase "
    "it at the end of that retention period. Questions about this notice go to "
    "our grievance officer, and if you are not satisfied you may make a "
    "complaint to the Data Protection Board of India."
)


# --------------------------------------------------------------- web fixtures


def build_web(
    *,
    pre_checked: bool = False,
    notice: bool = True,
    in_footer_only: bool = False,
    grievance: bool = True,
    trackers: bool = False,
    https: bool = True,
    headers: bool = True,
) -> WebScanResult:
    """A synthetic crawl of a compliant site, with the failure modes as switches."""
    marketing_optin = ConsentElement(
        field_name="consent_marketing",
        label_text="I agree to marketing email",
        pre_checked=pre_checked,
        near_submit=True,
    )
    consent_elements = [
        ConsentElement(
            field_name="consent_service",
            label_text="I agree to processing for account creation",
            pre_checked=False,
            near_submit=True,
        ),
        marketing_optin,
    ]
    aadhaar_field = FormField(
        name="aadhaar_number", input_type="text", label="Aadhaar number", required=True
    )
    signup = FormInfo(
        action="/signup",
        method="POST",
        fields=[
            FormField(name="email", input_type="email", label="Email", required=True),
            FormField(name="date_of_birth", input_type="date", label="Date of birth"),
            aadhaar_field,
        ],
        consent_elements=consent_elements,
        submits_over_https=https,
    )
    security_headers = (
        {
            "Strict-Transport-Security": "max-age=63072000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        if headers
        else {"X-Content-Type-Options": "nosniff"}
    )
    third_party_scripts = (
        [
            ScriptInfo(
                src="https://www.googletagmanager.com/gtag/js",
                domain="www.googletagmanager.com",
                is_third_party=True,
            )
        ]
        if trackers
        else []
    )
    # A compliant site still makes requests and still sets a cookie. The font
    # host receives an IP address, which is why it counts as a recipient the
    # notice has to disclose, but it does not profile the visitor.
    network_requests = [
        NetworkRequest(
            url="https://shop.example.in/api/cart",
            host="shop.example.in",
            resource_type="xhr",
            before_consent=True,
        ),
        NetworkRequest(
            url="https://cdn.example-static.in/fonts/inter.woff2",
            host="cdn.example-static.in",
            resource_type="font",
            is_third_party=True,
            before_consent=True,
        ),
    ]
    if trackers:
        network_requests.append(
            NetworkRequest(
                url="https://www.googletagmanager.com/gtag/js?id=G-1234",
                host="www.googletagmanager.com",
                resource_type="script",
                is_third_party=True,
                before_consent=True,
                tracker_category="tag_manager",
            )
        )
    cookies = [
        CookieInfo(
            name="sid",
            domain="shop.example.in",
            secure=True,
            http_only=True,
            same_site="Lax",
            set_before_consent=True,
            classification="necessary",
        ),
        CookieInfo(
            name="_shop_stats",
            domain=".shop.example.in",
            secure=True,
            http_only=False,
            same_site="Lax",
            set_before_consent=False,
            expiry_days=90.0,
            classification="analytics",
        ),
    ]
    return WebScanResult(
        entry_url="https://shop.example.in",
        pages=[
            PageInfo(
                url="https://shop.example.in",
                title="Example",
                status_code=200,
                text_content="Welcome",
            )
        ],
        forms=[signup],
        privacy_notice=(
            NoticeInfo(
                url="https://shop.example.in/privacy",
                link_text="Privacy Notice",
                in_footer_only=in_footer_only,
                reachable=True,
                body_text=NOTICE_BODY,
            )
            if notice
            else None
        ),
        security_headers=security_headers,
        third_party_scripts=third_party_scripts,
        cookies=cookies,
        age_gate_fields=[
            FormField(name="date_of_birth", input_type="date", label="Date of birth")
        ],
        rights_links=[
            "https://shop.example.in/rights/download-my-data",
            "https://shop.example.in/rights/correction",
            "https://shop.example.in/rights/erasure",
            "https://shop.example.in/rights/nomination",
            "https://shop.example.in/rights/withdraw-consent",
        ],
        grievance_contact="grievance@shop.example.in" if grievance else None,
        served_over_https=https,
        network_requests=network_requests,
        consent_banner=ConsentBanner(
            present=True,
            has_accept=True,
            has_reject=True,
            has_granular_options=True,
            has_manage_link=True,
            blocks_page_until_choice=True,
            accept_label="Accept all",
            reject_label="Reject all",
            selector="#consent-banner",
        ),
        dpo_contact="dpo@shop.example.in" if grievance else None,
        sensitive_fields=[aadhaar_field],
        marketing_optins=[marketing_optin],
    )


# -------------------------------------------------------------- code fixtures


def build_code(*, aadhaar_encrypted: bool = True, log_pii: bool = False) -> CodeScanResult:
    """A synthetic repository that satisfies every code side rule."""
    user = ModelInfo(
        class_name="User",
        table_name="users",
        file_path="app/models/user.py",
        line_number=12,
        columns=[
            ColumnInfo(name="email", column_type="String", line_number=15, is_encrypted=True),
            ColumnInfo(name="phone", column_type="String", line_number=16, is_encrypted=True),
            ColumnInfo(
                name="aadhaar_number",
                column_type="String",
                line_number=17,
                is_encrypted=aadhaar_encrypted,
            ),
            ColumnInfo(
                name="password_hash", column_type="String", line_number=18, is_hashed=True
            ),
            ColumnInfo(
                name="date_of_birth", column_type="Date", line_number=19, is_encrypted=True
            ),
            ColumnInfo(name="expires_at", column_type="DateTime", line_number=20),
        ],
    )
    consent_record = ModelInfo(
        class_name="ConsentRecord",
        table_name="consent_records",
        file_path="app/models/consent.py",
        line_number=10,
        columns=[
            ColumnInfo(name="user_id", column_type="UUID", line_number=12),
            ColumnInfo(name="purpose", column_type="String", line_number=13),
            ColumnInfo(name="consented_at", column_type="DateTime", line_number=14),
        ],
    )
    breach = ModelInfo(
        class_name="BreachIncident",
        table_name="breach_incidents",
        file_path="app/models/breach.py",
        line_number=8,
        columns=[
            ColumnInfo(name="detected_at", column_type="DateTime", line_number=10),
            ColumnInfo(name="notified_at", column_type="DateTime", line_number=11),
            ColumnInfo(name="summary", column_type="Text", line_number=12),
        ],
    )
    grievance = ModelInfo(
        class_name="Grievance",
        table_name="grievances",
        file_path="app/models/grievance.py",
        line_number=9,
        columns=[
            ColumnInfo(name="user_id", column_type="UUID", line_number=11),
            ColumnInfo(name="status", column_type="String", line_number=12),
            ColumnInfo(name="due_at", column_type="DateTime", line_number=13),
        ],
    )
    audit = ModelInfo(
        class_name="AuditLog",
        table_name="audit_logs",
        file_path="app/models/audit.py",
        line_number=7,
        columns=[
            ColumnInfo(name="actor_id", column_type="UUID", line_number=9),
            ColumnInfo(name="action", column_type="String", line_number=10),
            ColumnInfo(name="occurred_at", column_type="DateTime", line_number=11),
        ],
    )

    symbols = [
        SymbolInfo(
            name="hash_password",
            kind="function",
            file_path="app/security.py",
            line_number=20,
            source="return bcrypt.hashpw(raw.encode(), bcrypt.gensalt())",
        ),
        SymbolInfo(name="verify_age", kind="function", file_path="app/children.py", line_number=14),
        SymbolInfo(
            name="record_parental_consent",
            kind="function",
            file_path="app/children.py",
            line_number=30,
        ),
        SymbolInfo(
            name="withdraw_consent", kind="function", file_path="app/consent.py", line_number=40
        ),
        SymbolInfo(name="notify_board", kind="function", file_path="app/breach.py", line_number=25),
        SymbolInfo(
            name="notify_affected_principals",
            kind="function",
            file_path="app/breach.py",
            line_number=44,
        ),
        SymbolInfo(
            name="respond_to_board_direction",
            kind="function",
            file_path="app/board.py",
            line_number=10,
        ),
        SymbolInfo(
            name="export_audit_log", kind="function", file_path="app/audit.py", line_number=30
        ),
        SymbolInfo(
            name="purge_expired_records",
            kind="function",
            file_path="app/jobs/retention.py",
            line_number=18,
        ),
        SymbolInfo(
            name="RETENTION_DAYS", kind="constant", file_path="app/config.py", line_number=9
        ),
        # A code scan has to stand on its own: the DPO contact and the grievance
        # path cannot be borrowed from a web scan that is not part of this grade.
        SymbolInfo(
            name="DPO_CONTACT", kind="constant", file_path="app/config.py", line_number=11
        ),
        SymbolInfo(
            name="cascade_delete_user", kind="function", file_path="app/erasure.py", line_number=22
        ),
    ]

    routes = [
        RouteInfo(
            http_method="GET",
            path="/api/me/data",
            handler_name="export_my_data",
            file_path="app/api/rights.py",
            line_number=12,
            has_auth=True,
            framework="fastapi",
        ),
        RouteInfo(
            http_method="PATCH",
            path="/api/me/profile",
            handler_name="update_profile",
            file_path="app/api/rights.py",
            line_number=30,
            has_auth=True,
            framework="fastapi",
        ),
        RouteInfo(
            http_method="DELETE",
            path="/api/me",
            handler_name="delete_account",
            file_path="app/api/rights.py",
            line_number=48,
            has_auth=True,
            framework="fastapi",
        ),
        RouteInfo(
            http_method="POST",
            path="/api/nominee",
            handler_name="add_nominee",
            file_path="app/api/rights.py",
            line_number=66,
            has_auth=True,
            framework="fastapi",
        ),
        RouteInfo(
            http_method="POST",
            path="/api/grievance",
            handler_name="raise_grievance",
            file_path="app/api/grievance.py",
            line_number=14,
            has_auth=True,
            framework="fastapi",
        ),
    ]

    pii_fields = [
        PIIFieldRef(
            field_name="aadhaar_number",
            pii_category="aadhaar",
            sensitivity="critical",
            file_path="app/models/user.py",
            line_number=17,
            location_kind="db_column",
        ),
        PIIFieldRef(
            field_name="email",
            pii_category="email",
            sensitivity="medium",
            file_path="app/models/user.py",
            line_number=15,
            location_kind="db_column",
        ),
    ]

    edges = [
        DataFlowEdgeInfo(
            source_symbol="signup",
            source_file="app/api/signup.py",
            source_line=22,
            sink_symbol="User",
            sink_file="app/models/user.py",
            sink_line=12,
            edge_type="db_write",
            pii_categories=["email", "aadhaar"],
        )
    ]
    if log_pii:
        edges.append(
            DataFlowEdgeInfo(
                source_symbol="signup",
                source_file="app/api/signup.py",
                source_line=27,
                sink_symbol="logger.info",
                sink_file="app/api/signup.py",
                sink_line=27,
                edge_type="log_output",
                pii_categories=["aadhaar"],
            )
        )

    return CodeScanResult(
        root_path="/repo",
        files=[
            FileInfo(path="docs/dpia.md", language="markdown", line_count=120),
            FileInfo(path="docs/risk_register.md", language="markdown", line_count=80),
            FileInfo(path="docs/ropa.md", language="markdown", line_count=60),
            FileInfo(path="docs/compliance_audit.md", language="markdown", line_count=40),
            FileInfo(path="app/models/user.py", language="python", line_count=90),
        ],
        symbols=symbols,
        db_models=[user, consent_record, breach, grievance, audit],
        routes=routes,
        pii_fields=pii_fields,
        data_flow_edges=edges,
    )


def build_flows(
    *, consent: bool = True, encryption: bool = True, retention: bool = True
) -> list[PIIFlowPathInfo]:
    return [
        PIIFlowPathInfo(
            pii_category="aadhaar",
            source_description="signup form at app/api/signup.py:22",
            transforms=["validate_aadhaar", "encrypt_field"],
            sink_description="users.aadhaar_number at app/models/user.py:17",
            has_consent_check=consent,
            has_encryption=encryption,
            has_retention_policy=retention,
            crosses_third_party=False,
        ),
        PIIFlowPathInfo(
            pii_category="email",
            source_description="signup form at app/api/signup.py:22",
            transforms=["encrypt_field"],
            sink_description="users.email at app/models/user.py:15",
            has_consent_check=consent,
            has_encryption=encryption,
            has_retention_policy=retention,
            crosses_third_party=False,
        ),
    ]


def verdicts_by_id(verdicts) -> dict:
    return {verdict.rule_id: verdict for verdict in verdicts}


# A scan is a web scan or a code scan, never both, and each produces its own
# scorecard. These two builders keep every test on one side of that line.


def WEB_SCAN(**kwargs) -> dict:
    return {"web_result": build_web(**kwargs)}


def CODE_SCAN(**kwargs) -> dict:
    flow_kwargs = {k: kwargs.pop(k) for k in ("consent", "encryption", "retention") if k in kwargs}
    return {"code_result": build_code(**kwargs), "flows": build_flows(**flow_kwargs)}


# ------------------------------------------------------------ scoring helpers


def test_score_from_checks_is_a_plain_fraction():
    assert engine.score_from_checks(0, 4) == 0.0
    assert engine.score_from_checks(2, 4) == 0.5
    assert engine.score_from_checks(4, 4) == 1.0
    assert engine.score_from_checks(5, 6) == pytest.approx(5 / 6)


def test_score_from_checks_handles_an_empty_check_list():
    assert engine.score_from_checks(0, 0) == 0.0


def test_status_has_three_tiers_not_two():
    assert engine.status_from_score(1.0) == COMPLIANT
    assert engine.status_from_score(0.999) == GAP
    assert engine.status_from_score(5 / 6) == GAP
    assert engine.status_from_score(0.0001) == GAP
    assert engine.status_from_score(0.0) == VIOLATION


def test_status_constants_match_the_shared_enum():
    """The rules package restates the status strings so it stays ORM free."""
    enums = pytest.importorskip(
        "app.models.enums", reason="ORM dependencies are not installed in this environment"
    )
    assert engine.STATUS_COMPLIANT == enums.RuleStatus.COMPLIANT.value
    assert engine.STATUS_GAP == enums.RuleStatus.GAP.value
    assert engine.STATUS_VIOLATION == enums.RuleStatus.VIOLATION.value
    assert engine.STATUS_NOT_APPLICABLE == enums.RuleStatus.NOT_APPLICABLE.value


# ------------------------------------------------------------------- registry


def test_every_weighted_rule_has_a_checker():
    registered = [module.RULE_ID for module in engine.RULE_CHECKERS]
    assert len(registered) == 13
    assert sorted(registered) == sorted(engine.RULE_WEIGHTS)


def test_run_all_returns_one_verdict_per_checker():
    expected = [module.RULE_ID for module in engine.RULE_CHECKERS]
    for kwargs in (WEB_SCAN(), CODE_SCAN()):
        verdicts = engine.run_all(**kwargs)
        assert [verdict.rule_id for verdict in verdicts] == expected


def test_run_all_refuses_to_merge_a_web_scan_and_a_code_scan():
    """A scan is one kind or the other, and each gets its own grade.

    Merging them would produce a grade nobody's scan corresponds to, and the
    passes on the code side would mask the failures on the web side.
    """
    with pytest.raises(ValueError) as caught:
        engine.run_all(web_result=build_web(), code_result=build_code())
    assert "web scan or a code scan" in str(caught.value)

    # PII flow paths come out of the code scan, so they are code side evidence.
    with pytest.raises(ValueError):
        engine.run_all(web_result=build_web(), flows=build_flows())

    # An empty flow list is not evidence, so it is not a mixed scan.
    engine.run_all(web_result=build_web(), flows=[])


def test_retrieval_section_ids_are_pinned_to_real_provisions():
    """A finding must not be able to cite a provision the corpus does not hold."""
    act = pytest.importorskip("app.corpus.dpdp_act")
    rules = pytest.importorskip("app.corpus.dpdp_rules")
    known = {section.section_id for section in act.ACT_SECTIONS}
    known |= {rule.section_id for rule in rules.RULES}
    if not known:
        pytest.skip("statutory corpus is not populated yet")
    for module in engine.RULE_CHECKERS:
        assert module.RETRIEVAL_SECTION_IDS, f"{module.RULE_ID} pins no provisions"
        unknown = [
            section_id
            for section_id in module.RETRIEVAL_SECTION_IDS
            if section_id not in known
        ]
        assert not unknown, f"{module.RULE_ID} pins provisions absent from the corpus: {unknown}"


# ------------------------------------------------------------ the four verdicts


def test_pre_checked_consent_box_is_a_gap_not_a_violation():
    """s.6(1) consent must be free. A pre-ticked box is defective, not absent."""
    verdict = r04_consent.check(web_result=build_web(pre_checked=True))
    assert verdict.status == GAP
    assert verdict.status != VIOLATION
    # Pinned to the arithmetic rather than to a check count, so adding a check to
    # the rule cannot turn a correct verdict into a red test.
    assert verdict.score == pytest.approx(
        engine.score_from_checks(verdict.checks_passed, len(verdict.checks))
    )
    assert 0.0 < verdict.score < 1.0

    failed = verdict.failed_checks
    assert [check.name for check in failed] == ["no_pre_checked_consent"]
    assert "consent_marketing" in failed[0].detail
    assert "/signup" in failed[0].detail


def test_clean_consent_box_leaves_the_same_rule_compliant():
    verdict = r04_consent.check(web_result=build_web())
    assert verdict.status == COMPLIANT
    assert verdict.score == 1.0


def test_plaintext_aadhaar_column_is_a_violation_on_r6():
    """A national identifier in clear text is a bright line breach of s.8(5)."""
    verdict = r06_security.check(**CODE_SCAN(aadhaar_encrypted=False))
    assert verdict.status == VIOLATION
    assert verdict.bright_line_reason
    assert verdict.score <= engine.BRIGHT_LINE_SCORE_CEILING

    failed = [check for check in verdict.failed_checks if check.name == "pii_encrypted_at_rest"]
    assert failed, "the encryption check should be the one that failed"
    assert "aadhaar" in failed[0].detail.lower()
    assert "app/models/user.py:17" in failed[0].detail
    assert failed[0].file_path == "app/models/user.py"
    assert failed[0].line_number == 17
    assert "aadhaar" in verdict.evidence.lower()


def test_encrypted_aadhaar_column_is_compliant_on_r6():
    verdict = r06_security.check(**CODE_SCAN())
    assert verdict.status == COMPLIANT
    assert verdict.score == 1.0


def test_a_compliant_site_is_compliant_on_the_web_side_of_r6():
    verdict = r06_security.check(**WEB_SCAN())
    assert verdict.status == COMPLIANT
    assert [check.name for check in verdict.checks] == [
        "https_enforced",
        "security_headers_present",
        "cookies_carry_secure_flags",
        "sensitive_fields_collected_with_care",
    ]
    assert "No code scan was supplied" in verdict.evidence


def test_web_only_scan_is_not_applicable_on_r8_dpia():
    """A crawl cannot see a DPIA, so it must not be scored zero for one."""
    verdict = r08_dpia.check(web_result=build_web(), code_result=None, flows=[])
    assert verdict.status == NOT_APPLICABLE
    assert verdict.score is None
    assert verdict.checks == []
    assert "DPIA" in verdict.evidence or "assessment" in verdict.evidence.lower()


def test_web_only_scan_excludes_the_code_only_rules_from_scoring():
    verdicts = verdicts_by_id(engine.run_all(web_result=build_web()))
    for rule_id in ("R7", "R8", "R12", "RET"):
        assert verdicts[rule_id].status == NOT_APPLICABLE, rule_id
        assert verdicts[rule_id].score is None, rule_id
    # The rules a crawl can genuinely answer still get a real score.
    assert verdicts["R3"].score is not None
    assert verdicts["R10"].score is not None


def test_code_only_scan_is_not_applicable_on_r3_notice():
    verdict = verdicts_by_id(engine.run_all(code_result=build_code()))["R3"]
    assert verdict.status == NOT_APPLICABLE
    assert verdict.score is None


@pytest.mark.parametrize("scan", ("web", "code"))
def test_fully_compliant_input_is_compliant_on_every_rule_it_can_assess(scan):
    """Each scan kind stands on its own, so each has to grade cleanly on its own.

    A rule the other kind of scan would answer is not_applicable here rather
    than compliant, which is what keeps it out of the weighted average instead
    of inflating or deflating the grade.
    """
    verdicts = engine.run_all(**(WEB_SCAN() if scan == "web" else CODE_SCAN()))
    failing = {
        verdict.rule_id: verdict.evidence
        for verdict in verdicts
        if verdict.status not in (COMPLIANT, NOT_APPLICABLE)
    }
    assert not failing, f"expected no finding on a compliant {scan} scan, got {failing}"
    assert any(verdict.status == COMPLIANT for verdict in verdicts)
    for verdict in verdicts:
        assert verdict.score in (1.0, None), verdict.rule_id


def test_empty_evidence_is_not_applicable_everywhere_rather_than_zero():
    """No scan data at all must not be reported as total non-compliance."""
    verdicts = engine.run_all()
    assert all(verdict.status == NOT_APPLICABLE for verdict in verdicts)
    assert all(verdict.score is None for verdict in verdicts)


# ------------------------------------------------------------------ invariants


def test_status_always_matches_its_own_score():
    """A reviewer must be able to recompute any verdict from its check list."""
    for verdicts in (
        engine.run_all(**WEB_SCAN()),
        engine.run_all(**CODE_SCAN()),
        engine.run_all(
            **WEB_SCAN(pre_checked=True, notice=False, trackers=True, https=False)
        ),
        engine.run_all(
            **CODE_SCAN(
                aadhaar_encrypted=False,
                log_pii=True,
                consent=False,
                encryption=False,
                retention=False,
            )
        ),
    ):
        for verdict in verdicts:
            if verdict.score is None:
                assert verdict.status == NOT_APPLICABLE
                continue
            if verdict.bright_line_reason:
                # A bright line prohibition sets the status directly, so it no
                # longer follows from the score. The reason is recorded on the
                # verdict precisely so this stays checkable by hand.
                assert verdict.status == VIOLATION
                assert verdict.score <= engine.BRIGHT_LINE_SCORE_CEILING
                continue
            assert verdict.status == engine.status_from_score(verdict.score)


@pytest.mark.parametrize(
    "kwargs",
    (
        WEB_SCAN(pre_checked=True, in_footer_only=True, headers=False),
        CODE_SCAN(aadhaar_encrypted=False, log_pii=True, consent=False),
    ),
    ids=("web", "code"),
)
def test_every_check_carries_a_specific_detail_string(kwargs):
    verdicts = engine.run_all(**kwargs)
    for verdict in verdicts:
        for check in verdict.checks:
            assert check.detail.strip(), f"{verdict.rule_id}.{check.name} has no detail"
            assert len(check.detail) > 25, f"{verdict.rule_id}.{check.name} detail is too vague"
            assert check.name == check.name.lower()


def test_not_applicable_verdicts_never_carry_a_score():
    verdicts = engine.run_all(web_result=build_web())
    for verdict in verdicts:
        if verdict.status == NOT_APPLICABLE:
            assert verdict.score is None
            assert verdict.checks == []
        else:
            assert verdict.score is not None


@pytest.mark.parametrize(
    "kwargs", (WEB_SCAN(pre_checked=True), CODE_SCAN()), ids=("web", "code")
)
def test_scorecard_fields_line_up_with_the_checks(kwargs):
    verdicts = engine.run_all(**kwargs)
    for verdict in verdicts:
        if verdict.score is None:
            continue
        assert verdict.checks_passed == sum(1 for check in verdict.checks if check.passed)
        raw = engine.score_from_checks(verdict.checks_passed, len(verdict.checks))
        expected = (
            min(raw, engine.BRIGHT_LINE_SCORE_CEILING)
            if verdict.bright_line_reason
            else raw
        )
        assert verdict.score == pytest.approx(expected)


# ---------------------------------------------------------------- determinism


@pytest.mark.parametrize("scan", ("web", "code"))
@pytest.mark.parametrize(
    "checker", engine.RULE_CHECKERS, ids=[module.RULE_ID for module in engine.RULE_CHECKERS]
)
def test_each_checker_is_deterministic(checker, scan):
    """Same evidence in, same verdict out. This is the product's core claim."""
    kwargs = (
        WEB_SCAN(pre_checked=True, trackers=True)
        if scan == "web"
        else CODE_SCAN(aadhaar_encrypted=False, log_pii=True, consent=False, retention=False)
    )
    first = checker.check(**kwargs)
    second = checker.check(**kwargs)
    assert first == second
    assert first.status == second.status
    assert first.score == second.score
    assert first.evidence == second.evidence
    assert [check.detail for check in first.checks] == [
        check.detail for check in second.checks
    ]


@pytest.mark.parametrize(
    "checker", engine.RULE_CHECKERS, ids=[module.RULE_ID for module in engine.RULE_CHECKERS]
)
def test_each_checker_leaves_its_evidence_untouched(checker):
    """A pure function must not edit the scan results the other modules share."""
    web = build_web()
    code = build_code()
    flows = build_flows()

    checker.check(web_result=web)
    checker.check(code_result=code, flows=flows)

    assert web == build_web()
    assert code == build_code()
    assert flows == build_flows()


def test_run_all_is_deterministic_across_repeated_scans():
    for kwargs in (
        WEB_SCAN(pre_checked=True, in_footer_only=True, grievance=False),
        CODE_SCAN(aadhaar_encrypted=False, retention=False),
    ):
        assert engine.run_all(**kwargs) == engine.run_all(**kwargs)


def test_run_all_is_order_stable():
    for kwargs in (WEB_SCAN(), CODE_SCAN()):
        first = [verdict.rule_id for verdict in engine.run_all(**kwargs)]
        second = [verdict.rule_id for verdict in engine.run_all(**kwargs)]
        assert first == second


# ------------------------------------------------------- selected failure modes


def test_missing_notice_fails_r3_on_both_existence_and_timing():
    verdict = verdicts_by_id(engine.run_all(web_result=build_web(notice=False)))["R3"]
    failed = {check.name for check in verdict.failed_checks}
    assert "notice_exists_and_reachable" in failed
    assert "notice_before_collection" in failed
    assert verdict.status in (GAP, VIOLATION)


def test_footer_only_notice_is_a_gap_on_timing_alone():
    verdict = verdicts_by_id(engine.run_all(web_result=build_web(in_footer_only=True)))["R3"]
    assert verdict.status == GAP
    assert [check.name for check in verdict.failed_checks] == ["notice_before_collection"]
    assert "footer" in verdict.failed_checks[0].detail


def test_tracking_on_a_site_that_collects_age_is_a_violation_on_r5():
    """s.9(3) bans tracking of children outright, so it is not averaged away."""
    verdict = verdicts_by_id(engine.run_all(**WEB_SCAN(trackers=True)))["R5"]
    assert verdict.status == VIOLATION
    assert verdict.bright_line_reason
    assert verdict.score <= engine.BRIGHT_LINE_SCORE_CEILING
    assert verdict.checks_passed == 1, "the age gate check still passes on the evidence"
    assert [check.name for check in verdict.failed_checks] == ["no_child_tracking"]
    assert "googletagmanager" in verdict.failed_checks[0].detail


def test_no_retention_policy_on_any_flow_is_a_violation():
    verdicts = verdicts_by_id(engine.run_all(**CODE_SCAN(retention=False)))
    verdict = verdicts["RET"]
    assert verdict.status == VIOLATION
    assert verdict.bright_line_reason
    assert verdict.score <= engine.BRIGHT_LINE_SCORE_CEILING
    assert "indefinitely" in verdict.evidence


def test_plaintext_pii_in_logs_is_reported_with_its_call_site():
    verdict = r06_security.check(**CODE_SCAN(log_pii=True))
    failed = {check.name: check for check in verdict.failed_checks}
    assert "pii_not_logged_in_plaintext" in failed
    assert "app/api/signup.py:27" in failed["pii_not_logged_in_plaintext"].detail
    assert verdict.status == GAP


def test_sdf_rule_states_that_status_was_inferred():
    verdict = verdicts_by_id(engine.run_all(**CODE_SCAN()))["R9"]
    assert "inferred" in verdict.evidence
    assert "Central Government" in verdict.evidence


def test_sdf_rule_does_not_grade_the_audit_artefacts_off_a_web_scan():
    """A Data Auditor's report is internal, so a crawl cannot fail the site for it."""
    verdict = verdicts_by_id(engine.run_all(**WEB_SCAN()))["R9"]
    names = [check.name for check in verdict.checks]
    assert names == ["dpo_identified"]
    assert "No code scan was supplied" in verdict.evidence


def test_sdf_rule_is_not_applicable_without_scale_indicators():
    thin_code = CodeScanResult(root_path="/repo")
    verdict = verdicts_by_id(engine.run_all(code_result=thin_code))["R9"]
    assert verdict.status == NOT_APPLICABLE
    assert verdict.score is None
    assert "Central Government" in verdict.evidence
