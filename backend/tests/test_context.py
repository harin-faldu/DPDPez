"""Tests for the context engine: code graph, PII flow tracer, assembler.

Every fixture here is synthetic. The scanner is built by someone else and these
tests must stay green whether or not it is finished, so CodeScanResult objects
are hand built rather than produced by a scan.
"""

import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:  # allows `pytest` as well as `python -m pytest`
    sys.path.insert(0, str(BACKEND_ROOT))

from app.context.assembler import MAX_SNIPPET_LINES, assemble_for_verdict
from app.context.code_graph import CodeGraph
from app.context.pii_flow import (
    EDGE_API_SEND,
    EDGE_DB_WRITE,
    EDGE_LOG_OUTPUT,
    trace_flows,
)
from app.contracts import (
    AnalysisContext,
    CodeScanResult,
    ColumnInfo,
    ConsentElement,
    DataFlowEdgeInfo,
    FormField,
    FormInfo,
    ModelInfo,
    PIIFieldRef,
    RouteInfo,
    RuleCheck,
    RuleVerdict,
    SymbolInfo,
    WebScanResult,
)

ROUTES = "app/routes/signup.py"
SERVICE = "app/services/user_service.py"
CRYPTO = "app/utils/crypto.py"
MODELS = "app/models/user.py"


# ------------------------------------------------------------------ builders


def symbol(name, file_path, line, end=None, kind="function", source=None):
    return SymbolInfo(
        name=name,
        kind=kind,
        file_path=file_path,
        line_number=line,
        end_line=end if end is not None else line + 10,
        source=source,
    )


def edge(src_name, src_file, src_line, sink_name, sink_file, sink_line, edge_type, categories=None):
    return DataFlowEdgeInfo(
        source_symbol=src_name,
        source_file=src_file,
        source_line=src_line,
        sink_symbol=sink_name,
        sink_file=sink_file,
        sink_line=sink_line,
        edge_type=edge_type,
        pii_categories=list(categories or []),
    )


def pii(name, category, file_path, line, sensitivity="high"):
    return PIIFieldRef(
        field_name=name,
        pii_category=category,
        sensitivity=sensitivity,
        file_path=file_path,
        line_number=line,
        location_kind="variable",
    )


def scan(symbols=None, edges=None, fields=None, models=None, routes=None, root="/tmp/synthetic"):
    return CodeScanResult(
        root_path=root,
        symbols=list(symbols or []),
        data_flow_edges=list(edges or []),
        pii_fields=list(fields or []),
        db_models=list(models or []),
        routes=list(routes or []),
    )


def verdict(checks, rule_id="R6", rule_name="Reasonable Security Safeguards"):
    return RuleVerdict(
        rule_id=rule_id,
        rule_name=rule_name,
        status="violation",
        score=0.0,
        evidence="synthetic verdict",
        dpdp_section="s.8(5)",
        dpdp_rule="Rule 6",
        checks=list(checks),
    )


# ----------------------------------------------------------------- CodeGraph


def test_two_hop_caller_chain_resolves():
    signup = symbol("signup", ROUTES, 10, 40)
    create_user = symbol("create_user", SERVICE, 5, 30)
    store_user = symbol("store_user", SERVICE, 32, 50)
    result = scan(
        symbols=[signup, create_user, store_user],
        edges=[
            edge("signup", ROUTES, 14, "create_user", SERVICE, 5, "calls"),
            edge("create_user", SERVICE, 20, "store_user", SERVICE, 32, "data_pass"),
        ],
    )
    graph = CodeGraph(result)

    two_hops = [s.name for s in graph.callers_of(store_user, hops=2)]
    assert two_hops == ["create_user", "signup"]

    one_hop = [s.name for s in graph.callers_of(store_user, hops=1)]
    assert one_hop == ["create_user"]

    downstream = [s.name for s in graph.callees_of(signup, hops=2)]
    assert downstream == ["create_user", "store_user"]


def test_cyclic_graph_terminates():
    a = symbol("handle_request", ROUTES, 1, 20)
    b = symbol("normalise", SERVICE, 1, 20)
    c = symbol("retry", SERVICE, 21, 40)
    result = scan(
        symbols=[a, b, c],
        edges=[
            edge("handle_request", ROUTES, 5, "normalise", SERVICE, 1, "calls"),
            edge("normalise", SERVICE, 8, "retry", SERVICE, 21, "calls"),
            edge("retry", SERVICE, 30, "handle_request", ROUTES, 1, "calls"),
            # Direct self recursion on top of the cycle.
            edge("retry", SERVICE, 35, "retry", SERVICE, 21, "calls"),
        ],
    )
    graph = CodeGraph(result)

    # Reaching these assertions at all is the result being tested: an unbounded
    # walk over this graph would never return.
    assert {s.name for s in graph.callees_of(a, hops=2)} == {"normalise", "retry"}
    assert {s.name for s in graph.callers_of(a, hops=5)} == {"retry", "normalise"}
    assert graph.callees_of(a, hops=0) == []


def test_symbol_at_picks_innermost_symbol():
    outer = symbol("handler", ROUTES, 10, 60)
    inner = symbol("validate", ROUTES, 20, 30)
    graph = CodeGraph(scan(symbols=[outer, inner]))

    assert graph.symbol_at(ROUTES, 25).name == "validate"
    assert graph.symbol_at(ROUTES, 50).name == "handler"
    assert graph.symbol_at(ROUTES, 5) is None
    assert graph.symbol_at(SERVICE, 25) is None


def test_graph_tolerates_empty_and_unindexed_nodes():
    graph = CodeGraph(scan())
    assert graph.symbol_at(ROUTES, 1) is None
    assert graph.callers_of(symbol("ghost", ROUTES, 1)) == []

    caller = symbol("signup", ROUTES, 10, 40)
    with_sink = CodeGraph(
        scan(
            symbols=[caller],
            edges=[
                edge("signup", ROUTES, 18, "logger.info", ROUTES, 18, EDGE_LOG_OUTPUT)
            ],
        )
    )
    reached = with_sink.callees_of(caller, hops=1)
    assert [s.name for s in reached] == ["logger.info"]
    # The logger was never indexed as a symbol but still belongs in the context.
    assert reached[0].kind == "external"


# ------------------------------------------------------------------- flows


def log_output_scan():
    signup = symbol("signup", ROUTES, 10, 40)
    audit = symbol("write_line", "app/utils/audit.py", 5, 12)
    return scan(
        symbols=[signup, audit],
        fields=[pii("email", "email", ROUTES, 12)],
        edges=[
            edge(
                "signup",
                ROUTES,
                15,
                "write_line",
                "app/utils/audit.py",
                5,
                "data_pass",
                ["email"],
            ),
            edge(
                "write_line",
                "app/utils/audit.py",
                7,
                "logger.info",
                "app/utils/audit.py",
                7,
                EDGE_LOG_OUTPUT,
                ["email"],
            ),
        ],
    )


def test_log_output_flow_is_not_encrypted():
    result = log_output_scan()
    flows = trace_flows(result, CodeGraph(result))

    assert len(flows) == 1
    flow = flows[0]
    assert flow.pii_category == "email"
    assert flow.source_description == f"email in signup at {ROUTES}:12"
    assert flow.transforms == ["passed to write_line in app/utils/audit.py:5"]
    assert flow.sink_description == "logged by logger.info at app/utils/audit.py:7"
    assert flow.has_encryption is False
    assert flow.has_consent_check is False
    assert flow.has_retention_policy is False
    assert flow.crosses_third_party is False


def test_field_with_no_sink_still_yields_a_path():
    orphan = symbol("collect_profile", SERVICE, 100, 120)
    result = scan(
        symbols=[orphan],
        fields=[pii("phone", "phone", SERVICE, 105)],
    )
    flows = trace_flows(result, CodeGraph(result))

    assert len(flows) == 1
    flow = flows[0]
    assert flow.pii_category == "phone"
    assert flow.source_description == f"phone in collect_profile at {SERVICE}:105"
    assert flow.sink_description == ""
    assert flow.transforms == []
    assert flow.has_encryption is False
    # Unused collection is a purpose-limitation finding, so it must not be dropped.
    assert "phone" in flow.source_description


def test_db_write_reads_encryption_and_expiry_off_the_column():
    signup = symbol("signup", ROUTES, 10, 40)
    hasher = symbol("hash_value", CRYPTO, 30, 40)
    user_model = ModelInfo(
        class_name="User",
        table_name="users",
        file_path=MODELS,
        line_number=4,
        columns=[
            ColumnInfo(
                name="email",
                column_type="String",
                line_number=8,
                is_encrypted=False,
                is_hashed=True,
                has_expiry=True,
            )
        ],
    )
    result = scan(
        symbols=[signup, hasher],
        models=[user_model],
        fields=[pii("email", "email", ROUTES, 12)],
        edges=[
            edge("signup", ROUTES, 16, "hash_value", CRYPTO, 34, "data_pass"),
            edge("hash_value", CRYPTO, 34, "User.email", MODELS, 8, EDGE_DB_WRITE),
        ],
    )
    flows = trace_flows(result, CodeGraph(result))

    assert len(flows) == 1
    flow = flows[0]
    assert flow.transforms == [f"hashed in {CRYPTO}:34"]
    assert flow.sink_description == f"written to User.email at {MODELS}:8"
    assert flow.has_encryption is True
    assert flow.has_retention_policy is True


def test_plaintext_db_column_is_reported_unencrypted():
    signup = symbol("signup", ROUTES, 10, 40)
    model = ModelInfo(
        class_name="Profile",
        table_name="profiles",
        file_path=MODELS,
        line_number=20,
        columns=[ColumnInfo(name="aadhaar_ref", column_type="String", line_number=24)],
    )
    result = scan(
        symbols=[signup],
        models=[model],
        fields=[pii("aadhaar_ref", "government_id", ROUTES, 12, sensitivity="critical")],
        edges=[
            edge(
                "signup",
                ROUTES,
                18,
                "Profile.aadhaar_ref",
                MODELS,
                24,
                EDGE_DB_WRITE,
            )
        ],
    )
    flow = trace_flows(result, CodeGraph(result))[0]

    assert flow.has_encryption is False
    assert flow.has_retention_policy is False


def test_consent_guard_and_third_party_transfer_are_detected():
    signup = symbol("signup", ROUTES, 10, 40)
    guard = symbol("check_consent", SERVICE, 60, 70)
    result = scan(
        symbols=[signup, guard],
        fields=[pii("email", "email", ROUTES, 12)],
        edges=[
            edge("signup", ROUTES, 13, "check_consent", SERVICE, 60, "calls"),
            edge(
                "signup",
                ROUTES,
                22,
                "https://api.analytics-vendor.example/v1/track",
                ROUTES,
                22,
                EDGE_API_SEND,
            ),
        ],
    )
    flow = trace_flows(result, CodeGraph(result))[0]

    assert flow.has_consent_check is True
    assert flow.crosses_third_party is True
    assert flow.sink_description.startswith("sent to https://api.analytics-vendor.example")


def test_consent_check_after_the_sink_is_not_a_guard():
    signup = symbol("signup", ROUTES, 10, 40)
    guard = symbol("check_consent", SERVICE, 60, 70)
    result = scan(
        symbols=[signup, guard],
        fields=[pii("email", "email", ROUTES, 12)],
        edges=[
            edge("signup", ROUTES, 18, "logger.info", ROUTES, 18, EDGE_LOG_OUTPUT),
            # The consent call sits below the log line, so it guards nothing.
            edge("signup", ROUTES, 25, "check_consent", SERVICE, 60, "calls"),
        ],
    )
    flow = trace_flows(result, CodeGraph(result))[0]

    assert flow.has_consent_check is False


def test_internal_api_send_is_not_a_third_party_transfer():
    worker = symbol("enqueue", SERVICE, 10, 20)
    result = scan(
        symbols=[worker],
        fields=[pii("email", "email", SERVICE, 12)],
        edges=[
            edge(
                "enqueue",
                SERVICE,
                15,
                "http://localhost:8000/internal/queue",
                SERVICE,
                15,
                EDGE_API_SEND,
            )
        ],
    )
    flow = trace_flows(result, CodeGraph(result))[0]

    assert flow.crosses_third_party is False


def test_cleanup_job_sets_retention_flag():
    worker = symbol("purge_expired_users", SERVICE, 80, 95)
    handler = symbol("signup", ROUTES, 10, 40)
    result = scan(
        symbols=[worker, handler],
        fields=[pii("email", "email", ROUTES, 12)],
        edges=[
            edge("signup", ROUTES, 18, "logger.info", ROUTES, 18, EDGE_LOG_OUTPUT)
        ],
    )
    flow = trace_flows(result, CodeGraph(result))[0]

    assert flow.has_retention_policy is True


def test_flow_tracing_terminates_on_a_cycle():
    a = symbol("ingest", ROUTES, 1, 20)
    b = symbol("normalise", SERVICE, 1, 20)
    result = scan(
        symbols=[a, b],
        fields=[pii("email", "email", ROUTES, 5)],
        edges=[
            edge("ingest", ROUTES, 6, "normalise", SERVICE, 1, "data_pass"),
            edge("normalise", SERVICE, 10, "ingest", ROUTES, 1, "data_pass"),
            edge("normalise", SERVICE, 15, "logger.info", SERVICE, 15, EDGE_LOG_OUTPUT),
        ],
    )
    flows = trace_flows(result, CodeGraph(result))

    assert len(flows) == 1
    assert flows[0].sink_description == f"logged by logger.info at {SERVICE}:15"


def test_trace_flows_handles_empty_scan():
    assert trace_flows(scan(), CodeGraph(scan())) == []


# ---------------------------------------------------------------- assembler


def test_assemble_with_all_none_inputs_is_empty_but_valid():
    context = assemble_for_verdict(None, scan_result=None, graph=None, flows=None, web_result=None)

    assert isinstance(context, AnalysisContext)
    assert context.focus_file is None
    assert context.focus_line is None
    assert context.code_snippet is None
    assert context.callers == []
    assert context.callees == []
    assert context.pii_flows == []
    assert context.related_models == []
    assert context.related_routes == []
    assert context.web_evidence == {}
    assert context.render() == "No additional context available."


def test_assemble_packs_graph_neighbourhood_and_matching_flows():
    result = log_output_scan()
    result.routes = [
        RouteInfo(
            http_method="POST",
            path="/signup",
            handler_name="signup",
            file_path=ROUTES,
            line_number=9,
            has_auth=False,
            framework="fastapi",
        ),
        RouteInfo(
            http_method="GET",
            path="/health",
            handler_name="health",
            file_path="app/routes/health.py",
            line_number=3,
        ),
    ]
    graph = CodeGraph(result)
    flows = trace_flows(result, graph)
    unrelated = [f for f in trace_flows(scan(fields=[pii("pan", "government_id", MODELS, 3)]), graph)]

    context = assemble_for_verdict(
        verdict(
            [
                RuleCheck(
                    name="pii not written to logs",
                    passed=False,
                    detail="email reaches a log statement in plaintext",
                    file_path=ROUTES,
                    line_number=12,
                ),
                RuleCheck(name="tls enforced", passed=True, detail="ok"),
            ]
        ),
        scan_result=result,
        graph=graph,
        flows=flows + unrelated,
    )

    assert context.focus_file == ROUTES
    assert context.focus_line == 12
    assert [s.name for s in context.callees] == ["write_line", "logger.info"]
    assert len(context.pii_flows) == 1
    assert context.pii_flows[0].pii_category == "email"
    assert [r.path for r in context.related_routes] == ["/signup"]

    rendered = context.render()
    assert f"LOCATION: {ROUTES}:12" in rendered
    assert "no consent check" in rendered
    assert "not encrypted" in rendered


def test_assemble_caps_the_snippet():
    long_source = "\n".join(f"line {i}" for i in range(1, 201))
    handler = symbol("signup", ROUTES, 1, 200, source=long_source)
    result = scan(symbols=[handler])
    context = assemble_for_verdict(
        verdict(
            [
                RuleCheck(
                    name="security",
                    passed=False,
                    detail="plaintext write",
                    file_path=ROUTES,
                    line_number=120,
                )
            ]
        ),
        scan_result=result,
        graph=CodeGraph(result),
    )

    lines = context.code_snippet.splitlines()
    assert len(lines) <= MAX_SNIPPET_LINES + 1  # the cap plus the truncation marker
    assert "line 120" in context.code_snippet
    assert "line 1" != lines[0]


def test_assemble_uses_web_evidence_when_there_is_no_code_graph():
    web = WebScanResult(
        entry_url="https://synthetic.example/signup",
        forms=[
            FormInfo(
                action="/signup",
                method="post",
                fields=[FormField(name="email", input_type="email", required=True)],
                consent_elements=[
                    ConsentElement(
                        field_name="marketing_opt_in",
                        label_text="Send me offers",
                        pre_checked=True,
                        near_submit=True,
                    )
                ],
                submits_over_https=True,
            )
        ],
        served_over_https=True,
    )
    context = assemble_for_verdict(
        verdict(
            [
                RuleCheck(
                    name="consent checkbox not pre-checked",
                    passed=False,
                    detail="consent checkbox on form /signup is pre-checked",
                )
            ],
            rule_id="R4",
            rule_name="Consent",
        ),
        web_result=web,
    )

    assert context.focus_file is None
    assert context.callers == []
    assert "pre_checked=True" in context.web_evidence["consent_elements"]
    assert "/signup" in context.web_evidence["form"]
    assert "WEB EVIDENCE" in context.render()


def test_assemble_survives_a_verdict_with_no_located_checks():
    context = assemble_for_verdict(
        verdict([RuleCheck(name="retention configured", passed=False, detail="no expiry anywhere")]),
        scan_result=None,
        graph=None,
        flows=[],
        web_result=None,
    )

    assert context.focus_file is None
    assert context.pii_flows == []
    assert context.render() == "No additional context available."
