"""Context assembler.  OWNER: Harin

This is the answer to "how does this scale to a large repo". The AI never sees
the whole codebase. For each finding the assembler walks the graph two hops in
each direction, pulls the PII flows that pass through it, and packs only that.
A 10,000-file repo is analysed the same way as a 10-file one.
"""

from pathlib import Path

from app.context.code_graph import CodeGraph, normalize_path
from app.contracts import (
    AnalysisContext,
    CodeScanResult,
    FormInfo,
    ModelInfo,
    PIIFlowPathInfo,
    RouteInfo,
    RuleCheck,
    RuleVerdict,
    SymbolInfo,
    WebScanResult,
)

# Budgets. Padding the prompt with unrelated code makes the citation worse, so
# every list the AI sees is capped.
MAX_SNIPPET_LINES = 60
MAX_CALLERS = 8
MAX_CALLEES = 8
MAX_FLOWS = 6
MAX_MODELS = 4
MAX_ROUTES = 4
MAX_EVIDENCE_CHARS = 400
CONTEXT_HOPS = 2

EXPECTED_SECURITY_HEADERS = (
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)

_WEB_TOPICS: dict[str, tuple[str, ...]] = {
    "form": ("form", "checkbox", "consent", "signup", "sign up", "register", "collect", "field"),
    "notice": ("notice", "privacy", "policy", "disclosure", "purpose", "inform"),
    "headers": ("header", "hsts", "https", "tls", "csp", "clickjack", "transport", "security"),
    "cookies": ("cookie", "tracker", "session"),
    "third_party": ("third party", "third-party", "script", "processor", "analytics", "transfer"),
    "children": ("child", "children", "age", "minor", "guardian", "parental"),
    "rights": ("right", "grievance", "complaint", "erasure", "access", "correction", "nominee"),
}


def assemble_for_verdict(
    verdict: RuleVerdict | None,
    *,
    scan_result: CodeScanResult | None = None,
    graph: CodeGraph | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
    web_result: WebScanResult | None = None,
) -> AnalysisContext:
    """Pack the context the AI layer needs to explain one verdict."""
    context = AnalysisContext()

    check = _focus_check(verdict)
    if check is not None and check.file_path:
        context.focus_file = check.file_path
        context.focus_line = check.line_number

    symbol = None
    if graph is not None and context.focus_file and context.focus_line:
        symbol = graph.symbol_at(context.focus_file, context.focus_line)
        context.callers = graph.callers_of(symbol, hops=CONTEXT_HOPS)[:MAX_CALLERS]
        context.callees = graph.callees_of(symbol, hops=CONTEXT_HOPS)[:MAX_CALLEES]

    context.code_snippet = _code_snippet(
        symbol, scan_result, context.focus_file, context.focus_line
    )
    context.pii_flows = _relevant_flows(flows, context.focus_file)
    context.related_models = _related_models(scan_result, context.focus_file, context.pii_flows)
    context.related_routes = _related_routes(
        scan_result, context.focus_file, symbol, context.callers
    )

    if web_result is not None:
        context.web_evidence = _web_evidence(verdict, check, web_result)

    return context


# ----------------------------------------------------------------- code side


def _focus_check(verdict: RuleVerdict | None) -> RuleCheck | None:
    """The failed check is what the finding is about; prefer one with a location."""
    if verdict is None or not verdict.checks:
        return None
    failed = verdict.failed_checks
    for check in failed:
        if check.file_path:
            return check
    if failed:
        return failed[0]
    for check in verdict.checks:
        if check.file_path:
            return check
    return verdict.checks[0]


def _code_snippet(
    symbol: SymbolInfo | None,
    scan_result: CodeScanResult | None,
    focus_file: str | None,
    focus_line: int | None,
) -> str | None:
    if symbol is not None and symbol.source:
        return _window(symbol.source.splitlines(), symbol.line_number, focus_line)
    return _read_window(scan_result, focus_file, focus_line)


def _window(lines: list[str], start_line: int, focus_line: int | None) -> str | None:
    if not lines:
        return None
    if len(lines) <= MAX_SNIPPET_LINES:
        return "\n".join(lines)

    centre = 0
    if focus_line is not None and start_line:
        centre = max(0, focus_line - start_line)
    begin = max(0, centre - MAX_SNIPPET_LINES // 2)
    end = min(len(lines), begin + MAX_SNIPPET_LINES)
    begin = max(0, end - MAX_SNIPPET_LINES)
    return "\n".join([*lines[begin:end], "... (snippet truncated)"])


def _read_window(
    scan_result: CodeScanResult | None, focus_file: str | None, focus_line: int | None
) -> str | None:
    """Fallback when the scanner captured no source for the symbol. Best effort:
    the checkout may already be gone by the time findings are explained."""
    if not focus_file:
        return None
    candidates = []
    if scan_result is not None and scan_result.root_path:
        candidates.append(Path(scan_result.root_path) / focus_file)
    candidates.append(Path(focus_file))

    for candidate in candidates:
        try:
            if not candidate.is_file():
                continue
            lines = candidate.read_text(encoding="utf-8", errors="replace").splitlines()
        except (OSError, ValueError):
            continue
        if not lines:
            continue
        if focus_line is None:
            return _window(lines, 1, None)
        begin = max(0, focus_line - 1 - MAX_SNIPPET_LINES // 2)
        end = min(len(lines), begin + MAX_SNIPPET_LINES)
        begin = max(0, end - MAX_SNIPPET_LINES)
        selected = lines[begin:end]
        if end < len(lines):
            selected = [*selected, "... (snippet truncated)"]
        return "\n".join(selected)
    return None


def _relevant_flows(
    flows: list[PIIFlowPathInfo] | None, focus_file: str | None
) -> list[PIIFlowPathInfo]:
    if not flows:
        return []
    if not focus_file:
        return list(flows)[:MAX_FLOWS]

    target = normalize_path(focus_file)
    matched = [f for f in flows if target in _flow_text(f)]
    if not matched:
        # Absolute path in the verdict against a repo-relative path in the flow,
        # or the other way around. The file name alone still narrows it.
        basename = target.rsplit("/", 1)[-1]
        if basename:
            matched = [f for f in flows if basename in _flow_text(f)]
    return matched[:MAX_FLOWS]


def _flow_text(flow: PIIFlowPathInfo) -> str:
    return normalize_path(
        " ".join([flow.source_description, *flow.transforms, flow.sink_description])
    )


def _related_models(
    scan_result: CodeScanResult | None,
    focus_file: str | None,
    flows: list[PIIFlowPathInfo],
) -> list[ModelInfo]:
    if scan_result is None:
        return []
    target = normalize_path(focus_file) if focus_file else ""
    sink_text = " ".join(f.sink_description for f in flows).lower()

    picked: list[ModelInfo] = []
    seen: set[tuple[str, str]] = set()
    for model in scan_result.db_models or []:
        key = (normalize_path(model.file_path), model.class_name)
        if key in seen:
            continue
        in_focus_file = bool(target) and normalize_path(model.file_path) == target
        named_in_sink = any(
            n and n.lower() in sink_text for n in (model.class_name, model.table_name)
        )
        if in_focus_file or named_in_sink:
            seen.add(key)
            picked.append(model)
        if len(picked) >= MAX_MODELS:
            break
    return picked


def _related_routes(
    scan_result: CodeScanResult | None,
    focus_file: str | None,
    symbol: SymbolInfo | None,
    callers: list[SymbolInfo],
) -> list[RouteInfo]:
    if scan_result is None:
        return []
    target = normalize_path(focus_file) if focus_file else ""
    # A handler two hops upstream is the "enters at a signup route" half of the
    # story, so callers count as well as the focus file itself.
    handler_names = {c.name for c in callers}
    if symbol is not None:
        handler_names.add(symbol.name)

    picked: list[RouteInfo] = []
    for route in scan_result.routes or []:
        if (bool(target) and normalize_path(route.file_path) == target) or (
            route.handler_name in handler_names
        ):
            picked.append(route)
        if len(picked) >= MAX_ROUTES:
            break
    return picked


# ------------------------------------------------------------------ web side


def _web_evidence(
    verdict: RuleVerdict | None, check: RuleCheck | None, web: WebScanResult
) -> dict[str, str]:
    evidence: dict[str, str] = {}
    if web.entry_url:
        evidence["url"] = f"{web.entry_url} (https: {web.served_over_https})"

    topics = _topics_for(verdict, check)
    detail = (check.detail if check is not None else "") or ""

    if "form" in topics and web.forms:
        form = _relevant_form(web.forms, detail)
        if form is not None:
            evidence["form"] = _describe_form(form)
            consent = _describe_consent(form)
            if consent:
                evidence["consent_elements"] = consent
    if "notice" in topics:
        evidence["privacy_notice"] = _describe_notice(web)
    if "headers" in topics:
        present = ", ".join(sorted(k.lower() for k in web.security_headers)) or "none"
        missing = [
            h for h in EXPECTED_SECURITY_HEADERS if h not in {k.lower() for k in web.security_headers}
        ]
        evidence["security_headers"] = f"present: {present}; missing: {', '.join(missing) or 'none'}"
    if "cookies" in topics and web.cookies:
        evidence["cookies"] = "; ".join(
            f"{c.name} secure={c.secure} http_only={c.http_only} same_site={c.same_site}"
            for c in web.cookies[:5]
        )
    if "third_party" in topics and web.third_party_scripts:
        evidence["third_party_scripts"] = ", ".join(
            s.domain or s.src for s in web.third_party_scripts if s.is_third_party
        )[:MAX_EVIDENCE_CHARS]
    if "children" in topics:
        evidence["age_gate"] = (
            ", ".join(f"{f.name} ({f.input_type})" for f in web.age_gate_fields)
            or "no age or guardian field found on any scanned form"
        )
    if "rights" in topics:
        evidence["rights"] = (
            f"links: {', '.join(web.rights_links) or 'none'}; "
            f"grievance contact: {web.grievance_contact or 'none'}"
        )

    if len(evidence) <= 1:
        # Nothing matched the wording of the check, so give the AI the shape of
        # the scan rather than nothing at all.
        evidence["pages_scanned"] = str(len(web.pages))
        evidence["forms_found"] = str(len(web.forms))

    return {k: v[:MAX_EVIDENCE_CHARS] for k, v in evidence.items() if v}


def _topics_for(verdict: RuleVerdict | None, check: RuleCheck | None) -> set[str]:
    haystack = " ".join(
        part
        for part in (
            check.name if check is not None else None,
            check.detail if check is not None else None,
            verdict.rule_name if verdict is not None else None,
            verdict.evidence if verdict is not None else None,
        )
        if part
    ).lower()
    return {topic for topic, words in _WEB_TOPICS.items() if any(w in haystack for w in words)}


def _relevant_form(forms: list[FormInfo], detail: str) -> FormInfo | None:
    lowered = detail.lower()
    for form in forms:
        if form.action and form.action.lower() in lowered:
            return form
    for form in forms:
        if form.consent_elements:
            return form
    return forms[0] if forms else None


def _describe_form(form: FormInfo) -> str:
    fields = ", ".join(f"{f.name}:{f.input_type}" for f in form.fields[:10]) or "no fields parsed"
    return (
        f"{form.method.upper()} {form.action or '(no action)'} "
        f"https={form.submits_over_https}; fields: {fields}"
    )


def _describe_consent(form: FormInfo) -> str:
    if not form.consent_elements:
        return "no consent checkbox found on this form"
    return "; ".join(
        f"{c.field_name} pre_checked={c.pre_checked} near_submit={c.near_submit} "
        f"label={c.label_text!r}"
        for c in form.consent_elements[:4]
    )


def _describe_notice(web: WebScanResult) -> str:
    notice = web.privacy_notice
    if notice is None:
        return "no privacy notice link found"
    return (
        f"{notice.url} text={notice.link_text!r} reachable={notice.reachable} "
        f"footer_only={notice.in_footer_only}"
    )
