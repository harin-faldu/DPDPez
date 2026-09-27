"""PII flow tracer.  OWNER: Harin

Finding an "email" column is easy. Showing that the email enters at a signup
route, passes through a logger that prints it in plaintext, and then reaches a
third-party analytics call with no consent check is what makes this a compliance
tool rather than a grep. The DPDP Act regulates processing, not existence.
"""

import re

from app.context.code_graph import CodeGraph, NodeKey, normalize_path
from app.contracts import (
    CodeScanResult,
    ColumnInfo,
    DataFlowEdgeInfo,
    PIIFieldRef,
    PIIFlowPathInfo,
    SymbolInfo,
)

# These mirror EdgeType in app/models/enums.py. They are repeated rather than
# imported because app.models pulls the whole ORM layer and its database driver
# in with it, and the context engine only ever touches contracts.py dataclasses.
EDGE_DB_READ = "db_read"
EDGE_DB_WRITE = "db_write"
EDGE_API_SEND = "api_send"
EDGE_LOG_OUTPUT = "log_output"

TERMINAL_SINK_TYPES = frozenset({EDGE_DB_WRITE, EDGE_API_SEND, EDGE_LOG_OUTPUT})

SINK_VERBS = {
    EDGE_DB_WRITE: "written to",
    EDGE_API_SEND: "sent to",
    EDGE_LOG_OUTPUT: "logged by",
}

# Traversal bounds. A real repo has fan-out that would otherwise make one field
# explode into thousands of near-identical paths.
MAX_PATH_DEPTH = 8
MAX_SINKS_PER_FIELD = 6
MAX_EXPANSIONS_PER_FIELD = 500

CONSENT_MARKERS = (
    "consent",
    "opt_in",
    "optin",
    "opted_in",
    "lawful_basis",
    "legal_basis",
    "permission_granted",
    "has_agreed",
    "agreed_to_terms",
)
HASH_MARKERS = (
    "hash",
    "bcrypt",
    "scrypt",
    "argon",
    "pbkdf2",
    "sha256",
    "sha512",
    "hmac",
    "digest",
)
ENCRYPT_MARKERS = ("encrypt", "cipher", "fernet", "aes_", "kms", "seal_", "envelope_")
MASK_MARKERS = ("mask", "redact", "anonymi", "pseudonym", "tokeni", "scrub", "obfuscat")
CLEANUP_MARKERS = (
    "cleanup",
    "clean_up",
    "purge",
    "prune",
    "sweep",
    "expire",
    "expiry",
    "retention",
    "delete_old",
    "delete_expired",
    "delete_stale",
    "erase_",
    "ttl",
)
THIRD_PARTY_MARKERS = (
    "analytics",
    "segment",
    "mixpanel",
    "amplitude",
    "posthog",
    "clevertap",
    "moengage",
    "appsflyer",
    "braze",
    "intercom",
    "hubspot",
    "mailchimp",
    "sendgrid",
    "twilio",
    "stripe",
    "razorpay",
    "sentry",
    "datadog",
    "newrelic",
    "firebase",
    "facebook",
    "gtag",
    "googleapis",
    "slack_webhook",
    "openai",
)
INTERNAL_HOST_MARKERS = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
    "::1",
    ".local",
    ".internal",
    ".svc",
    "host.docker.internal",
)

_URL_RE = re.compile(r"https?://([^/\s'\"()<>]+)", re.IGNORECASE)
_MEMBER_SPLIT_RE = re.compile(r"[.\[\]\"'()\s]+")


def trace_flows(scan_result: CodeScanResult, graph: CodeGraph) -> list[PIIFlowPathInfo]:
    """Build one end-to-end path per PII field per sink it reaches.

    A field with no reachable sink is still returned with an empty sink, since
    unused PII collection is itself a purpose-limitation problem.
    """
    if scan_result is None:
        return []
    if graph is None:
        graph = CodeGraph(scan_result)

    cleanup_job = _cleanup_job_exists(scan_result)
    flows: list[PIIFlowPathInfo] = []
    seen: set[tuple[str, str, str]] = set()

    for pii_field in scan_result.pii_fields or []:
        symbol = _enclosing_symbol(graph, pii_field)
        source = _source_description(pii_field, symbol)
        start_keys = _start_keys(graph, scan_result, pii_field, symbol)

        reached = []
        for start in start_keys:
            reached.extend(_walk_to_sinks(graph, start, pii_field))
            if len(reached) >= MAX_SINKS_PER_FIELD:
                break

        if not reached:
            # No sink is still a finding, not a gap in the report. Transforms are
            # left empty so render() does not print a chain that goes nowhere.
            flow = PIIFlowPathInfo(
                pii_category=pii_field.pii_category,
                source_description=source,
                sink_description="",
                has_consent_check=_has_consent_guard(graph, [(k, None) for k in start_keys]),
                has_encryption=False,
                has_retention_policy=cleanup_job,
                crosses_third_party=False,
            )
            _append_unique(flows, seen, flow)
            continue

        for path, terminal in reached[:MAX_SINKS_PER_FIELD]:
            flow = _build_flow(
                scan_result=scan_result,
                graph=graph,
                pii_field=pii_field,
                source=source,
                path=path,
                terminal=terminal,
                start_keys=start_keys,
                cleanup_job=cleanup_job,
            )
            _append_unique(flows, seen, flow)

    return flows


# ------------------------------------------------------------------ traversal


def _walk_to_sinks(
    graph: CodeGraph, start: NodeKey, pii_field: PIIFieldRef
) -> list[tuple[tuple[DataFlowEdgeInfo, ...], DataFlowEdgeInfo]]:
    """Depth-first walk returning (intermediate edges, terminal edge) per sink."""
    results: list[tuple[tuple[DataFlowEdgeInfo, ...], DataFlowEdgeInfo]] = []
    seen_sinks: set[tuple] = set()
    expansions = 0
    stack: list[tuple[NodeKey, tuple[DataFlowEdgeInfo, ...], frozenset[NodeKey]]] = [
        (start, (), frozenset({start}))
    ]

    while stack and len(results) < MAX_SINKS_PER_FIELD and expansions < MAX_EXPANSIONS_PER_FIELD:
        node, path, visited = stack.pop()
        expansions += 1

        for edge in graph.outgoing_edges(node):
            if not _carries(edge, pii_field.pii_category):
                continue
            if edge.edge_type in TERMINAL_SINK_TYPES:
                fingerprint = _edge_fingerprint(edge)
                if fingerprint in seen_sinks:
                    continue
                seen_sinks.add(fingerprint)
                results.append((path, edge))
                if len(results) >= MAX_SINKS_PER_FIELD:
                    break
                continue
            following = graph.sink_key(edge)
            # Per-branch visited set: a cycle must terminate, but a diamond where
            # two branches meet again is a legitimate second path.
            if following in visited or len(path) + 1 >= MAX_PATH_DEPTH:
                continue
            stack.append((following, path + (edge,), visited | {following}))

    return results


def _start_keys(
    graph: CodeGraph,
    scan_result: CodeScanResult,
    pii_field: PIIFieldRef,
    symbol: SymbolInfo | None,
) -> list[NodeKey]:
    """Where in the graph this field enters. Prefers the enclosing symbol."""
    keys: list[NodeKey] = []
    if symbol is not None:
        keys.append(CodeGraph.key_for(symbol))

    if not keys and pii_field.file_path:
        # The symbol pass may not have indexed this file. Fall back to any edge
        # leaving the same file that carries the same PII category.
        file_path = normalize_path(pii_field.file_path)
        for edge in scan_result.data_flow_edges or []:
            if normalize_path(edge.source_file) != file_path:
                continue
            if not _carries(edge, pii_field.pii_category):
                continue
            key = CodeGraph.source_key(edge)
            if key not in keys:
                keys.append(key)

    if not keys and pii_field.field_name:
        keys.append((normalize_path(pii_field.file_path), pii_field.field_name))
    return keys


def _enclosing_symbol(graph: CodeGraph, pii_field: PIIFieldRef) -> SymbolInfo | None:
    if not pii_field.file_path or pii_field.line_number is None:
        return None
    return graph.symbol_at(pii_field.file_path, pii_field.line_number)


def _carries(edge: DataFlowEdgeInfo, category: str) -> bool:
    """Only filter when the scanner actually tagged the edge, so an untagged
    scan still produces flows instead of silently producing none."""
    if not edge.pii_categories:
        return True
    if not category:
        return True
    lowered = {c.lower() for c in edge.pii_categories}
    return category.lower() in lowered


# --------------------------------------------------------------- flow building


def _build_flow(
    *,
    scan_result: CodeScanResult,
    graph: CodeGraph,
    pii_field: PIIFieldRef,
    source: str,
    path: tuple[DataFlowEdgeInfo, ...],
    terminal: DataFlowEdgeInfo,
    start_keys: list[NodeKey],
    cleanup_job: bool,
) -> PIIFlowPathInfo:
    column = _matching_column(scan_result, terminal)
    hashed_on_path = any(_matches(edge.sink_symbol, HASH_MARKERS + ENCRYPT_MARKERS) for edge in path)

    # Each node on the path is paired with the line at which the data leaves it,
    # so a consent check further down the function does not count as a guard.
    hops = (*path, terminal)
    guard_nodes: list[tuple[NodeKey, int | None]] = [(key, hops[0].source_line) for key in start_keys]
    for index, hop in enumerate(path):
        guard_nodes.append((CodeGraph.sink_key(hop), hops[index + 1].source_line))

    return PIIFlowPathInfo(
        pii_category=pii_field.pii_category,
        source_description=source,
        transforms=[_transform_label(edge) for edge in path],
        sink_description=_sink_description(terminal),
        has_consent_check=_has_consent_guard(graph, guard_nodes),
        has_encryption=bool(column and (column.is_encrypted or column.is_hashed)) or hashed_on_path,
        has_retention_policy=bool(column and column.has_expiry) or cleanup_job,
        crosses_third_party=_leaves_own_host(terminal),
    )


def _source_description(pii_field: PIIFieldRef, symbol: SymbolInfo | None) -> str:
    where = _location(pii_field.file_path, pii_field.line_number)
    name = pii_field.field_name or pii_field.pii_category
    if symbol is not None and where:
        return f"{name} in {symbol.name} at {where}"
    if where:
        return f"{name} at {where}"
    if pii_field.location_kind:
        return f"{name} ({pii_field.location_kind})"
    return name


def _transform_label(edge: DataFlowEdgeInfo) -> str:
    target = edge.sink_symbol or edge.edge_type
    where = _location(edge.sink_file, edge.sink_line)
    verb = None
    if _matches(target, HASH_MARKERS):
        verb = "hashed"
    elif _matches(target, ENCRYPT_MARKERS):
        verb = "encrypted"
    elif _matches(target, MASK_MARKERS):
        verb = "masked"
    if verb:
        return f"{verb} in {where}" if where else verb
    if edge.edge_type == EDGE_DB_READ:
        return f"read from {target} in {where}" if where else f"read from {target}"
    return f"passed to {target} in {where}" if where else f"passed to {target}"


def _sink_description(edge: DataFlowEdgeInfo) -> str:
    verb = SINK_VERBS.get(edge.edge_type, edge.edge_type)
    target = edge.sink_symbol or "unnamed sink"
    where = _location(edge.sink_file, edge.sink_line)
    return f"{verb} {target} at {where}" if where else f"{verb} {target}"


def _location(file_path: str | None, line_number: int | None) -> str:
    if not file_path:
        return ""
    path = normalize_path(file_path)
    return f"{path}:{line_number}" if line_number else path


# --------------------------------------------------------------------- flags


def _has_consent_guard(graph: CodeGraph, nodes: list[tuple[NodeKey, int | None]]) -> bool:
    """A consent guard is rarely on the data path itself: the handler calls
    check_consent(user) and only then touches the field. So look at each node on
    the path and at what that node calls directly."""
    for node, before_line in nodes:
        if _matches(node[1], CONSENT_MARKERS):
            return True
        for edge in graph.outgoing_edges(node):
            if not _matches(edge.sink_symbol, CONSENT_MARKERS):
                continue
            # A consent check that runs after the data has already moved is not
            # a guard. Line order within the node is the only ordering available.
            if before_line is None or edge.source_line is None or edge.source_line <= before_line:
                return True
    return False


def _matching_column(scan_result: CodeScanResult, edge: DataFlowEdgeInfo) -> ColumnInfo | None:
    """Resolve a db_write sink to the declared column, so encryption and expiry
    come off ColumnInfo rather than off a hopeful reading of the column name."""
    if edge.edge_type != EDGE_DB_WRITE:
        return None

    parts = [p for p in _MEMBER_SPLIT_RE.split(edge.sink_symbol or "") if p]
    if not parts:
        return None
    column_name = parts[-1].lower()
    owner = parts[-2].lower() if len(parts) > 1 else None
    sink_file = normalize_path(edge.sink_file)

    best: ColumnInfo | None = None
    best_rank = 0
    for model in scan_result.db_models or []:
        model_names = {n.lower() for n in (model.class_name, model.table_name) if n}
        for column in model.columns:
            if column.name.lower() != column_name:
                continue
            if owner and owner in model_names:
                rank = 3
            elif normalize_path(model.file_path) == sink_file:
                rank = 2
            elif owner is None:
                rank = 1
            else:
                rank = 0  # column name matched but nothing ties it to this model
            if rank > best_rank:
                best, best_rank = column, rank
    return best


def _cleanup_job_exists(scan_result: CodeScanResult) -> bool:
    return any(_matches(symbol.name, CLEANUP_MARKERS) for symbol in scan_result.symbols or [])


def _leaves_own_host(edge: DataFlowEdgeInfo) -> bool:
    if edge.edge_type != EDGE_API_SEND:
        return False
    # Only the call target is inspected. The file path is inside the repo under
    # review, so a module named analytics.py must not be read as a transfer.
    target = edge.sink_symbol or ""
    match = _URL_RE.search(target)
    if match:
        host = match.group(1).lower()
        return not any(marker in host for marker in INTERNAL_HOST_MARKERS)
    return _matches(target, THIRD_PARTY_MARKERS)


def _matches(text: str | None, markers: tuple[str, ...]) -> bool:
    if not text:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in markers)


def _edge_fingerprint(edge: DataFlowEdgeInfo) -> tuple:
    return (
        normalize_path(edge.source_file),
        edge.source_symbol,
        edge.source_line,
        normalize_path(edge.sink_file),
        edge.sink_symbol,
        edge.sink_line,
        edge.edge_type,
    )


def _append_unique(
    flows: list[PIIFlowPathInfo],
    seen: set[tuple[str, str, str]],
    flow: PIIFlowPathInfo,
) -> None:
    key = (flow.pii_category, flow.source_description, flow.sink_description)
    if key in seen:
        return
    seen.add(key)
    flows.append(flow)
