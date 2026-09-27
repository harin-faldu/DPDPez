"""Code graph.  OWNER: Harin

A directed graph of symbols and the edges between them, persisted so the rules
engine, the AI layer and the scorecard can all query the same structure
independently instead of each rebuilding it.
"""

from collections import defaultdict, deque

from app.contracts import CodeScanResult, DataFlowEdgeInfo, SymbolInfo

# (file_path, symbol_name). Names alone collide across files in any real repo.
NodeKey = tuple[str, str]

UNKNOWN_SYMBOL_KIND = "external"


def normalize_path(path: str | None) -> str:
    """Windows and POSIX separators both reach us, so keys must agree on one."""
    return (path or "").replace("\\", "/")


class CodeGraph:
    """In-memory adjacency over a CodeScanResult, backed by data_flow_edges."""

    def __init__(self, scan_result: CodeScanResult | None) -> None:
        self._symbols: dict[NodeKey, SymbolInfo] = {}
        self._symbols_by_file: dict[str, list[SymbolInfo]] = defaultdict(list)
        self._forward: dict[NodeKey, list[DataFlowEdgeInfo]] = defaultdict(list)
        self._reverse: dict[NodeKey, list[DataFlowEdgeInfo]] = defaultdict(list)
        self._placeholders: dict[NodeKey, SymbolInfo] = {}

        for symbol in getattr(scan_result, "symbols", None) or []:
            file_path = normalize_path(symbol.file_path)
            # First definition wins as the named node; symbol_at still sees every
            # definition through the per-file list, so nested ones are not lost.
            self._symbols.setdefault((file_path, symbol.name), symbol)
            self._symbols_by_file[file_path].append(symbol)

        for edge in getattr(scan_result, "data_flow_edges", None) or []:
            self._forward[self.source_key(edge)].append(edge)
            self._reverse[self.sink_key(edge)].append(edge)

    # ------------------------------------------------------------- node keys

    @staticmethod
    def source_key(edge: DataFlowEdgeInfo) -> NodeKey:
        return (normalize_path(edge.source_file), edge.source_symbol or "")

    @staticmethod
    def sink_key(edge: DataFlowEdgeInfo) -> NodeKey:
        return (normalize_path(edge.sink_file), edge.sink_symbol or "")

    @staticmethod
    def key_for(symbol: SymbolInfo) -> NodeKey:
        return (normalize_path(symbol.file_path), symbol.name)

    # ------------------------------------------------------------- traversal

    def outgoing_edges(self, node: NodeKey | SymbolInfo) -> list[DataFlowEdgeInfo]:
        """Edges leaving a node, in scan order. The flow tracer walks these."""
        return list(self._forward.get(self._as_key(node), ()))

    def incoming_edges(self, node: NodeKey | SymbolInfo) -> list[DataFlowEdgeInfo]:
        return list(self._reverse.get(self._as_key(node), ()))

    def callers_of(self, symbol: SymbolInfo, *, hops: int = 2) -> list[SymbolInfo]:
        """Symbols that reach this one, up to `hops` edges upstream."""
        return self._walk(symbol, hops=hops, forward=False)

    def callees_of(self, symbol: SymbolInfo, *, hops: int = 2) -> list[SymbolInfo]:
        """Symbols this one reaches, up to `hops` edges downstream."""
        return self._walk(symbol, hops=hops, forward=True)

    def _walk(self, symbol: SymbolInfo | None, *, hops: int, forward: bool) -> list[SymbolInfo]:
        if symbol is None or hops < 1:
            return []

        start = self.key_for(symbol)
        adjacency = self._forward if forward else self._reverse
        # Visited is global to the walk, not per branch: recursive and mutually
        # recursive code is normal, and a cycle must not hang the scan.
        visited: set[NodeKey] = {start}
        found: list[SymbolInfo] = []
        queue: deque[tuple[NodeKey, int]] = deque([(start, 0)])

        while queue:
            key, depth = queue.popleft()
            if depth >= hops:
                continue
            for edge in adjacency.get(key, ()):
                if forward:
                    neighbour, line = self.sink_key(edge), edge.sink_line
                else:
                    neighbour, line = self.source_key(edge), edge.source_line
                if neighbour in visited:
                    continue
                visited.add(neighbour)
                found.append(self.resolve(neighbour, line_hint=line))
                queue.append((neighbour, depth + 1))

        return found

    # ------------------------------------------------------------- lookup

    def symbol_at(self, file_path: str, line_number: int) -> SymbolInfo | None:
        """The innermost symbol whose line range contains this line."""
        if not file_path or line_number is None:
            return None

        best: SymbolInfo | None = None
        best_span: int | None = None
        for symbol in self._symbols_by_file.get(normalize_path(file_path), ()):
            start = symbol.line_number
            end = symbol.end_line if symbol.end_line is not None else symbol.line_number
            if end < start:
                end = start
            if not start <= line_number <= end:
                continue
            span = end - start
            if best is None or best_span is None or span < best_span:
                best, best_span = symbol, span
            elif span == best_span and start > best.line_number:
                best = symbol
        return best

    def symbol_named(self, file_path: str, name: str) -> SymbolInfo | None:
        return self._symbols.get((normalize_path(file_path), name))

    def resolve(self, node: NodeKey | SymbolInfo, *, line_hint: int | None = None) -> SymbolInfo:
        """A SymbolInfo for any node, indexed or not."""
        if isinstance(node, SymbolInfo):
            return node
        known = self._symbols.get(node)
        if known is not None:
            return known
        cached = self._placeholders.get(node)
        if cached is not None:
            return cached
        # Edges routinely point at things the symbol pass never indexed: a
        # logger, an ORM method, a vendor SDK call. Those are exactly the sinks
        # a compliance reviewer cares about, so stand in for them rather than
        # dropping them from the context.
        placeholder = SymbolInfo(
            name=node[1] or "<unknown>",
            kind=UNKNOWN_SYMBOL_KIND,
            file_path=node[0],
            line_number=line_hint or 0,
        )
        self._placeholders[node] = placeholder
        return placeholder

    def _as_key(self, node: NodeKey | SymbolInfo) -> NodeKey:
        if isinstance(node, SymbolInfo):
            return self.key_for(node)
        return (normalize_path(node[0]), node[1] or "")

    def __repr__(self) -> str:
        edges = sum(len(v) for v in self._forward.values())
        return f"CodeGraph(symbols={len(self._symbols)}, edges={edges})"
