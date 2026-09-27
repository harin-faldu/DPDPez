"""Code scanner.  OWNER: Harin

tree-sitter gives a real syntax tree, not pattern matching on text. A regex
cannot tell whether "email" is a variable, a string literal or a comment. The
AST can, which is why detection here is structural.

This module only collects evidence. It never decides compliance.

Two consequences of "structural" are worth stating, because they are the
difference between this and grep:

* A bare string literal is never treated as a field name. "email" becomes a
  field only when the tree says it is a subscript key or an object key, which
  is exactly the distinction a regex cannot make.
* is_encrypted and is_hashed are read off identifier nodes inside the column
  declaration, plus assignments to the same attribute elsewhere in the file. A
  comment or a docstring that says "encrypted" proves nothing and is ignored.

Symbol kinds emitted: "function", "method", "class". Go structs are reported as
"class" because they are what carries the model declaration there.
"""

from __future__ import annotations

import asyncio
import importlib
import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass, field, replace
from functools import cache
from pathlib import Path
from typing import Any, ClassVar

from app.config import settings
from app.contracts import (
    CodeScanResult,
    ColumnInfo,
    DataFlowEdgeInfo,
    FileInfo,
    ModelInfo,
    PIIFieldRef,
    RouteInfo,
    SymbolInfo,
)
from app.models.enums import EdgeType
from app.pii import field_classifier

logger = logging.getLogger(__name__)

LANGUAGE_BY_EXTENSION = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
}

SKIP_DIRECTORIES = frozenset(
    {
        "node_modules",
        ".git",
        "venv",
        ".venv",
        "__pycache__",
        "dist",
        "build",
        "migrations",
        "vendor",
        ".next",
    }
)

# One minified bundle can be several megabytes on a single line and yields no
# usable evidence, so cap per-file size rather than stalling the whole scan.
MAX_FILE_BYTES = 1_500_000
MAX_SOURCE_SNIPPET_CHARS = 4000
MAX_SOURCE_SNIPPET_LINES = 150
# Matches the width of the persisted symbol columns in app.models.data_flow.
MAX_SYMBOL_CHARS = 200

# ------------------------------------------------------------------- markers

ENCRYPTION_MARKERS = (
    "encrypt",
    "decrypt",
    "fernet",
    "aesengine",
    "aesgcm",
    "pgcrypto",
    "pgp_sym",
    "cipher",
    "kms",
    "vaultstring",
)

# "crypt" on its own is deliberately absent: it matches "encrypt" and would
# mark every encrypted column as hashed too.
HASH_MARKERS = (
    "bcrypt",
    "argon2",
    "scrypt",
    "pbkdf2",
    "hashlib",
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "blake2",
    "digest",
    "hashpw",
    "passwordhash",
    "password_hash",
    "generate_password_hash",
    "createhash",
    "messagedigest",
)

EXPIRY_MARKERS = (
    "expires",
    "expiry",
    "expire",
    "ttl",
    "retention",
    "retain_until",
    "valid_until",
    "validuntil",
    "purge_at",
    "purgeat",
    "delete_after",
    "deleteafter",
    "erase_at",
)

AUTH_MARKERS = (
    "auth",
    "login_required",
    "loginrequired",
    "jwt",
    "token_required",
    "tokenrequired",
    "verifytoken",
    "verify_token",
    "current_user",
    "currentuser",
    "permission",
    "requires",
    "security",
    "protected",
    "rolesallowed",
    "secured",
    "preauthorize",
    "isloggedin",
    "ensureloggedin",
    "session_required",
    "admin_required",
    "adminrequired",
    "guard",
)

HTTP_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})

LOG_OBJECT_NAMES = frozenset(
    {
        "logger",
        "log",
        "logging",
        "console",
        "winston",
        "logrus",
        "slog",
        "syslog",
        "audit",
        "auditlog",
        "applog",
    }
)
LOG_LEVEL_NAMES = frozenset(
    {
        "debug",
        "info",
        "warn",
        "warning",
        "error",
        "critical",
        "exception",
        "fatal",
        "trace",
        "log",
        "print",
        "printf",
        "println",
    }
)
# Fully qualified calls that are logging whatever the receiver is named.
LOG_FULL_CALLS = frozenset(
    {
        "print",
        "fmt.print",
        "fmt.printf",
        "fmt.println",
        "system.out.print",
        "system.out.println",
        "system.err.print",
        "system.err.println",
        "sys.stdout.write",
        "sys.stderr.write",
    }
)

HTTP_CLIENT_NAMES = frozenset(
    {
        "requests",
        "httpx",
        "aiohttp",
        "urllib",
        "axios",
        "got",
        "superagent",
        "resttemplate",
        "webclient",
        "okhttp",
        "httpclient",
    }
)
HTTP_CLIENT_METHODS = HTTP_VERBS | {"request", "send", "fetch", "exchange"}
API_SEND_FULL_CALLS = frozenset({"fetch", "urlopen", "urllib.request.urlopen"})

DB_RECEIVER_NAMES = frozenset(
    {
        "session",
        "db",
        "database",
        "conn",
        "connection",
        "cursor",
        "repo",
        "repository",
        "collection",
        "objects",
        "query",
        "engine",
        "tx",
        "store",
        "em",
        "entitymanager",
        "prisma",
        "knex",
        "sequelize",
        "mongo",
        "gorm",
        "dao",
    }
)
DB_WRITE_DISTINCT = frozenset(
    {
        "add_all",
        "bulk_save_objects",
        "bulk_create",
        "bulkcreate",
        "insert_one",
        "insertone",
        "insert_many",
        "insertmany",
        "upsert",
        "put_item",
        "persist",
        "save",
        "commit",
        "create",
    }
)
DB_WRITE_GENERIC = frozenset({"add", "insert", "update", "write", "merge"})
DB_READ_DISTINCT = frozenset(
    {
        "find_one",
        "findone",
        "find_all",
        "findall",
        "findbypk",
        "filter_by",
        "one_or_none",
        "fetchall",
        "fetchone",
        "get_or_404",
        "scalars",
        "scalar_one",
    }
)
DB_READ_GENERIC = frozenset(
    {"query", "get", "filter", "all", "first", "one", "find", "select", "aggregate"}
)

# Column declaration callees. Django and peewee field classes all end in
# "Field", which is checked separately.
SQLALCHEMY_COLUMN_CALLEES = frozenset({"column", "mapped_column", "deferred"})
DJANGO_EXTRA_FIELD_CALLEES = frozenset({"foreignkey", "onetoonefield", "manytomanyfield"})

IDENTIFIER_NODE_TYPES = frozenset(
    {
        "identifier",
        "property_identifier",
        "field_identifier",
        "shorthand_property_identifier",
        "shorthand_property_identifier_pattern",
        "package_identifier",
    }
)

KEY_PARENT_TYPES = frozenset({"subscript", "subscript_expression", "pair", "index"})

_IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_GO_TAG_COLUMN_RE = re.compile(r"column:([A-Za-z0-9_]+)")
_CAMEL_BOUNDARY_RE = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


# ------------------------------------------------------------------ grammars

_GRAMMAR_LOADERS = {
    "python": ("tree_sitter_python", "language"),
    "javascript": ("tree_sitter_javascript", "language"),
    "typescript": ("tree_sitter_typescript", "language_typescript"),
    "tsx": ("tree_sitter_typescript", "language_tsx"),
    "java": ("tree_sitter_java", "language"),
    "go": ("tree_sitter_go", "language"),
}


@cache
def _parser_for(grammar: str) -> Any | None:
    """Load a tree-sitter grammar once per process, or None if unavailable."""
    try:
        from tree_sitter import Language, Parser
    except ImportError:  # pragma: no cover - pinned in requirements.txt
        logger.warning("tree_sitter is not installed, code scanning is disabled")
        return None

    entry = _GRAMMAR_LOADERS.get(grammar)
    if entry is None:
        return None
    module_name, attr = entry
    try:
        module = importlib.import_module(module_name)
        return Parser(Language(getattr(module, attr)()))
    except Exception as exc:
        logger.warning("grammar %s unavailable: %s", grammar, exc)
        return None


def _grammar_for_suffix(suffix: str) -> str | None:
    if suffix == ".tsx":
        return "tsx"
    return LANGUAGE_BY_EXTENSION.get(suffix)


# -------------------------------------------------------------- node helpers


def _text(node: Any, src: bytes) -> str:
    return src[node.start_byte : node.end_byte].decode("utf-8", "replace")


def _line(node: Any) -> int:
    return node.start_point[0] + 1


def _end_line(node: Any) -> int:
    return node.end_point[0] + 1


def _descend(node: Any) -> Iterator[Any]:
    """Every named node at or below `node`, iteratively to survive deep trees."""
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(current.named_children)


def _field(node: Any, name: str) -> Any | None:
    return node.child_by_field_name(name)


def _field_text(node: Any, name: str, src: bytes) -> str:
    child = _field(node, name)
    return _text(child, src) if child is not None else ""


def _string_value(node: Any, src: bytes) -> str | None:
    """Content of a string literal node, without its quotes."""
    if node is None:
        return None
    if "string" not in node.type:
        return None
    for child in node.named_children:
        if child.type.endswith(("_content", "_fragment")):
            return _text(child, src)
    raw = _text(node, src)
    return raw.strip("\"'`")


def _first_string_arg(args: Any, src: bytes) -> str | None:
    if args is None:
        return None
    for child in args.named_children:
        value = _string_value(child, src)
        if value is not None:
            return value
    return None


def _identifier_blob(node: Any, src: bytes) -> str:
    """Identifier text under `node`, lowercased and joined.

    String literals are excluded on purpose: a description that says
    "encrypted" is not evidence that anything is encrypted.
    """
    parts = [
        _text(child, src)
        for child in _descend(node)
        if child.type in IDENTIFIER_NODE_TYPES or child.type == "type_identifier"
    ]
    return " ".join(parts).lower()


def _has_marker(blob: str, markers: tuple[str, ...]) -> bool:
    return any(marker in blob for marker in markers)


def _normalize(name: str) -> str:
    return name.replace("_", "").replace("-", "").lower()


def _last_segment(dotted: str) -> str:
    cleaned = dotted.strip()
    for separator in (".", "::", "->"):
        if separator in cleaned:
            cleaned = cleaned.rsplit(separator, 1)[-1]
    return cleaned.strip()


def _route_path_params(path: str) -> list[str]:
    """Parameter names in a route path, for {id}, :id and <int:id> styles."""
    params: list[str] = []
    for segment in path.split("/"):
        segment = segment.strip()
        if not segment:
            continue
        if segment.startswith("{") and segment.endswith("}"):
            params.append(segment[1:-1].split(":", 1)[0].strip())
        elif segment.startswith("<") and segment.endswith(">"):
            params.append(segment[1:-1].rsplit(":", 1)[-1].strip())
        elif segment.startswith(":"):
            params.append(segment[1:].strip())
    return [p for p in params if _IDENT_RE.match(p)]


def _join_paths(prefix: str, suffix: str) -> str:
    if not prefix:
        return suffix or "/"
    if not suffix:
        return prefix
    return f"{prefix.rstrip('/')}/{suffix.lstrip('/')}"


def _is_field_name(name: str) -> bool:
    """Dunders are language machinery, never a data field."""
    if not name or not _IDENT_RE.match(name):
        return False
    return not (name.startswith("__") and name.endswith("__"))


def _name_variants(name: str) -> list[str]:
    """The name as written, plus a snake_case form for camelCase identifiers.

    Java, Go and JS field names are camelCase while the classifier matches on
    underscore-separated tokens, so without this every camelCase field is
    invisible to it.
    """
    variants = [name]
    if "_" not in name:
        snake = _CAMEL_BOUNDARY_RE.sub("_", name).lower()
        if snake != name.lower():
            variants.append(snake)
    return variants


def _type_label(text: str) -> str:
    """Reduce a type expression to its trailing name, e.g. DataTypes.STRING."""
    head = text.split("\n")[0].split("(", 1)[0].strip()
    return _last_segment(head) or head


def _callee_label(receiver: str, method: str) -> str:
    """Short, stable name for a call sink.

    A fluent chain such as session.query(M).filter_by(x).one_or_none() has a
    receiver that is most of the statement. Collapsing it to its root keeps the
    label readable and inside the persisted column width.
    """
    if not receiver:
        return method[:MAX_SYMBOL_CHARS]
    compact = receiver.replace("\n", " ").strip()
    if "(" in compact or "[" in compact or len(compact) > 60:
        root = compact.split("(", 1)[0].split("[", 1)[0].split(".", 1)[0].strip()
        compact = root or compact[:60]
    return f"{compact}.{method}".strip(".")[:MAX_SYMBOL_CHARS]


# ------------------------------------------------------ PII classifier bridge

_classifier_warned = False


def _warn_classifier_once(exc: Exception) -> None:
    # The classifier lands independently of the scanner. A missing one degrades
    # PII tagging; it must never abort a scan that is otherwise producing
    # structural evidence.
    global _classifier_warned
    if not _classifier_warned:
        _classifier_warned = True
        logger.warning("pii field_classifier unavailable, PII tagging is off: %s", exc)


def _category_of(name: str) -> str | None:
    if not _is_field_name(name):
        return None
    for variant in _name_variants(name):
        try:
            category = field_classifier.classify(variant)
        except NotImplementedError as exc:
            _warn_classifier_once(exc)
            return None
        except Exception as exc:
            logger.debug("classify(%s) failed: %s", variant, exc)
            return None
        if category:
            return category
    return None


def _field_ref(
    name: str,
    *,
    file_path: str,
    line_number: int,
    location_kind: str,
    context: str | None = None,
) -> PIIFieldRef | None:
    if not _is_field_name(name):
        return None
    for variant in _name_variants(name):
        try:
            ref = field_classifier.build_field_ref(
                variant,
                file_path=file_path,
                line_number=line_number,
                location_kind=location_kind,
                context=context,
            )
        except NotImplementedError as exc:
            _warn_classifier_once(exc)
            return None
        except Exception as exc:
            logger.debug("build_field_ref(%s) failed: %s", variant, exc)
            return None
        if ref is not None:
            # Report the identifier as it appears in the source, not the
            # normalised form that happened to match.
            return replace(ref, field_name=name) if variant != name else ref
    return None


# ----------------------------------------------------------------- scan state


@dataclass
class _CallSite:
    caller_symbol: str
    caller_file: str
    line: int
    callee_name: str
    callee_text: str
    edge_type: str | None
    sink_label: str | None
    pii_categories: list[str] = field(default_factory=list)


@dataclass
class _ImportSite:
    caller_symbol: str
    caller_file: str
    line: int
    module: str


@dataclass
class _ScanState:
    result: CodeScanResult
    calls: list[_CallSite] = field(default_factory=list)
    imports: list[_ImportSite] = field(default_factory=list)
    # (file, normalised attribute name) seen assigned a hashed/encrypted value.
    hashed_targets: set[tuple[str, str]] = field(default_factory=set)
    encrypted_targets: set[tuple[str, str]] = field(default_factory=set)


# ------------------------------------------------------------ base extractor


class _Extractor:
    """Shared traversal scaffolding. One instance per file."""

    def __init__(self, state: _ScanState, rel_path: str, src: bytes) -> None:
        self.state = state
        self.result = state.result
        self.path = rel_path
        self.src = src
        self.module_symbol = Path(rel_path).stem or rel_path

    # -- emit helpers

    def add_symbol(self, name: str, kind: str, node: Any) -> None:
        if not name:
            return
        source = None
        if _end_line(node) - _line(node) <= MAX_SOURCE_SNIPPET_LINES:
            source = _text(node, self.src)[:MAX_SOURCE_SNIPPET_CHARS]
        self.result.symbols.append(
            SymbolInfo(
                name=name,
                kind=kind,
                file_path=self.path,
                line_number=_line(node),
                end_line=_end_line(node),
                source=source,
            )
        )

    def add_pii(
        self, name: str, line: int, location_kind: str, context: str | None = None
    ) -> None:
        ref = _field_ref(
            name,
            file_path=self.path,
            line_number=line,
            location_kind=location_kind,
            context=context,
        )
        if ref is not None:
            self.result.pii_fields.append(ref)

    def record_import(self, module: str, node: Any) -> None:
        if module:
            self.state.imports.append(
                _ImportSite(self.module_symbol, self.path, _line(node), module)
            )

    # -- PII discovery inside an expression

    def pii_candidates(self, node: Any) -> list[str]:
        """Field-like names under `node`, in source order, de-duplicated.

        Identifiers, plus strings the tree says are keys. A plain string literal
        that happens to read "email" is not a field reference.
        """
        if node is None:
            return []
        names: list[str] = []
        seen: set[str] = set()
        for child in _descend(node):
            candidate: str | None = None
            if child.type in IDENTIFIER_NODE_TYPES:
                candidate = _text(child, self.src)
            elif child.type.endswith(("_content", "_fragment")):
                holder = child.parent
                owner = holder.parent if holder is not None else None
                if owner is not None and owner.type in KEY_PARENT_TYPES:
                    candidate = _text(child, self.src)
            if candidate and _is_field_name(candidate) and candidate not in seen:
                seen.add(candidate)
                names.append(candidate)
        return names

    def categories_in(self, node: Any) -> list[str]:
        found: list[str] = []
        for name in self.pii_candidates(node):
            category = _category_of(name)
            if category and category not in found:
                found.append(category)
        return found

    def record_arg_pii(self, node: Any, location_kind: str, context: str) -> None:
        if node is None:
            return
        for name in self.pii_candidates(node):
            self.add_pii(name, _line(node), location_kind, context)

    # -- call classification, shared across all five languages

    def classify_call(
        self, receiver: str, method: str, args: Any
    ) -> tuple[str | None, str | None]:
        """Map a call onto an EdgeType, plus an optional sink label."""
        full = f"{receiver}.{method}".strip(".").lower()
        recv = _last_segment(receiver).lower()
        meth = method.lower()

        if full in LOG_FULL_CALLS or (
            recv in LOG_OBJECT_NAMES and meth in LOG_LEVEL_NAMES
        ):
            return EdgeType.LOG_OUTPUT.value, None

        if full in API_SEND_FULL_CALLS or (
            recv in HTTP_CLIENT_NAMES and meth in HTTP_CLIENT_METHODS
        ):
            return EdgeType.API_SEND.value, self._external_host(args)

        if meth in ("execute", "executemany", "raw"):
            # The SQL verb in the literal is the only reliable direction signal.
            statement = (_first_string_arg(args, self.src) or "").strip().lower()
            if statement.startswith(("insert", "update", "delete", "merge", "upsert")):
                return EdgeType.DB_WRITE.value, None
            if statement.startswith(("select", "with")):
                return EdgeType.DB_READ.value, None

        if meth in DB_WRITE_DISTINCT or (
            recv in DB_RECEIVER_NAMES and meth in DB_WRITE_GENERIC
        ):
            return EdgeType.DB_WRITE.value, None
        if meth in DB_READ_DISTINCT or (
            recv in DB_RECEIVER_NAMES and meth in DB_READ_GENERIC
        ):
            return EdgeType.DB_READ.value, None
        return None, None

    def _external_host(self, args: Any) -> str | None:
        """Host of the first URL literal in the argument list, if any."""
        if args is None:
            return None
        for child in _descend(args):
            value = _string_value(child, self.src)
            if value and value.startswith(("http://", "https://")):
                return value.split("://", 1)[1].split("/", 1)[0] or None
        return None

    def record_call(
        self, *, scope: str, node: Any, receiver: str, method: str, args: Any
    ) -> None:
        edge_type, sink_label = self.classify_call(receiver, method, args)
        categories = self.categories_in(args) if args is not None else []
        callee_text = _callee_label(receiver, method)

        if edge_type == EdgeType.API_SEND.value and categories:
            self.record_arg_pii(args, "api_payload", callee_text)

        self.state.calls.append(
            _CallSite(
                caller_symbol=scope,
                caller_file=self.path,
                line=_line(node),
                callee_name=method or callee_text,
                callee_text=callee_text,
                edge_type=edge_type,
                sink_label=sink_label,
                pii_categories=categories,
            )
        )

    # -- correlation of hashing and encryption with a named attribute

    def record_transform_target(self, target_name: str, value_node: Any) -> None:
        """Remember `x = bcrypt(...)` so a column named x can be marked hashed.

        Hashing almost never happens inside the column declaration, so without
        this correlation is_hashed would be False for every real codebase.
        """
        if not target_name or value_node is None:
            return
        blob = _identifier_blob(value_node, self.src)
        key = (self.path, _normalize(target_name))
        if _has_marker(blob, HASH_MARKERS):
            self.state.hashed_targets.add(key)
        if _has_marker(blob, ENCRYPTION_MARKERS):
            self.state.encrypted_targets.add(key)

    def run(self, root: Any) -> None:  # pragma: no cover - always overridden
        raise NotImplementedError


# -------------------------------------------------------------------- Python


class _PythonExtractor(_Extractor):
    def run(self, root: Any) -> None:
        self.visit(root, self.module_symbol, in_class=False)

    def visit(self, node: Any, scope: str, *, in_class: bool) -> None:
        for child in node.named_children:
            kind = child.type
            if kind == "decorated_definition":
                self.visit_decorated(child, scope, in_class=in_class)
            elif kind == "function_definition":
                self.visit_function(child, scope, in_class=in_class, decorators=[])
            elif kind == "class_definition":
                self.visit_class(child, scope)
            elif kind in ("import_statement", "import_from_statement"):
                self.visit_import(child)
            elif kind == "assignment":
                self.visit_assignment(child, scope, in_class=in_class)
                self.visit(child, scope, in_class=in_class)
            elif kind == "call":
                self.visit_call(child, scope)
                self.visit(child, scope, in_class=in_class)
            else:
                self.visit(child, scope, in_class=in_class)

    # -- definitions

    def visit_decorated(self, node: Any, scope: str, *, in_class: bool) -> None:
        decorators = [c for c in node.named_children if c.type == "decorator"]
        definition = _field(node, "definition")
        if definition is None:
            return
        if definition.type == "function_definition":
            self.visit_function(
                definition, scope, in_class=in_class, decorators=decorators
            )
        elif definition.type == "class_definition":
            self.visit_class(definition, scope)

    def visit_class(self, node: Any, scope: str) -> None:
        name = _field_text(node, "name", self.src)
        self.add_symbol(name, "class", node)
        body = _field(node, "body")
        if body is not None:
            self.extract_model(node, name, body)
            self.visit(body, name or scope, in_class=True)

    def visit_function(
        self, node: Any, scope: str, *, in_class: bool, decorators: list[Any]
    ) -> None:
        name = _field_text(node, "name", self.src)
        self.add_symbol(name, "method" if in_class else "function", node)

        params = _field(node, "parameters")
        if params is not None:
            self.extract_parameters(params, name)
        for decorator in decorators:
            self.extract_route(decorator, decorators, node, name, params)

        body = _field(node, "body")
        if body is not None:
            self.visit(body, name or scope, in_class=False)

    def extract_parameters(self, params: Any, owner: str) -> None:
        for param in params.named_children:
            if param.type == "identifier":
                target = param
            elif param.type in (
                "typed_parameter",
                "default_parameter",
                "typed_default_parameter",
            ):
                target = _field(param, "name") or next(
                    (c for c in param.named_children if c.type == "identifier"), None
                )
            else:
                continue
            if target is None:
                continue
            text = _text(target, self.src)
            if text in ("self", "cls"):
                continue
            self.add_pii(text, _line(target), "function_param", owner)

    # -- models

    def extract_model(self, class_node: Any, class_name: str, body: Any) -> None:
        table_name: str | None = None
        columns: list[ColumnInfo] = []

        for statement in body.named_children:
            inner = statement
            if statement.type == "expression_statement" and statement.named_children:
                inner = statement.named_children[0]

            if inner.type == "class_definition":
                # Django puts the table name on a nested Meta class.
                meta_body = _field(inner, "body")
                if _field_text(inner, "name", self.src) == "Meta" and meta_body:
                    table_name = table_name or self._meta_table_name(meta_body)
                continue
            if inner.type != "assignment":
                continue

            left = _field(inner, "left")
            right = _field(inner, "right")
            if left is None or left.type != "identifier":
                continue
            attribute = _text(left, self.src)

            if attribute == "__tablename__":
                table_name = table_name or _string_value(right, self.src)
                continue
            if right is None or right.type != "call":
                continue
            column = self._column_from_call(attribute, right, inner)
            if column is not None:
                columns.append(column)

        # A declarative base carries no columns and no table, and is not a model.
        if not table_name and not columns:
            return

        self.result.db_models.append(
            ModelInfo(
                class_name=class_name,
                table_name=table_name,
                file_path=self.path,
                line_number=_line(class_node),
                columns=columns,
            )
        )
        for column in columns:
            self.add_pii(
                column.name,
                column.line_number,
                "db_column",
                f"{class_name}.{column.name}",
            )

    def _meta_table_name(self, meta_body: Any) -> str | None:
        for statement in meta_body.named_children:
            inner = statement
            if statement.type == "expression_statement" and statement.named_children:
                inner = statement.named_children[0]
            if inner.type != "assignment":
                continue
            left = _field(inner, "left")
            if left is not None and _text(left, self.src) == "db_table":
                return _string_value(_field(inner, "right"), self.src)
        return None

    def _column_from_call(
        self, attribute: str, call: Any, assignment: Any
    ) -> ColumnInfo | None:
        declaration = self._column_declaration(call)
        if declaration is None:
            return None

        callee = _field_text(declaration, "function", self.src)
        base = _last_segment(callee).lower()
        column_type = _last_segment(callee)
        if base in SQLALCHEMY_COLUMN_CALLEES:
            column_type = (
                self._declared_type(_field(declaration, "arguments"))
                or self._annotation_type(assignment)
                or column_type
            )

        # Markers come from the whole right-hand side, not just the inner
        # declaration, so a field wrapped in encrypt(...) is still seen.
        blob = _identifier_blob(call, self.src)
        name_blob = attribute.lower()
        return ColumnInfo(
            name=attribute,
            column_type=column_type,
            line_number=_line(assignment),
            is_encrypted=_has_marker(blob, ENCRYPTION_MARKERS),
            is_hashed=_has_marker(blob, HASH_MARKERS)
            or _has_marker(name_blob, HASH_MARKERS),
            has_expiry=_has_marker(blob, EXPIRY_MARKERS)
            or _has_marker(name_blob, EXPIRY_MARKERS),
        )

    def _column_declaration(self, call: Any) -> Any | None:
        """The column or field call inside `call`, unwrapping any helper.

        django_cryptography writes encrypt(models.CharField(...)). Matching only
        the outermost callee would drop the column entirely, which is the worst
        outcome: an unreported column is an unreported piece of personal data.
        """
        for node in _descend(call):
            if node.type != "call":
                continue
            base = _last_segment(_field_text(node, "function", self.src)).lower()
            if (
                base in SQLALCHEMY_COLUMN_CALLEES
                or base in DJANGO_EXTRA_FIELD_CALLEES
                or base.endswith("field")
            ):
                return node
        return None

    def _declared_type(self, args: Any) -> str | None:
        """First positional argument of Column(...), reduced to its type name."""
        if args is None:
            return None
        for child in args.named_children:
            if child.type == "keyword_argument":
                continue
            if child.type == "call":
                return _last_segment(_field_text(child, "function", self.src))
            if child.type in ("identifier", "attribute"):
                return _last_segment(_text(child, self.src))
            return None
        return None

    def _annotation_type(self, assignment: Any) -> str | None:
        """Inner type of a `Mapped[...]` annotation, when the call gives none."""
        annotation = _field(assignment, "type")
        if annotation is None:
            return None
        for child in _descend(annotation):
            if child.type == "type_parameter":
                return _text(child, self.src).strip("[]")
        return _text(annotation, self.src)

    # -- routes

    def extract_route(
        self,
        decorator: Any,
        all_decorators: list[Any],
        function_node: Any,
        handler: str,
        params: Any,
    ) -> None:
        expression = decorator.named_children[0] if decorator.named_children else None
        if expression is None or expression.type != "call":
            return
        callee = _field(expression, "function")
        if callee is None or callee.type != "attribute":
            return

        verb = _field_text(callee, "attribute", self.src).lower()
        args = _field(expression, "arguments")
        path = _first_string_arg(args, self.src)
        if path is None:
            return

        if verb in HTTP_VERBS:
            methods = [verb.upper()]
            framework = "fastapi"
        elif verb in ("route", "add_url_rule"):
            methods = self._flask_methods(args)
            framework = "flask"
        else:
            return

        has_auth = self._route_has_auth(decorator, all_decorators, args, params)
        for method in methods:
            self.result.routes.append(
                RouteInfo(
                    http_method=method,
                    path=path,
                    handler_name=handler,
                    file_path=self.path,
                    line_number=_line(function_node),
                    has_auth=has_auth,
                    framework=framework,
                )
            )
        for param in _route_path_params(path):
            self.add_pii(param, _line(decorator), "route_param", path)

    def _flask_methods(self, args: Any) -> list[str]:
        if args is not None:
            for child in args.named_children:
                if child.type != "keyword_argument":
                    continue
                if _field_text(child, "name", self.src) != "methods":
                    continue
                value = _field(child, "value")
                found = {
                    (_string_value(item, self.src) or "").upper()
                    for item in _descend(value)
                    if _string_value(item, self.src)
                }
                if found:
                    return sorted(found)
        return ["GET"]

    def _route_has_auth(
        self, route_decorator: Any, all_decorators: list[Any], args: Any, params: Any
    ) -> bool:
        for decorator in all_decorators:
            if decorator is route_decorator:
                continue
            if _has_marker(_identifier_blob(decorator, self.src), AUTH_MARKERS):
                return True

        if args is not None:
            for child in args.named_children:
                if child.type != "keyword_argument":
                    continue
                if _field_text(child, "name", self.src) != "dependencies":
                    continue
                if _has_marker(_identifier_blob(child, self.src), AUTH_MARKERS):
                    return True

        if params is not None:
            for param in params.named_children:
                if param.type not in ("default_parameter", "typed_default_parameter"):
                    continue
                value = _field(param, "value")
                if value is None or value.type != "call":
                    continue
                injector = _last_segment(_field_text(value, "function", self.src))
                if injector not in ("Depends", "Security"):
                    continue
                if injector == "Security" or _has_marker(
                    _identifier_blob(param, self.src), AUTH_MARKERS
                ):
                    return True
        return False

    # -- statements

    def visit_import(self, node: Any) -> None:
        if node.type == "import_from_statement":
            self.record_import(_field_text(node, "module_name", self.src), node)
            return
        for child in node.named_children:
            if child.type == "aliased_import":
                child = _field(child, "name") or child
            self.record_import(_text(child, self.src), node)

    def visit_assignment(self, node: Any, scope: str, *, in_class: bool = False) -> None:
        left = _field(node, "left")
        right = _field(node, "right")
        if left is None:
            return

        targets = (
            left.named_children
            if left.type in ("pattern_list", "tuple_pattern")
            else [left]
        )
        for target in targets:
            if target.type == "identifier":
                name = _text(target, self.src)
            elif target.type == "attribute":
                name = _field_text(target, "attribute", self.src)
            else:
                continue
            self.record_transform_target(name, right)
            # A class-body assignment is a column or a class attribute and is
            # already reported as such, so do not repeat it as a variable.
            if not in_class:
                self.add_pii(name, _line(node), "variable", scope)

        if right is not None:
            for pair in _descend(right):
                if pair.type != "pair":
                    continue
                key = _string_value(_field(pair, "key"), self.src)
                if key:
                    self.add_pii(key, _line(pair), "dict_key", scope)

    def visit_call(self, node: Any, scope: str) -> None:
        callee = _field(node, "function")
        if callee is None:
            return
        if callee.type == "attribute":
            receiver = _field_text(callee, "object", self.src)
            method = _field_text(callee, "attribute", self.src)
        else:
            receiver = ""
            method = _text(callee, self.src)
        self.record_call(
            scope=scope,
            node=node,
            receiver=receiver,
            method=method,
            args=_field(node, "arguments"),
        )


# ------------------------------------------------------------ JavaScript / TS


class _JsExtractor(_Extractor):
    def run(self, root: Any) -> None:
        self.visit(root, self.module_symbol)

    def visit(self, node: Any, scope: str) -> None:
        for child in node.named_children:
            kind = child.type
            if kind in ("function_declaration", "generator_function_declaration"):
                name = _field_text(child, "name", self.src)
                self.add_symbol(name, "function", child)
                self.extract_js_params(child, name)
                self.visit(child, name or scope)
            elif kind in ("class_declaration", "abstract_class_declaration"):
                name = _field_text(child, "name", self.src)
                self.add_symbol(name, "class", child)
                self.visit(child, name or scope)
            elif kind == "method_definition":
                name = _field_text(child, "name", self.src)
                self.add_symbol(name, "method", child)
                self.extract_js_params(child, name)
                self.visit(child, name or scope)
            elif kind == "variable_declarator":
                self.visit_declarator(child, scope)
            elif kind == "import_statement":
                source = _field(child, "source")
                if source is not None:
                    self.record_import(_string_value(source, self.src) or "", child)
            elif kind == "call_expression":
                self.visit_call(child, scope)
            elif kind in ("assignment_expression", "augmented_assignment_expression"):
                self.visit_assignment(child, scope)
                self.visit(child, scope)
            else:
                self.visit(child, scope)

    def extract_js_params(self, node: Any, owner: str) -> None:
        params = _field(node, "parameters")
        if params is None:
            return
        for child in _descend(params):
            if child.type in ("identifier", "shorthand_property_identifier_pattern"):
                self.add_pii(
                    _text(child, self.src), _line(child), "function_param", owner
                )

    def visit_declarator(self, node: Any, scope: str) -> None:
        name_node = _field(node, "name")
        value = _field(node, "value")
        name = _text(name_node, self.src) if name_node is not None else ""

        if value is not None and value.type in (
            "arrow_function",
            "function_expression",
            "function",
        ):
            self.add_symbol(name, "function", node)
            self.extract_js_params(value, name)
            body = _field(value, "body")
            if body is not None:
                self.visit(body, name or scope)
            return

        if value is not None:
            if name_node is not None and name_node.type == "identifier":
                self.record_transform_target(name, value)
                self.add_pii(name, _line(node), "variable", scope)
            if self.extract_sequelize(node, name, value):
                # The model declaration is already reported as a ModelInfo;
                # re-reading it as a call would duplicate the same evidence.
                return
        self.visit(node, scope)

    def visit_assignment(self, node: Any, scope: str) -> None:
        left = _field(node, "left")
        right = _field(node, "right")
        if left is None:
            return
        if left.type == "member_expression":
            name = _field_text(left, "property", self.src)
        elif left.type == "identifier":
            name = _text(left, self.src)
        else:
            return
        self.record_transform_target(name, right)
        self.add_pii(name, _line(node), "variable", scope)

    # -- Sequelize and Mongoose models

    def extract_sequelize(self, declarator: Any, var_name: str, value: Any) -> bool:
        if value.type == "new_expression":
            callee = _field(value, "constructor")
            arguments = _field(value, "arguments")
        elif value.type == "call_expression":
            callee = _field(value, "function")
            arguments = _field(value, "arguments")
        else:
            return False
        if callee is None or arguments is None:
            return False

        method = _last_segment(_text(callee, self.src))
        if method not in ("define", "init", "Schema", "model"):
            return False
        objects = [c for c in arguments.named_children if c.type == "object"]
        if not objects:
            return False

        class_name = var_name or method
        table_name: str | None = None
        first_string = _first_string_arg(arguments, self.src)
        if method in ("define", "model") and first_string:
            class_name = first_string
            table_name = first_string
        if len(objects) > 1:
            table_name = (
                self._option_string(objects[-1], "tableName")
                or self._option_string(objects[-1], "collection")
                or table_name
            )

        columns = self._columns_from_object(objects[0])
        if not columns:
            return False

        self.result.db_models.append(
            ModelInfo(
                class_name=class_name,
                table_name=table_name,
                file_path=self.path,
                line_number=_line(declarator),
                columns=columns,
            )
        )
        for column in columns:
            self.add_pii(
                column.name,
                column.line_number,
                "db_column",
                f"{class_name}.{column.name}",
            )
        return True

    def _option_string(self, obj: Any, key: str) -> str | None:
        for pair in obj.named_children:
            if pair.type != "pair":
                continue
            if _field_text(pair, "key", self.src).strip("\"'") != key:
                continue
            return _string_value(_field(pair, "value"), self.src)
        return None

    def _columns_from_object(self, obj: Any) -> list[ColumnInfo]:
        columns: list[ColumnInfo] = []
        for pair in obj.named_children:
            if pair.type == "shorthand_property_identifier":
                name = _text(pair, self.src)
                value = pair
            elif pair.type == "pair":
                name = _field_text(pair, "key", self.src).strip("\"'")
                value = _field(pair, "value") or pair
            else:
                continue
            if not name or not _IDENT_RE.match(name):
                continue

            if value.type == "object":
                column_type = self._option_type(value) or "object"
            else:
                column_type = _type_label(_text(value, self.src))

            blob = _identifier_blob(pair, self.src)
            name_blob = name.lower()
            columns.append(
                ColumnInfo(
                    name=name,
                    column_type=column_type[:60],
                    line_number=_line(pair),
                    is_encrypted=_has_marker(blob, ENCRYPTION_MARKERS),
                    is_hashed=_has_marker(blob, HASH_MARKERS)
                    or _has_marker(name_blob, HASH_MARKERS),
                    has_expiry=_has_marker(blob, EXPIRY_MARKERS)
                    or _has_marker(name_blob, EXPIRY_MARKERS),
                )
            )
        return columns

    def _option_type(self, obj: Any) -> str | None:
        for pair in obj.named_children:
            if pair.type != "pair":
                continue
            if _field_text(pair, "key", self.src).strip("\"'") != "type":
                continue
            value = _field(pair, "value")
            return _type_label(_text(value, self.src)) if value is not None else None
        return None

    # -- calls and Express routes

    def visit_call(self, node: Any, scope: str) -> None:
        callee = _field(node, "function")
        args = _field(node, "arguments")
        if callee is None:
            return

        if callee.type == "member_expression":
            receiver = _field_text(callee, "object", self.src)
            method = _field_text(callee, "property", self.src)
        else:
            receiver = ""
            method = _text(callee, self.src)

        if method == "require" and args is not None:
            self.record_import(_first_string_arg(args, self.src) or "", node)

        if not self.extract_express_route(node, receiver, method, args):
            self.record_call(
                scope=scope, node=node, receiver=receiver, method=method, args=args
            )
        # The handler body still holds the log and db calls worth recording.
        if args is not None:
            self.visit(args, scope)

    def extract_express_route(
        self, node: Any, receiver: str, method: str, args: Any
    ) -> bool:
        verb = method.lower()
        if verb not in HTTP_VERBS and verb != "all":
            return False
        if args is None:
            return False
        children = args.named_children
        # Express is (path, ...middleware, handler); axios.get(url) is not.
        if len(children) < 2:
            return False
        path = _string_value(children[0], self.src)
        if path is None or not path.startswith("/"):
            return False
        if _last_segment(receiver).lower() in HTTP_CLIENT_NAMES:
            return False

        handler = children[-1]
        if handler.type not in (
            "arrow_function",
            "function_expression",
            "function",
            "identifier",
            "member_expression",
            "call_expression",
        ):
            return False

        middleware = children[1:-1]
        has_auth = any(
            _has_marker(_identifier_blob(m, self.src), AUTH_MARKERS) for m in middleware
        )
        if handler.type in ("identifier", "member_expression"):
            handler_name = _text(handler, self.src)
        else:
            handler_name = _field_text(handler, "name", self.src) or f"{verb} {path}"

        self.result.routes.append(
            RouteInfo(
                http_method=verb.upper(),
                path=path,
                handler_name=handler_name,
                file_path=self.path,
                line_number=_line(node),
                has_auth=has_auth,
                framework="express",
            )
        )
        for param in _route_path_params(path):
            self.add_pii(param, _line(node), "route_param", path)
        return True


# ---------------------------------------------------------------------- Java


class _JavaExtractor(_Extractor):
    MAPPING_VERBS: ClassVar[dict[str, str]] = {
        "GetMapping": "GET",
        "PostMapping": "POST",
        "PutMapping": "PUT",
        "PatchMapping": "PATCH",
        "DeleteMapping": "DELETE",
    }

    def run(self, root: Any) -> None:
        self.visit(root, self.module_symbol)

    def visit(self, node: Any, scope: str) -> None:
        for child in node.named_children:
            kind = child.type
            if kind in ("class_declaration", "record_declaration"):
                self.visit_class(child, scope)
            elif kind == "import_declaration":
                module = _text(child, self.src).removeprefix("import").strip(" ;\n")
                self.record_import(module.removeprefix("static ").strip(), child)
            elif kind == "method_invocation":
                self.visit_invocation(child, scope)
                self.visit(child, scope)
            elif kind == "assignment_expression":
                self.visit_assignment(child, scope)
                self.visit(child, scope)
            else:
                self.visit(child, scope)

    def visit_class(self, node: Any, scope: str) -> None:
        name = _field_text(node, "name", self.src)
        self.add_symbol(name, "class", node)
        annotations = self._annotations(node)
        prefix = self._class_route_prefix(annotations)
        class_auth = self._annotations_have_auth(annotations)
        body = _field(node, "body")
        if body is None:
            return
        self.extract_entity(node, name, body, annotations)

        for member in body.named_children:
            if member.type in ("method_declaration", "constructor_declaration"):
                method_name = _field_text(member, "name", self.src)
                self.add_symbol(method_name, "method", member)
                member_annotations = self._annotations(member)
                self.extract_mapping(
                    member, method_name, member_annotations, prefix, class_auth
                )
                self.extract_java_params(member, method_name)
                inner = _field(member, "body")
                if inner is not None:
                    self.visit(inner, method_name or name or scope)
            else:
                self.visit(member, name or scope)

    def extract_java_params(self, method: Any, owner: str) -> None:
        params = _field(method, "parameters")
        if params is None:
            return
        for param in params.named_children:
            name = _field_text(param, "name", self.src)
            if name:
                self.add_pii(name, _line(param), "function_param", owner)

    # -- annotations

    def _annotations(self, node: Any) -> list[Any]:
        modifiers = next((c for c in node.named_children if c.type == "modifiers"), None)
        if modifiers is None:
            return []
        return [
            c
            for c in modifiers.named_children
            if c.type in ("annotation", "marker_annotation")
        ]

    def _annotation_named(self, annotations: list[Any], name: str) -> Any | None:
        for annotation in annotations:
            if _field_text(annotation, "name", self.src) == name:
                return annotation
        return None

    def _annotations_have_auth(self, annotations: list[Any]) -> bool:
        return any(
            _has_marker(_text(a, self.src).lower(), AUTH_MARKERS) for a in annotations
        )

    def _annotation_value(self, annotation: Any, key: str | None = None) -> str | None:
        args = _field(annotation, "arguments")
        if args is None:
            return None
        for child in args.named_children:
            if child.type == "element_value_pair":
                if key is not None and _field_text(child, "key", self.src) == key:
                    return _string_value(_field(child, "value"), self.src)
                continue
            if key is None:
                value = _string_value(child, self.src)
                if value is not None:
                    return value
        return None

    def _class_route_prefix(self, annotations: list[Any]) -> str:
        mapping = self._annotation_named(annotations, "RequestMapping")
        if mapping is None:
            return ""
        return (
            self._annotation_value(mapping)
            or self._annotation_value(mapping, "value")
            or self._annotation_value(mapping, "path")
            or ""
        )

    # -- JPA entities

    def extract_entity(
        self, class_node: Any, class_name: str, body: Any, annotations: list[Any]
    ) -> None:
        if self._annotation_named(annotations, "Entity") is None:
            return

        table = self._annotation_named(annotations, "Table")
        table_name = self._annotation_value(table, "name") if table is not None else None

        columns: list[ColumnInfo] = []
        for member in body.named_children:
            if member.type != "field_declaration":
                continue
            if "static" in _field_text(member, "modifiers", self.src).split():
                continue
            declarator = _field(member, "declarator")
            if declarator is None:
                continue
            field_name = _field_text(declarator, "name", self.src)
            if not field_name:
                continue

            field_annotations = self._annotations(member)
            column_annotation = self._annotation_named(field_annotations, "Column")
            column_name = (
                self._annotation_value(column_annotation, "name")
                if column_annotation is not None
                else None
            ) or field_name

            # Annotation arguments are declarations, not prose, so the string
            # values there (a converter class, a pgcrypto expression) are
            # legitimate evidence in a way that a code comment is not.
            annotation_text = " ".join(
                _text(a, self.src) for a in field_annotations
            ).lower()
            name_blob = f"{field_name} {column_name}".lower()
            columns.append(
                ColumnInfo(
                    name=column_name,
                    column_type=_field_text(member, "type", self.src),
                    line_number=_line(member),
                    is_encrypted=_has_marker(annotation_text, ENCRYPTION_MARKERS),
                    is_hashed=_has_marker(annotation_text, HASH_MARKERS)
                    or _has_marker(name_blob, HASH_MARKERS),
                    has_expiry=_has_marker(annotation_text, EXPIRY_MARKERS)
                    or _has_marker(name_blob, EXPIRY_MARKERS),
                )
            )

        self.result.db_models.append(
            ModelInfo(
                class_name=class_name,
                table_name=table_name,
                file_path=self.path,
                line_number=_line(class_node),
                columns=columns,
            )
        )
        for column in columns:
            self.add_pii(
                column.name,
                column.line_number,
                "db_column",
                f"{class_name}.{column.name}",
            )

    # -- Spring mappings

    def extract_mapping(
        self,
        method_node: Any,
        handler: str,
        annotations: list[Any],
        prefix: str,
        class_auth: bool,
    ) -> None:
        has_auth = class_auth or self._annotations_have_auth(annotations)
        for annotation in annotations:
            name = _field_text(annotation, "name", self.src)
            verb = self.MAPPING_VERBS.get(name)
            if verb is None and name != "RequestMapping":
                continue
            suffix = (
                self._annotation_value(annotation)
                or self._annotation_value(annotation, "value")
                or self._annotation_value(annotation, "path")
                or ""
            )
            if verb is None:
                text = _text(annotation, self.src)
                verb = next(
                    (v for v in HTTP_VERBS if f"RequestMethod.{v.upper()}" in text),
                    "get",
                ).upper()
            path = _join_paths(prefix, suffix)
            self.result.routes.append(
                RouteInfo(
                    http_method=verb,
                    path=path,
                    handler_name=handler,
                    file_path=self.path,
                    line_number=_line(method_node),
                    has_auth=has_auth,
                    framework="spring",
                )
            )
            for param in _route_path_params(path):
                self.add_pii(param, _line(annotation), "route_param", path)

    # -- statements

    def visit_invocation(self, node: Any, scope: str) -> None:
        self.record_call(
            scope=scope,
            node=node,
            receiver=_field_text(node, "object", self.src),
            method=_field_text(node, "name", self.src),
            args=_field(node, "arguments"),
        )

    def visit_assignment(self, node: Any, scope: str) -> None:
        left = _field(node, "left")
        right = _field(node, "right")
        if left is None:
            return
        if left.type == "field_access":
            name = _field_text(left, "field", self.src)
        elif left.type == "identifier":
            name = _text(left, self.src)
        else:
            return
        self.record_transform_target(name, right)
        self.add_pii(name, _line(node), "variable", scope)


# ------------------------------------------------------------------------ Go


class _GoExtractor(_Extractor):
    def run(self, root: Any) -> None:
        self.table_names = self._collect_table_names(root)
        self.visit(root, self.module_symbol)

    def _collect_table_names(self, root: Any) -> dict[str, str]:
        """`func (X) TableName() string { return "..." }` is GORM's table hook."""
        names: dict[str, str] = {}
        for node in _descend(root):
            if node.type != "method_declaration":
                continue
            if _field_text(node, "name", self.src) != "TableName":
                continue
            receiver = _field(node, "receiver")
            body = _field(node, "body")
            if receiver is None or body is None:
                continue
            receiver_type = _last_segment(
                _text(receiver, self.src).strip("()").replace("*", "")
            )
            for child in _descend(body):
                value = _string_value(child, self.src)
                if value:
                    names[receiver_type] = value
                    break
        return names

    def visit(self, node: Any, scope: str) -> None:
        for child in node.named_children:
            kind = child.type
            if kind in ("function_declaration", "method_declaration"):
                name = _field_text(child, "name", self.src)
                self.add_symbol(
                    name, "method" if kind == "method_declaration" else "function", child
                )
                self.extract_go_params(child, name)
                body = _field(child, "body")
                if body is not None:
                    self.visit(body, name or scope)
            elif kind == "type_declaration":
                self.visit_type_declaration(child, scope)
            elif kind == "import_declaration":
                for spec in _descend(child):
                    value = _string_value(spec, self.src)
                    if value:
                        self.record_import(value, child)
            elif kind == "call_expression":
                self.visit_call(child, scope)
                self.visit(child, scope)
            elif kind in ("assignment_statement", "short_var_declaration"):
                self.visit_assignment(child, scope)
                self.visit(child, scope)
            else:
                self.visit(child, scope)

    def extract_go_params(self, node: Any, owner: str) -> None:
        params = _field(node, "parameters")
        if params is None:
            return
        for param in params.named_children:
            name = _field_text(param, "name", self.src)
            if name:
                self.add_pii(name, _line(param), "function_param", owner)

    def visit_type_declaration(self, node: Any, scope: str) -> None:
        for spec in node.named_children:
            if spec.type != "type_spec":
                continue
            struct = _field(spec, "type")
            if struct is None or struct.type != "struct_type":
                continue
            name = _field_text(spec, "name", self.src)
            self.add_symbol(name, "class", spec)
            self.extract_struct_model(spec, name, struct)

    def extract_struct_model(self, spec: Any, name: str, struct: Any) -> None:
        field_list = next(
            (c for c in struct.named_children if c.type == "field_declaration_list"), None
        )
        if field_list is None:
            return

        columns: list[ColumnInfo] = []
        persisted = False
        for declaration in field_list.named_children:
            if declaration.type != "field_declaration":
                continue
            tag_node = _field(declaration, "tag")
            tag = (_string_value(tag_node, self.src) or "") if tag_node is not None else ""
            if any(marker in tag for marker in ("gorm:", "db:", "sql:", "bson:")):
                persisted = True

            field_name = _field_text(declaration, "name", self.src)
            if not field_name:
                # An embedded gorm.Model still marks the struct as persisted.
                if "gorm.Model" in _text(declaration, self.src):
                    persisted = True
                continue

            match = _GO_TAG_COLUMN_RE.search(tag)
            column_name = match.group(1) if match else field_name
            # Struct tags are declarations, so their contents count as evidence.
            blob = f"{_identifier_blob(declaration, self.src)} {tag.lower()}"
            name_blob = f"{field_name} {column_name}".lower()
            columns.append(
                ColumnInfo(
                    name=column_name,
                    column_type=_field_text(declaration, "type", self.src),
                    line_number=_line(declaration),
                    is_encrypted=_has_marker(blob, ENCRYPTION_MARKERS),
                    is_hashed=_has_marker(blob, HASH_MARKERS)
                    or _has_marker(name_blob, HASH_MARKERS),
                    has_expiry=_has_marker(blob, EXPIRY_MARKERS)
                    or _has_marker(name_blob, EXPIRY_MARKERS),
                )
            )

        if not persisted or not columns:
            return

        self.result.db_models.append(
            ModelInfo(
                class_name=name,
                table_name=self.table_names.get(name),
                file_path=self.path,
                line_number=_line(spec),
                columns=columns,
            )
        )
        for column in columns:
            self.add_pii(
                column.name, column.line_number, "db_column", f"{name}.{column.name}"
            )

    def visit_call(self, node: Any, scope: str) -> None:
        callee = _field(node, "function")
        args = _field(node, "arguments")
        if callee is None:
            return
        if callee.type == "selector_expression":
            receiver = _field_text(callee, "operand", self.src)
            method = _field_text(callee, "field", self.src)
        else:
            receiver = ""
            method = _text(callee, self.src)

        if not self.extract_go_route(node, receiver, method, args):
            self.record_call(
                scope=scope, node=node, receiver=receiver, method=method, args=args
            )

    def extract_go_route(self, node: Any, receiver: str, method: str, args: Any) -> bool:
        """gin/echo/chi `r.GET("/p", h)` and net/http `HandleFunc("/p", h)`."""
        if args is None:
            return False
        children = args.named_children
        if len(children) < 2:
            return False
        path = _string_value(children[0], self.src)
        if path is None or not path.startswith("/"):
            return False

        verb = method.lower()
        if verb in HTTP_VERBS:
            if _last_segment(receiver).lower() in HTTP_CLIENT_NAMES:
                return False
            framework = "gin"
        elif verb in ("handlefunc", "handle"):
            verb = "get"
            framework = "net/http"
        else:
            return False

        has_auth = any(
            _has_marker(_identifier_blob(m, self.src), AUTH_MARKERS)
            for m in children[1:-1]
        )
        self.result.routes.append(
            RouteInfo(
                http_method=verb.upper(),
                path=path,
                handler_name=_text(children[-1], self.src).split("\n")[0][:80],
                file_path=self.path,
                line_number=_line(node),
                has_auth=has_auth,
                framework=framework,
            )
        )
        for param in _route_path_params(path):
            self.add_pii(param, _line(node), "route_param", path)
        return True

    def visit_assignment(self, node: Any, scope: str) -> None:
        left = _field(node, "left")
        right = _field(node, "right")
        if left is None or right is None:
            return
        for target in left.named_children:
            if target.type == "selector_expression":
                name = _field_text(target, "field", self.src)
            elif target.type == "identifier":
                name = _text(target, self.src)
            else:
                continue
            self.record_transform_target(name, right)
            self.add_pii(name, _line(node), "variable", scope)


EXTRACTORS: dict[str, type[_Extractor]] = {
    "python": _PythonExtractor,
    "javascript": _JsExtractor,
    "typescript": _JsExtractor,
    "tsx": _JsExtractor,
    "java": _JavaExtractor,
    "go": _GoExtractor,
}


# -------------------------------------------------------------- file walking


def _iter_source_files(root: Path, limit: int) -> Iterator[tuple[Path, str, str]]:
    """(path, language, grammar) for every scannable file under root."""
    yielded = 0
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            entries = sorted(current.iterdir())
        except OSError as exc:
            logger.warning("cannot list %s: %s", current, exc)
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name in SKIP_DIRECTORIES or entry.name.startswith("."):
                    continue
                stack.append(entry)
                continue
            suffix = entry.suffix.lower()
            language = LANGUAGE_BY_EXTENSION.get(suffix)
            grammar = _grammar_for_suffix(suffix)
            if language is None or grammar is None:
                continue
            if yielded >= limit:
                logger.warning("file cap %s reached, remaining files skipped", limit)
                return
            yielded += 1
            yield entry, language, grammar


def _scan_file(
    state: _ScanState, path: Path, rel_path: str, language: str, grammar: str
) -> None:
    parser = _parser_for(grammar)
    if parser is None:
        return

    try:
        raw = path.read_bytes()
    except OSError as exc:
        logger.warning("skipping %s: %s", rel_path, exc)
        return
    if len(raw) > MAX_FILE_BYTES:
        logger.warning("skipping %s: %d bytes exceeds the scan limit", rel_path, len(raw))
        return

    try:
        tree = parser.parse(raw)
    except Exception as exc:
        logger.warning("skipping %s: parse failed (%s)", rel_path, exc)
        return

    state.result.files.append(
        FileInfo(
            path=rel_path,
            language=language,
            line_count=raw.count(b"\n") + (1 if raw and not raw.endswith(b"\n") else 0),
        )
    )
    if tree.root_node.has_error:
        # A partial tree still carries usable structure, so extract anyway.
        logger.debug("%s parsed with syntax errors, using the partial tree", rel_path)

    extractor_cls = EXTRACTORS.get(grammar)
    if extractor_cls is None:
        return
    try:
        extractor_cls(state, rel_path, raw).run(tree.root_node)
    except RecursionError:
        logger.warning("skipping %s: syntax tree too deep to walk", rel_path)
    except Exception as exc:
        logger.warning("skipping %s: extraction failed (%s)", rel_path, exc)


# --------------------------------------------------------- resolution passes


def _resolve_calls(state: _ScanState) -> None:
    """Turn recorded call sites into edges.

    An unresolved call into a third-party helper is dropped unless it carries
    PII or is already typed as a sink, otherwise the graph fills with stdlib
    noise that every downstream consumer has to filter back out.
    """
    by_file: dict[tuple[str, str], SymbolInfo] = {}
    by_name: dict[str, SymbolInfo] = {}
    for symbol in state.result.symbols:
        by_file.setdefault((symbol.file_path, symbol.name), symbol)
        by_name.setdefault(symbol.name, symbol)

    for call in state.calls:
        if call.edge_type is not None:
            state.result.data_flow_edges.append(
                DataFlowEdgeInfo(
                    source_symbol=call.caller_symbol,
                    source_file=call.caller_file,
                    source_line=call.line,
                    sink_symbol=call.sink_label or call.callee_text,
                    sink_file=call.caller_file,
                    sink_line=call.line,
                    edge_type=call.edge_type,
                    pii_categories=list(call.pii_categories),
                )
            )
            continue

        target = by_file.get((call.caller_file, call.callee_name)) or by_name.get(
            call.callee_name
        )
        if target is not None:
            if (
                target.name == call.caller_symbol
                and target.file_path == call.caller_file
            ):
                continue
            state.result.data_flow_edges.append(
                DataFlowEdgeInfo(
                    source_symbol=call.caller_symbol,
                    source_file=call.caller_file,
                    source_line=call.line,
                    sink_symbol=target.name,
                    sink_file=target.file_path,
                    sink_line=target.line_number,
                    edge_type=EdgeType.CALLS.value,
                    pii_categories=list(call.pii_categories),
                )
            )
        elif call.pii_categories:
            state.result.data_flow_edges.append(
                DataFlowEdgeInfo(
                    source_symbol=call.caller_symbol,
                    source_file=call.caller_file,
                    source_line=call.line,
                    sink_symbol=call.callee_text,
                    sink_file=call.caller_file,
                    sink_line=call.line,
                    edge_type=EdgeType.DATA_PASS.value,
                    pii_categories=list(call.pii_categories),
                )
            )


def _resolve_imports(state: _ScanState) -> None:
    by_module: dict[str, str] = {}
    for info in state.result.files:
        dotted = info.path.rsplit(".", 1)[0].replace("/", ".")
        by_module.setdefault(dotted, info.path)
        by_module.setdefault(dotted.rsplit(".", 1)[-1], info.path)

    for entry in state.imports:
        module = entry.module.strip().strip("\"'")
        if not module:
            continue
        normalized = module.lstrip("./").replace("/", ".")
        target = by_module.get(normalized) or by_module.get(normalized.rsplit(".", 1)[-1])
        state.result.data_flow_edges.append(
            DataFlowEdgeInfo(
                source_symbol=entry.caller_symbol,
                source_file=entry.caller_file,
                source_line=entry.line,
                sink_symbol=module[:MAX_SYMBOL_CHARS],
                sink_file=target or "",
                sink_line=1,
                edge_type=EdgeType.IMPORTS.value,
                pii_categories=[],
            )
        )


def _apply_transform_correlation(state: _ScanState) -> None:
    """Promote is_hashed and is_encrypted from assignments elsewhere in the file."""
    for model in state.result.db_models:
        for column in model.columns:
            key = (model.file_path, _normalize(column.name))
            if key in state.hashed_targets:
                column.is_hashed = True
            if key in state.encrypted_targets:
                column.is_encrypted = True


def _dedupe(state: _ScanState) -> None:
    result = state.result

    seen_pii: set[tuple] = set()
    unique_pii: list[PIIFieldRef] = []
    for ref in result.pii_fields:
        key = (ref.field_name, ref.file_path, ref.line_number, ref.location_kind)
        if key in seen_pii:
            continue
        seen_pii.add(key)
        unique_pii.append(ref)
    result.pii_fields = unique_pii

    seen_edges: set[tuple] = set()
    unique_edges: list[DataFlowEdgeInfo] = []
    for edge in result.data_flow_edges:
        key = (
            edge.source_symbol,
            edge.source_file,
            edge.source_line,
            edge.sink_symbol,
            edge.sink_file,
            edge.sink_line,
            edge.edge_type,
        )
        if key in seen_edges:
            continue
        seen_edges.add(key)
        unique_edges.append(edge)
    result.data_flow_edges = unique_edges

    seen_routes: set[tuple] = set()
    unique_routes: list[RouteInfo] = []
    for route in result.routes:
        key = (route.http_method, route.path, route.file_path, route.line_number)
        if key in seen_routes:
            continue
        seen_routes.add(key)
        unique_routes.append(route)
    result.routes = unique_routes


# ---------------------------------------------------------------- entry point


def _scan_directory_sync(root_path: str) -> CodeScanResult:
    root = Path(root_path).resolve()
    result = CodeScanResult(root_path=str(root))
    state = _ScanState(result=result)

    if not root.is_dir():
        logger.warning("scan root %s is not a directory", root)
        return result

    limit = max(1, int(getattr(settings, "max_files_per_scan", 5000)))
    for path, language, grammar in _iter_source_files(root, limit):
        try:
            rel_path = path.relative_to(root).as_posix()
        except ValueError:
            rel_path = path.as_posix()
        _scan_file(state, path, rel_path, language, grammar)

    _resolve_calls(state)
    _resolve_imports(state)
    _apply_transform_correlation(state)
    _dedupe(state)

    logger.info(
        "scanned %d files: %d symbols, %d models, %d routes, %d pii fields, %d edges",
        len(result.files),
        len(result.symbols),
        len(result.db_models),
        len(result.routes),
        len(result.pii_fields),
        len(result.data_flow_edges),
    )
    return result


async def scan_directory(root_path: str) -> CodeScanResult:
    """Walk root_path and build a CodeScanResult.

    Parsing is CPU bound, so it runs off the event loop: the API process keeps
    serving while a large repository is being walked.
    """
    return await asyncio.to_thread(_scan_directory_sync, root_path)
