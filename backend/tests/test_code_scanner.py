"""Tests for the tree-sitter code scanner.

The scanner is the evidence layer, so every assertion here is about what is
structurally present, never about whether the fixture is compliant.
"""

import asyncio

import pytest

from app.contracts import PIIFieldRef
from app.models.enums import EdgeType
from app.pii import field_classifier
from app.scanner import code_scanner

# The scanner owns structure, the PII module owns the taxonomy. These two land
# independently, so if the classifier is still a stub the fixture below swaps in
# a minimal stand-in and the structural assertions still mean something. Once
# field_classifier is implemented it steps aside and the real one is exercised.
_FALLBACK_CATEGORIES = {
    "aadhaar": ("aadhaar", "critical"),
    "pan": ("pan", "critical"),
    "password": ("password", "critical"),
    "email": ("email", "medium"),
    "phone": ("phone", "medium"),
    "name": ("name", "low"),
}


def _fallback_classify(field_name: str, *, nearby_literal: str | None = None):
    normalized = (field_name or "").strip().lower()
    tokens = {t for t in normalized.replace("-", "_").split("_") if t}
    for token, (category, _sensitivity) in _FALLBACK_CATEGORIES.items():
        if token in tokens:
            return category
    return None


def _fallback_build_field_ref(field_name: str, **kwargs) -> PIIFieldRef | None:
    category = _fallback_classify(field_name)
    if category is None:
        return None
    sensitivity = next(
        s for c, s in _FALLBACK_CATEGORIES.values() if c == category
    )
    return PIIFieldRef(
        field_name=field_name, pii_category=category, sensitivity=sensitivity, **kwargs
    )


@pytest.fixture(autouse=True)
def _classifier(monkeypatch):
    try:
        implemented = bool(field_classifier.classify("email_address"))
    except Exception:
        implemented = False
    if implemented:
        return
    monkeypatch.setattr(field_classifier, "classify", _fallback_classify)
    monkeypatch.setattr(field_classifier, "build_field_ref", _fallback_build_field_ref)


def scan(path) -> "code_scanner.CodeScanResult":
    return asyncio.run(code_scanner.scan_directory(str(path)))


@pytest.fixture
def vulnerable_py(fixtures_dir):
    return scan(fixtures_dir / "vulnerable_py")


@pytest.fixture
def multi_lang(fixtures_dir):
    return scan(fixtures_dir / "multi_lang")


@pytest.fixture
def subscriber(vulnerable_py):
    return model_in(vulnerable_py, "models.py")


def model_in(result, file_path):
    return next(m for m in result.db_models if m.file_path == file_path)


def column(model, column_name):
    return next(c for c in model.columns if c.name == column_name)


def edges_of(result, edge_type):
    return [e for e in result.data_flow_edges if e.edge_type == edge_type]


# ------------------------------------------------------------------- files


def test_every_python_file_is_walked(vulnerable_py):
    paths = {f.path for f in vulnerable_py.files}
    assert paths == {"models.py", "notices.py", "partners.py", "routes.py"}
    assert {f.language for f in vulnerable_py.files} == {"python"}
    assert all(f.line_count > 0 for f in vulnerable_py.files)


# ------------------------------------------------------------------ symbols


def test_symbols_carry_kind_and_line_range(vulnerable_py):
    by_name = {s.name: s for s in vulnerable_py.symbols}

    assert by_name["Subscriber"].kind == "class"
    assert by_name["Subscriber"].file_path == "models.py"
    assert by_name["set_password"].kind == "method"
    assert by_name["register_subscriber"].kind == "function"

    for symbol in vulnerable_py.symbols:
        assert symbol.end_line is not None
        assert symbol.end_line >= symbol.line_number


# ------------------------------------------------------------------- models


def test_model_and_columns_are_found(vulnerable_py):
    assert len(vulnerable_py.db_models) == 1
    model = vulnerable_py.db_models[0]

    assert model.class_name == "Subscriber"
    assert model.table_name == "subscribers"
    assert model.file_path == "models.py"

    names = [c.name for c in model.columns]
    assert names == [
        "id",
        "full_name",
        "email_address",
        "aadhaar_number",
        "pan_number",
        "password_hash",
        "recovery_answer",
        "retention_expires_at",
    ]
    assert column(model, "aadhaar_number").column_type == "String"
    assert column(model, "id").line_number == 17


def test_plaintext_aadhaar_column_is_not_flagged_as_protected(subscriber):
    aadhaar = column(subscriber, "aadhaar_number")
    assert aadhaar.is_encrypted is False
    assert aadhaar.is_hashed is False
    assert aadhaar.has_expiry is False


def test_encrypted_control_column_is_flagged(subscriber):
    pan = column(subscriber, "pan_number")
    assert pan.is_encrypted is True
    assert pan.is_hashed is False
    assert pan.column_type == "StringEncryptedType"


def test_hashed_column_is_flagged(subscriber):
    assert column(subscriber, "password_hash").is_hashed is True


def test_hashing_is_correlated_from_the_assignment_not_the_name(subscriber):
    # recovery_answer has no hash-like name. The only evidence is the
    # hashlib.sha256 assignment in set_recovery_answer.
    recovery = column(subscriber, "recovery_answer")
    assert recovery.is_hashed is True
    assert recovery.is_encrypted is False


def test_expiry_column_is_flagged(subscriber):
    assert column(subscriber, "retention_expires_at").has_expiry is True
    assert column(subscriber, "email_address").has_expiry is False


# ------------------------------------------------------------------- routes


def test_route_auth_is_detected_in_both_directions(vulnerable_py):
    by_path = {r.path: r for r in vulnerable_py.routes}
    assert set(by_path) == {"/subscribers", "/subscribers/{subscriber_id}"}

    unguarded = by_path["/subscribers"]
    assert unguarded.http_method == "POST"
    assert unguarded.handler_name == "register_subscriber"
    assert unguarded.framework == "fastapi"
    assert unguarded.has_auth is False

    guarded = by_path["/subscribers/{subscriber_id}"]
    assert guarded.http_method == "GET"
    assert guarded.has_auth is True


# ---------------------------------------------------------------- pii fields


def test_columns_are_reported_as_pii_fields(vulnerable_py):
    columns = {
        ref.field_name: ref
        for ref in vulnerable_py.pii_fields
        if ref.location_kind == "db_column"
    }
    aadhaar = columns["aadhaar_number"]
    assert aadhaar.file_path == "models.py"
    assert aadhaar.pii_category
    assert aadhaar.sensitivity
    assert "email_address" in columns


def test_outbound_payload_fields_are_reported(vulnerable_py):
    payload = {
        ref.field_name
        for ref in vulnerable_py.pii_fields
        if ref.location_kind == "api_payload"
    }
    assert {"email_address", "phone_number"} <= payload


def test_string_literals_and_comments_are_not_fields(vulnerable_py):
    # The whole case for tree-sitter over a regex: notices.py is full of
    # personal-data words, none of which is a field.
    assert [r for r in vulnerable_py.pii_fields if r.file_path == "notices.py"] == []
    tainted = [e for e in vulnerable_py.data_flow_edges if e.pii_categories]
    assert [e for e in tainted if e.source_file == "notices.py"] == []


# -------------------------------------------------------------------- edges


def test_log_output_edge_carries_a_pii_category(vulnerable_py):
    logs = edges_of(vulnerable_py, EdgeType.LOG_OUTPUT.value)
    assert logs, "logger.info call was not detected"

    tainted = [e for e in logs if e.pii_categories]
    assert tainted, "no log_output edge carried a pii category"

    edge = tainted[0]
    assert edge.source_symbol == "register_subscriber"
    assert edge.source_file == "routes.py"
    assert edge.sink_symbol == "logger.info"
    assert all(isinstance(c, str) and c for c in edge.pii_categories)


def test_api_send_edge_reaches_the_external_call(vulnerable_py):
    sends = edges_of(vulnerable_py, EdgeType.API_SEND.value)
    assert [e for e in sends if e.source_symbol == "forward_to_partner"]
    assert any(e.pii_categories for e in sends)


def test_db_write_and_db_read_edges_are_separated(vulnerable_py):
    writes = edges_of(vulnerable_py, EdgeType.DB_WRITE.value)
    reads = edges_of(vulnerable_py, EdgeType.DB_READ.value)
    assert {e.sink_symbol for e in writes} >= {"session.add", "session.commit"}
    assert reads and all(e.source_symbol == "read_subscriber" for e in reads)


def test_calls_edges_resolve_across_files(vulnerable_py):
    calls = edges_of(vulnerable_py, EdgeType.CALLS.value)
    cross_file = {
        (e.source_symbol, e.sink_symbol)
        for e in calls
        if e.source_file != e.sink_file
    }
    assert ("register_subscriber", "forward_to_partner") in cross_file


def test_import_edges_link_local_modules(vulnerable_py):
    imports = edges_of(vulnerable_py, EdgeType.IMPORTS.value)
    local = {e.sink_symbol: e.sink_file for e in imports}
    assert local["models"] == "models.py"
    assert local["partners"] == "partners.py"


def test_every_edge_type_is_a_known_enum_value(vulnerable_py):
    allowed = {e.value for e in EdgeType}
    assert {e.edge_type for e in vulnerable_py.data_flow_edges} <= allowed


# ---------------------------------------------------------- other languages


def test_javascript_sequelize_model_and_express_routes(multi_lang):
    model = model_in(multi_lang, "store.js")
    assert model.table_name == "subscribers"
    assert column(model, "aadhaar_number").is_encrypted is False
    assert column(model, "pan_number").is_encrypted is True
    assert column(model, "session_expires_at").has_expiry is True

    routes = {r.path: r for r in multi_lang.routes if r.file_path == "store.js"}
    assert routes["/subscribers"].has_auth is False
    assert routes["/subscribers/:subscriberId"].has_auth is True

    console = [
        e
        for e in edges_of(multi_lang, EdgeType.LOG_OUTPUT.value)
        if e.source_file == "store.js"
    ]
    assert console and console[0].pii_categories


def test_javascript_mongoose_schema_is_read_as_a_model(multi_lang):
    model = model_in(multi_lang, "profiles.js")
    assert model.table_name == "profiles"
    assert column(model, "aadhaar_number").is_encrypted is False
    assert column(model, "pan_number").is_encrypted is True
    assert column(model, "token_ttl").has_expiry is True


def test_django_model_including_a_wrapped_field(multi_lang):
    model = model_in(multi_lang, "django_store.py")
    assert model.table_name == "django_citizens"
    assert [c.name for c in model.columns] == [
        "email_address",
        "aadhaar_number",
        "pan_number",
        "session_expires_at",
    ]
    assert column(model, "email_address").column_type == "EmailField"
    assert column(model, "aadhaar_number").is_encrypted is False
    # encrypt(models.CharField(...)) still has to yield the column and the flag.
    assert column(model, "pan_number").column_type == "CharField"
    assert column(model, "pan_number").is_encrypted is True
    assert column(model, "session_expires_at").has_expiry is True


def test_typescript_symbols_and_outbound_call(multi_lang):
    kinds = {
        s.name: s.kind for s in multi_lang.symbols if s.file_path == "profile.ts"
    }
    assert kinds["ProfileService"] == "class"
    assert kinds["publish"] == "method"
    assert kinds["normalise"] == "function"

    sends = [
        e
        for e in edges_of(multi_lang, EdgeType.API_SEND.value)
        if e.source_file == "profile.ts"
    ]
    assert sends and sends[0].sink_symbol == "partner.example.invalid"


def test_java_entity_and_spring_mappings(multi_lang):
    model = model_in(multi_lang, "Citizen.java")
    assert model.table_name == "citizens"
    assert column(model, "aadhaar_number").is_encrypted is False
    assert column(model, "pan_number").is_encrypted is True
    assert column(model, "retention_expires_at").has_expiry is True

    routes = {r.path: r for r in multi_lang.routes if r.file_path == "Citizen.java"}
    # The class level @RequestMapping prefix is joined onto the method path.
    assert routes["/api/citizens"].has_auth is False
    assert routes["/api/citizens/{citizenId}"].has_auth is True


def test_go_struct_model_and_gin_routes(multi_lang):
    model = model_in(multi_lang, "citizen.go")
    assert model.table_name == "citizens"
    assert column(model, "aadhaar_number").is_encrypted is False
    assert column(model, "pan_number").is_encrypted is True
    assert column(model, "expires_at").has_expiry is True

    routes = {r.path: r for r in multi_lang.routes if r.file_path == "citizen.go"}
    assert routes["/citizens"].has_auth is False
    assert routes["/citizens/:citizenId"].has_auth is True

    logs = [
        e
        for e in edges_of(multi_lang, EdgeType.LOG_OUTPUT.value)
        if e.source_file == "citizen.go"
    ]
    assert logs and logs[0].pii_categories


# ----------------------------------------------------------------- resilience


def test_unreadable_file_does_not_abort_the_scan(tmp_path):
    (tmp_path / "broken.py").write_bytes(b"\xff\xfe def (((( : \x00 not python")
    (tmp_path / "good.py").write_text("def handler(email_address):\n    return 1\n")

    result = scan(tmp_path)

    assert "good.py" in {f.path for f in result.files}
    assert any(s.name == "handler" for s in result.symbols)


def test_skip_directories_are_not_walked(tmp_path):
    vendored = tmp_path / "node_modules" / "pkg"
    vendored.mkdir(parents=True)
    (vendored / "index.js").write_text("function vendored() {}\n")
    (tmp_path / "app.js").write_text("function mine() {}\n")

    result = scan(tmp_path)

    assert {f.path for f in result.files} == {"app.js"}
    assert {s.name for s in result.symbols} == {"mine"}


def test_file_cap_is_respected(tmp_path, monkeypatch):
    for index in range(4):
        (tmp_path / f"mod{index}.py").write_text(f"def fn{index}():\n    return {index}\n")
    monkeypatch.setattr(code_scanner.settings, "max_files_per_scan", 2)

    result = scan(tmp_path)

    assert len(result.files) == 2


def test_missing_classifier_never_aborts_a_scan(fixtures_dir, monkeypatch):
    def unimplemented(*args, **kwargs):
        raise NotImplementedError

    monkeypatch.setattr(code_scanner.field_classifier, "classify", unimplemented)
    monkeypatch.setattr(code_scanner.field_classifier, "build_field_ref", unimplemented)

    result = scan(fixtures_dir / "vulnerable_py")

    assert result.pii_fields == []
    assert result.db_models and result.routes and result.symbols
