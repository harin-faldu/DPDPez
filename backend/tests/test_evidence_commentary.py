"""A comment is not an implementation.

Found against the demo fixture: its create_app docstring says "no Data
Protection Officer is named anywhere in the code" and "there is no data
protection impact assessment in this project". Naive substring matching over
the whole symbol source read both as evidence that the controls existed, so a
deliberately non-compliant app scored 0.67 on R8 and R9.
"""

from app.contracts import CodeScanResult, SymbolInfo
from app.rules import evidence as ev


def _result(source: str) -> CodeScanResult:
    return CodeScanResult(
        root_path="/repo",
        symbols=[
            SymbolInfo(
                name="create_app",
                kind="function",
                file_path="app.py",
                line_number=28,
                end_line=60,
                source=source,
            )
        ],
    )


class TestStripCommentary:
    def test_removes_python_docstring(self):
        cleaned = ev.strip_commentary('def f():\n    """a data protection officer"""\n    return 1')
        assert "data protection officer" not in cleaned
        assert "return 1" in cleaned

    def test_removes_hash_comment(self):
        cleaned = ev.strip_commentary("x = 1  # no data protection officer here\ny = 2")
        assert "data protection officer" not in cleaned
        assert "x = 1" in cleaned
        assert "y = 2" in cleaned

    def test_removes_slash_comment(self):
        cleaned = ev.strip_commentary("const a = 1; // no dpo\nconst b = 2;")
        assert "dpo" not in cleaned
        assert "const b = 2;" in cleaned

    def test_removes_block_comment(self):
        cleaned = ev.strip_commentary("/* there is no dpia */\nint x = 1;")
        assert "dpia" not in cleaned
        assert "int x = 1;" in cleaned

    def test_keeps_string_literals(self):
        # A real contact point is frequently just a literal in config, so
        # stripping every string would throw away genuine evidence.
        cleaned = ev.strip_commentary('DPO_EMAIL = "dpo@example.invalid"')
        assert "dpo@example.invalid" in cleaned

    def test_handles_empty_source(self):
        assert ev.strip_commentary("") == ""


class TestFindSymbolsBySource:
    def test_does_not_match_a_control_mentioned_only_in_a_docstring(self):
        source = (
            'def create_app():\n'
            '    """Build the app.\n\n'
            '    VIOLATION: no Data Protection Officer is named anywhere in the\n'
            '    code, the config or the templates.\n'
            '    """\n'
            '    return Flask(__name__)\n'
        )
        assert ev.find_symbols_by_source(_result(source), ("data protection officer",)) == []

    def test_does_not_match_a_denial_in_a_line_comment(self):
        source = "def create_app():\n    # there is no data protection impact assessment\n    return 1\n"
        assert ev.find_symbols_by_source(
            _result(source), ("data protection impact assessment",)
        ) == []

    def test_still_matches_real_code(self):
        source = 'def create_app():\n    app.config["DPO_CONTACT"] = "dpo@example.invalid"\n    return app\n'
        found = ev.find_symbols_by_source(_result(source), ("dpo_contact",))
        assert [s.name for s in found] == ["create_app"]

    def test_weak_digest_in_a_comment_is_not_weak_digest_usage(self):
        # The same bug in reverse on R6: a comment saying md5 was replaced
        # would otherwise be reported as md5 still in use.
        source = "def hash_pw(p):\n    # migrated away from md5 in 2024\n    return bcrypt.hash(p)\n"
        assert ev.find_symbols_by_source(_result(source), ("md5",)) == []
        assert ev.find_symbols_by_source(_result(source), ("bcrypt",))

    def test_handles_symbol_with_no_captured_source(self):
        result = CodeScanResult(
            root_path="/repo",
            symbols=[
                SymbolInfo(name="f", kind="function", file_path="a.py", line_number=1)
            ],
        )
        assert ev.find_symbols_by_source(result, ("anything",)) == []

    def test_handles_none_scan_result(self):
        assert ev.find_symbols_by_source(None, ("anything",)) == []
