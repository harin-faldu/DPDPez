"""The response parser must not corrupt a response that was already valid.

Found live: the prompt asks for a code snippet in suggested_fix, so the model
routinely returns a markdown code fence INSIDE a JSON string. An unanchored
fence regex matched that inner fence, extracted the snippet, and threw away the
surrounding object. Valid findings were reported as "AI response was not valid
JSON" across both providers.
"""

import json

from app.ai import gateway

SNIPPET_RESPONSE = json.dumps(
    {
        "title": "No correction or erasure route",
        "description": "The application exposes no path to exercise s.12 rights.",
        "citation": "DPDP Act 2023, Section 12",
        "citation_text": "the right to correction, completion, updating and erasure",
        "cited_section_ids": ["s.12"],
        "suggested_fix": (
            "Add explicit routes. In Flask:\n\n"
            "```python\n"
            "@app.route('/rights/correction', methods=['POST'])\n"
            "def request_correction():\n"
            "    ...\n"
            "```\n"
        ),
        "data_flow_summary": "Personal data is stored with no rights path.",
        "confidence": 0.9,
    }
)


class TestSnippetsInsideJson:
    def test_a_fenced_snippet_inside_a_string_does_not_break_parsing(self):
        parsed = gateway.parse_json_response(SNIPPET_RESPONSE)
        assert isinstance(parsed, dict)
        assert parsed["cited_section_ids"] == ["s.12"]
        assert "```python" in parsed["suggested_fix"]

    def test_the_snippet_survives_intact(self):
        parsed = gateway.parse_json_response(SNIPPET_RESPONSE)
        assert "request_correction" in parsed["suggested_fix"]


class TestMarkdownWrapper:
    def test_unwraps_a_fence_that_wraps_the_whole_response(self):
        parsed = gateway.parse_json_response('```json\n{"ok": true}\n```')
        assert parsed == {"ok": True}

    def test_unwraps_a_bare_fence(self):
        parsed = gateway.parse_json_response('```\n{"ok": true}\n```')
        assert parsed == {"ok": True}

    def test_prefers_the_raw_text_when_it_already_parses(self):
        # A wrapper must never be stripped from something already valid.
        raw = json.dumps({"suggested_fix": "```json\n{}\n```"})
        assert gateway.parse_json_response(raw)["suggested_fix"].startswith("```json")


class TestDegenerateInput:
    def test_empty(self):
        assert gateway.parse_json_response("") is None

    def test_whitespace(self):
        assert gateway.parse_json_response("   \n ") is None

    def test_prose_with_no_json(self):
        assert gateway.parse_json_response("I could not answer that.") is None

    def test_json_with_leading_prose_is_recovered(self):
        assert gateway.parse_json_response('Here you go:\n{"ok": true}') == {"ok": True}

    def test_truncated_object_returns_none(self):
        assert gateway.parse_json_response('{"title": "cut off mid') is None
