"""An absent header must not count as a present one.

Found on the first live web scan. The scanner reports every header it looked
for and uses an empty string for the ones the server did not send, so a checker
that iterates the dict keys sees them all as present. python.org, which sends
neither CSP nor referrer-policy nor x-content-type-options, was graded fully
compliant on security.

False compliance is the worst direction for this tool to fail in: a missing
finding is a risk nobody knows they carry.
"""

from app.contracts import FormInfo, WebScanResult
from app.rules import engine, r06_security
from app.models.enums import RuleStatus

ALL_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
)


def _web(headers: dict[str, str]) -> WebScanResult:
    return WebScanResult(
        entry_url="https://example.test",
        served_over_https=True,
        security_headers=headers,
        forms=[
            FormInfo(action="https://example.test/signup", method="post", submits_over_https=True)
        ],
    )


def _header_check(result: WebScanResult):
    verdict = r06_security.check(web_result=result)
    return next(c for c in verdict.checks if c.name == "security_headers_present")


class TestHeaderPresence:
    def test_absent_headers_reported_as_empty_strings_do_not_pass(self):
        # Exactly the shape the scanner produces: every key present, most empty.
        headers = {h: "" for h in ALL_HEADERS}
        headers["strict-transport-security"] = "max-age=63072000"
        headers["x-frame-options"] = "SAMEORIGIN"
        check = _header_check(_web(headers))
        assert not check.passed
        assert "missing" in check.detail.lower()

    def test_all_headers_set_passes(self):
        headers = {h: "set" for h in ALL_HEADERS}
        assert _header_check(_web(headers)).passed

    def test_whitespace_only_value_is_not_a_header(self):
        headers = {h: "set" for h in ALL_HEADERS}
        headers["content-security-policy"] = "   "
        assert not _header_check(_web(headers)).passed

    def test_completely_absent_key_still_fails(self):
        headers = {"strict-transport-security": "max-age=1"}
        assert not _header_check(_web(headers)).passed


class TestVerdictImpact:
    def test_a_site_missing_headers_is_not_graded_compliant_on_security(self):
        headers = {h: "" for h in ALL_HEADERS}
        headers["strict-transport-security"] = "max-age=63072000"
        verdict = r06_security.check(web_result=_web(headers))
        assert verdict.status != RuleStatus.COMPLIANT

    def test_engine_agrees(self):
        headers = {h: "" for h in ALL_HEADERS}
        headers["strict-transport-security"] = "max-age=63072000"
        verdicts = {v.rule_id: v for v in engine.run_all(web_result=_web(headers))}
        assert verdicts["R6"].status != RuleStatus.COMPLIANT
