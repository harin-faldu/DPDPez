"""Stage 3 resolving what stage 2 could not see from a page load.

Only claims still not_observable (or never looked at) after the web stage are
handed to code evidence. A claim the web stage already settled, either way,
stays exactly as the web stage left it.
"""

from app.contracts import (
    CertInEvidence,
    CertInHit,
    ColumnInfo,
    CodeScanResult,
    DataFlowEdgeInfo,
    ModelInfo,
    PolicyClaim,
    RouteInfo,
)
from app.policy import code_verification as cv
from app.policy import verification as v


def claim(claim_type: str, subject: str, value: str | None = None, quote: str = "a verbatim sentence") -> PolicyClaim:
    return PolicyClaim(
        claim_type=claim_type,
        subject=subject,
        value=value,
        quote=quote,
        source_url="https://example.test/privacy",
    )


def code(**kw) -> CodeScanResult:
    kw.setdefault("root_path", "/repo")
    return CodeScanResult(**kw)


def certin_hit(value: str) -> CertInHit:
    return CertInHit(file_path="infra.tf", line_number=1, detail=value, value=value)


class TestClaimsAlreadyResolvedByWebAreUntouched:
    def test_a_web_supported_claim_is_left_alone(self):
        supported = v._record(claim("security", "encryption in transit", "encrypted"), v.SUPPORTED, "web said so")
        result = cv.verify_against_code([supported], code())[0]
        assert result.verification == v.SUPPORTED
        assert result.verified_by == v.WEB
        assert result.verification_detail == "web said so"

    def test_a_web_contradicted_claim_is_left_alone(self):
        contradicted = v._record(claim("children", "age condition", "18"), v.CONTRADICTED, "web said so")
        result = cv.verify_against_code([contradicted], code())[0]
        assert result.verification == v.CONTRADICTED
        assert result.verified_by == v.WEB


class TestNoEvidenceLeavesClaimsAsTheyWere:
    def test_no_code_and_no_certin_copies_through(self):
        original = claim("retention", "account data", "90 days")
        result = cv.verify_against_code([original], None)[0]
        assert result.verification is None

    def test_still_unresolved_after_code_keeps_not_observable(self):
        not_observable = v._record(claim("children", "age condition", "18"), v.NOT_OBSERVABLE, "web could not see it")
        result = cv.verify_against_code([not_observable], code())[0]
        assert result.verification == v.NOT_OBSERVABLE
        assert result.verified_by == v.WEB
        assert result.verification_detail == "web could not see it"


class TestRetention:
    def test_a_column_with_expiry_supports_the_claim(self):
        result = cv.verify_against_code(
            [claim("retention", "account data", "90 days")],
            code(
                db_models=[
                    ModelInfo(
                        class_name="Account",
                        table_name="accounts",
                        file_path="models.py",
                        line_number=1,
                        columns=[ColumnInfo(name="deleted_at", column_type="datetime", line_number=2, has_expiry=True)],
                    )
                ]
            ),
        )[0]
        assert result.verification == v.SUPPORTED
        assert result.verified_by == cv.CODE

    def test_no_expiry_column_stays_not_observable_not_contradicted(self):
        """A cleanup job outside the schema would not show up here either."""
        result = cv.verify_against_code(
            [claim("retention", "account data", "90 days")],
            code(
                db_models=[
                    ModelInfo(
                        class_name="Account", table_name="accounts", file_path="models.py", line_number=1,
                        columns=[ColumnInfo(name="email", column_type="varchar", line_number=2)],
                    )
                ]
            ),
        )[0]
        assert result.verification is None


class TestBreach:
    def test_a_certin_alert_sink_supports_the_claim(self):
        evidence = CertInEvidence(alert_sinks=[certin_hit("pagerduty")], files_examined=1)
        result = cv.verify_against_code([claim("breach", "intimation")], code(), certin=evidence)[0]
        assert result.verification == v.SUPPORTED
        assert "pagerduty" in result.verification_detail

    def test_a_breach_route_supports_the_claim(self):
        result = cv.verify_against_code(
            [claim("breach", "intimation")],
            code(routes=[RouteInfo(http_method="POST", path="/api/incident-report", handler_name="report_incident", file_path="r.py", line_number=1)]),
        )[0]
        assert result.verification == v.SUPPORTED

    def test_nothing_found_stays_not_observable(self):
        result = cv.verify_against_code([claim("breach", "intimation")], code())[0]
        assert result.verification is None


class TestCrossBorder:
    def test_a_no_transfer_claim_contradicted_by_a_foreign_region(self):
        evidence = CertInEvidence(
            storage_regions=[certin_hit("us-east-1")], has_indian_region=False, files_examined=1
        )
        result = cv.verify_against_code(
            [claim("cross_border", "data location", "stored in India only")], code(), certin=evidence
        )[0]
        assert result.verification == v.CONTRADICTED
        assert "us-east-1" in result.verification_detail

    def test_a_no_transfer_claim_supported_by_an_indian_only_region(self):
        evidence = CertInEvidence(
            storage_regions=[certin_hit("ap-south-1")], has_indian_region=True, files_examined=1
        )
        result = cv.verify_against_code(
            [claim("cross_border", "data location", "not transferred outside India")], code(), certin=evidence
        )[0]
        assert result.verification == v.SUPPORTED

    def test_a_named_foreign_destination_is_not_guessed_at(self):
        evidence = CertInEvidence(
            storage_regions=[certin_hit("eu-west-1")], has_indian_region=False, files_examined=1
        )
        result = cv.verify_against_code(
            [claim("cross_border", "transfer", "Ireland")], code(), certin=evidence
        )[0]
        assert result.verification is None

    def test_no_region_evidence_stays_not_observable(self):
        result = cv.verify_against_code(
            [claim("cross_border", "data location", "stored in India only")], code(), certin=CertInEvidence()
        )[0]
        assert result.verification is None


class TestThirdPartyServerSideRecipient:
    def test_a_recipient_reached_only_server_side_is_now_supported(self):
        result = cv.verify_against_code(
            [claim("third_party", "named recipient", "Stripe")],
            code(
                data_flow_edges=[
                    DataFlowEdgeInfo(
                        source_symbol="charge", source_file="pay.py", source_line=1,
                        sink_symbol="api.stripe.com", sink_file="pay.py", sink_line=1,
                        edge_type="api_send",
                    )
                ]
            ),
        )[0]
        assert result.verification == v.SUPPORTED
        assert result.verified_by == cv.CODE

    def test_no_matching_edge_stays_not_observable(self):
        result = cv.verify_against_code(
            [claim("third_party", "named recipient", "Stripe")],
            code(data_flow_edges=[]),
        )[0]
        assert result.verification is None


class TestRightsBehindSignIn:
    def test_an_authenticated_erasure_route_supports_the_claim(self):
        result = cv.verify_against_code(
            [claim("rights", "right to erasure", "erasure")],
            code(
                routes=[
                    RouteInfo(http_method="DELETE", path="/account", handler_name="delete_account", file_path="r.py", line_number=1, has_auth=True)
                ]
            ),
        )[0]
        assert result.verification == v.SUPPORTED

    def test_a_matching_route_without_auth_is_not_enough(self):
        result = cv.verify_against_code(
            [claim("rights", "right to erasure", "erasure")],
            code(
                routes=[
                    RouteInfo(http_method="DELETE", path="/account", handler_name="delete_account", file_path="r.py", line_number=1, has_auth=False)
                ]
            ),
        )[0]
        assert result.verification is None


class TestSecurityAtRest:
    def test_an_encrypted_column_supports_the_claim(self):
        result = cv.verify_against_code(
            [claim("security", "encryption at rest", "encrypted")],
            code(
                db_models=[
                    ModelInfo(
                        class_name="User", table_name="users", file_path="m.py", line_number=1,
                        columns=[ColumnInfo(name="aadhaar", column_type="varchar", line_number=2, is_encrypted=True)],
                    )
                ]
            ),
        )[0]
        assert result.verification == v.SUPPORTED

    def test_no_encrypted_column_stays_not_observable_not_contradicted(self):
        """A managed database's own at-rest encryption would not show up here."""
        result = cv.verify_against_code(
            [claim("security", "encryption at rest", "encrypted")],
            code(
                db_models=[
                    ModelInfo(
                        class_name="User", table_name="users", file_path="m.py", line_number=1,
                        columns=[ColumnInfo(name="aadhaar", column_type="varchar", line_number=2)],
                    )
                ]
            ),
        )[0]
        assert result.verification is None

    def test_a_non_encryption_security_claim_is_left_to_stay_not_observable(self):
        result = cv.verify_against_code(
            [claim("security", "access control", "role based")], code()
        )[0]
        assert result.verification is None


class TestPurposeStaysUnresolved:
    def test_purpose_has_no_code_level_handler(self):
        result = cv.verify_against_code([claim("purpose", "marketing analytics")], code())[0]
        assert result.verification is None


class TestOriginalClaimIsNeverMutated:
    def test_the_input_claim_object_is_untouched(self):
        original = claim("retention", "account data", "90 days")
        cv.verify_against_code(
            [original],
            code(
                db_models=[
                    ModelInfo(
                        class_name="Account", table_name="accounts", file_path="models.py", line_number=1,
                        columns=[ColumnInfo(name="deleted_at", column_type="datetime", line_number=2, has_expiry=True)],
                    )
                ]
            ),
        )
        assert original.verification is None
