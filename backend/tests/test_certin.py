"""CERT-In Directions: evidence gathering and the rule checker built on it.

Fixtures are synthetic files written to tmp_path, following the project's
convention of never reading real secrets or real infrastructure. Values used
as "secrets" are throwaway strings that exist only inside this test.
"""

from app.contracts import CertInEvidence, CertInHit
from app.rules import certin
from app.scanner import certin_scanner


def write(tmp_path, name: str, content: str):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# --------------------------------------------------------------- scanner


class TestClockSync:
    def test_an_approved_nic_host_is_recognised(self, tmp_path):
        write(tmp_path, "chrony.conf", "server samay1.nic.in iburst\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.uses_approved_ntp is True
        assert evidence.ntp_servers[0].value == "samay1.nic.in"

    def test_an_unapproved_public_pool_is_recorded_but_not_approved(self, tmp_path):
        write(tmp_path, "chrony.conf", "pool time.google.com iburst\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.uses_approved_ntp is False
        assert evidence.ntp_servers
        assert evidence.ntp_servers[0].value == "time.google.com"

    def test_no_ntp_configuration_anywhere_leaves_the_list_empty(self, tmp_path):
        write(tmp_path, "docker-compose.yml", "services:\n  web:\n    image: app\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.ntp_servers == []
        assert evidence.uses_approved_ntp is False


class TestLogRetention:
    def test_retention_below_180_days_is_captured(self, tmp_path):
        write(tmp_path, "logging.tf", 'log_retention_days = "30"\n')
        evidence = certin_scanner.scan_directory(str(tmp_path))
        shortest = evidence.shortest_retention()
        assert shortest is not None and int(shortest.value) == 30

    def test_retention_at_the_180_day_floor_is_captured(self, tmp_path):
        write(tmp_path, "logging.tf", 'retention_in_days = "180"\n')
        evidence = certin_scanner.scan_directory(str(tmp_path))
        shortest = evidence.shortest_retention()
        assert shortest is not None and int(shortest.value) == 180

    def test_retention_above_the_dpdp_year_is_captured(self, tmp_path):
        write(tmp_path, "logging.tf", 'retention_period = "400"\n')
        evidence = certin_scanner.scan_directory(str(tmp_path))
        shortest = evidence.shortest_retention()
        assert shortest is not None and int(shortest.value) == 400

    def test_the_shortest_of_several_settings_wins(self, tmp_path):
        write(
            tmp_path,
            "logging.tf",
            'retention_days = "365"\nlog_retention = "45"\n',
        )
        evidence = certin_scanner.scan_directory(str(tmp_path))
        shortest = evidence.shortest_retention()
        assert shortest is not None and int(shortest.value) == 45

    def test_a_zero_retention_is_not_recorded_as_a_policy(self, tmp_path):
        write(tmp_path, "logging.tf", 'retention_days = "0"\n')
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.shortest_retention() is None


class TestSovereignty:
    def test_an_indian_region_is_recognised(self, tmp_path):
        write(tmp_path, "infra.tf", 'region = "ap-south-1"\n')
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.has_indian_region is True
        assert evidence.foreign_regions() == []

    def test_a_foreign_region_is_recorded_as_foreign(self, tmp_path):
        write(tmp_path, "infra.tf", 'region = "us-east-1"\n')
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.has_indian_region is False
        assert len(evidence.foreign_regions()) == 1

    def test_no_region_configured_leaves_no_evidence_either_way(self, tmp_path):
        write(tmp_path, "app.py", "print('hello')\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.storage_regions == []
        assert evidence.has_indian_region is False


class TestLoggingAndAlerting:
    def test_a_known_logging_framework_is_detected(self, tmp_path):
        write(tmp_path, "app.py", "import structlog\nlogger = structlog.get_logger()\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert any(h.value == "structlog" for h in evidence.logging_frameworks)

    def test_a_known_alert_sink_is_detected(self, tmp_path):
        write(tmp_path, "alerts.py", "PAGERDUTY_URL = 'https://events.pagerduty.com/x'\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert any(h.value == "pagerduty" for h in evidence.alert_sinks)

    def test_a_swallowed_python_exception_is_flagged(self, tmp_path):
        write(
            tmp_path,
            "handler.py",
            "try:\n    do_thing()\nexcept Exception:\n    pass\n",
        )
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.swallowed_errors

    def test_no_alerting_and_no_swallowing_leaves_both_empty(self, tmp_path):
        write(tmp_path, "handler.py", "def add(a, b):\n    return a + b\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.alert_sinks == []
        assert evidence.swallowed_errors == []


class TestCryptography:
    def test_a_hardcoded_secret_is_flagged_without_storing_its_value(self, tmp_path):
        write(tmp_path, "settings.py", 'api_key = "sk-throwaway-not-a-real-secret-1234"\n')
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.hardcoded_secrets
        hit = evidence.hardcoded_secrets[0]
        assert "redacted" in hit.detail
        assert "sk-throwaway" not in hit.detail

    def test_a_placeholder_value_is_not_flagged(self, tmp_path):
        write(tmp_path, "settings.py", 'api_key = "changeme_replace_in_production"\n')
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.hardcoded_secrets == []

    def test_an_env_reference_is_not_flagged(self, tmp_path):
        write(tmp_path, "settings.py", "api_key = os.environ['API_KEY']\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.hardcoded_secrets == []

    def test_a_deprecated_tls_version_is_flagged(self, tmp_path):
        write(tmp_path, "ssl_config.py", "ssl_version = 'TLSv1'\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.weak_tls

    def test_no_weak_tls_leaves_the_list_empty(self, tmp_path):
        write(tmp_path, "ssl_config.py", "ssl_version = 'TLSv1.2'\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.weak_tls == []

    def test_a_credential_written_to_a_log_call_is_flagged(self, tmp_path):
        write(tmp_path, "auth.py", 'logger.info("login attempt password=" + password)\n')
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.credentials_logged

    def test_a_credential_only_read_not_logged_is_not_flagged(self, tmp_path):
        write(tmp_path, "auth.py", "password = request.form['password']\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.credentials_logged == []


class TestFilesExamined:
    def test_an_empty_directory_is_not_treated_as_examined(self, tmp_path):
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.files_examined == 0
        assert evidence.examined is False

    def test_a_missing_directory_is_not_treated_as_examined(self, tmp_path):
        evidence = certin_scanner.scan_directory(str(tmp_path / "does-not-exist"))
        assert evidence.examined is False

    def test_a_directory_with_relevant_files_is_examined(self, tmp_path):
        write(tmp_path, "app.py", "print('hi')\n")
        evidence = certin_scanner.scan_directory(str(tmp_path))
        assert evidence.examined is True
        assert evidence.files_examined >= 1


# ----------------------------------------------------------------- checker


def hit(value: str = "x", detail: str = "d") -> CertInHit:
    return CertInHit(file_path="f.py", line_number=1, detail=detail, value=value)


class TestNotApplicable:
    def test_no_code_result_and_no_evidence_is_not_applicable(self):
        verdict = certin.check()
        assert verdict.status == "not_applicable"
        assert verdict.score is None

    def test_unexamined_evidence_is_not_applicable(self):
        verdict = certin.check(code_result=object(), certin=CertInEvidence())
        assert verdict.status == "not_applicable"


class TestClockSyncCheck:
    def test_an_approved_host_passes(self):
        evidence = CertInEvidence(
            ntp_servers=[hit("samay1.nic.in")], uses_approved_ntp=True, files_examined=1
        )
        verdict = certin.check(code_result=object(), certin=evidence)
        clock_check = next(c for c in verdict.checks if c.name == "ntp_synchronised_to_nic_or_npl")
        assert clock_check.passed is True

    def test_an_unapproved_host_fails(self):
        evidence = CertInEvidence(
            ntp_servers=[hit("pool.ntp.org")], uses_approved_ntp=False, files_examined=1
        )
        verdict = certin.check(code_result=object(), certin=evidence)
        clock_check = next(c for c in verdict.checks if c.name == "ntp_synchronised_to_nic_or_npl")
        assert clock_check.passed is False

    def test_no_configuration_at_all_fails(self):
        evidence = CertInEvidence(files_examined=1)
        verdict = certin.check(code_result=object(), certin=evidence)
        clock_check = next(c for c in verdict.checks if c.name == "ntp_synchronised_to_nic_or_npl")
        assert clock_check.passed is False


class TestRetentionCheck:
    def test_180_days_or_more_passes(self):
        evidence = CertInEvidence(log_retention=[hit("180")], files_examined=1)
        verdict = certin.check(code_result=object(), certin=evidence)
        retention_check = next(c for c in verdict.checks if c.name == "logs_retained_180_days")
        assert retention_check.passed is True

    def test_below_180_days_fails(self):
        evidence = CertInEvidence(log_retention=[hit("30")], files_examined=1)
        verdict = certin.check(code_result=object(), certin=evidence)
        retention_check = next(c for c in verdict.checks if c.name == "logs_retained_180_days")
        assert retention_check.passed is False

    def test_no_retention_configured_fails(self):
        evidence = CertInEvidence(files_examined=1)
        verdict = certin.check(code_result=object(), certin=evidence)
        retention_check = next(c for c in verdict.checks if c.name == "logs_retained_180_days")
        assert retention_check.passed is False


class TestSovereigntyCheck:
    def test_an_indian_region_passes(self):
        evidence = CertInEvidence(
            storage_regions=[hit("ap-south-1")], has_indian_region=True, files_examined=1
        )
        verdict = certin.check(code_result=object(), certin=evidence)
        names = [c.name for c in verdict.checks]
        assert "logs_held_in_indian_jurisdiction" in names
        sovereignty = next(c for c in verdict.checks if c.name == "logs_held_in_indian_jurisdiction")
        assert sovereignty.passed is True

    def test_a_foreign_only_region_fails(self):
        evidence = CertInEvidence(
            storage_regions=[hit("us-east-1")], has_indian_region=False, files_examined=1
        )
        verdict = certin.check(code_result=object(), certin=evidence)
        sovereignty = next(c for c in verdict.checks if c.name == "logs_held_in_indian_jurisdiction")
        assert sovereignty.passed is False

    def test_no_region_evidence_omits_the_check_rather_than_failing_it(self):
        evidence = CertInEvidence(files_examined=1, ntp_servers=[hit("samay1.nic.in")], uses_approved_ntp=True)
        verdict = certin.check(code_result=object(), certin=evidence)
        names = [c.name for c in verdict.checks]
        assert "logs_held_in_indian_jurisdiction" not in names


class TestLoggingAndReportingChecks:
    def test_a_logging_framework_passes(self):
        evidence = CertInEvidence(logging_frameworks=[hit("winston")], files_examined=1)
        verdict = certin.check(code_result=object(), certin=evidence)
        c = next(x for x in verdict.checks if x.name == "logging_enabled")
        assert c.passed is True

    def test_no_logging_framework_fails(self):
        evidence = CertInEvidence(files_examined=1)
        verdict = certin.check(code_result=object(), certin=evidence)
        c = next(x for x in verdict.checks if x.name == "logging_enabled")
        assert c.passed is False

    def test_an_alert_sink_passes_even_with_some_swallowed_errors(self):
        evidence = CertInEvidence(
            alert_sinks=[hit("pagerduty")],
            swallowed_errors=[hit(detail="ends silently")],
            files_examined=1,
        )
        verdict = certin.check(code_result=object(), certin=evidence)
        c = next(x for x in verdict.checks if x.name == "incident_reaches_a_responder")
        assert c.passed is True

    def test_no_alert_sink_fails(self):
        evidence = CertInEvidence(files_examined=1)
        verdict = certin.check(code_result=object(), certin=evidence)
        c = next(x for x in verdict.checks if x.name == "incident_reaches_a_responder")
        assert c.passed is False


class TestCryptographyChecks:
    def test_no_secrets_no_credential_logs_no_weak_tls_all_pass(self):
        evidence = CertInEvidence(files_examined=1)
        verdict = certin.check(code_result=object(), certin=evidence)
        for name in (
            "no_hardcoded_secrets",
            "no_credentials_written_to_logs",
            "no_deprecated_transport_security",
        ):
            c = next(x for x in verdict.checks if x.name == name)
            assert c.passed is True

    def test_a_hardcoded_secret_fails_and_never_echoes_the_value(self):
        evidence = CertInEvidence(
            hardcoded_secrets=[hit(detail="api_key assigned a literal value [redacted, 30 characters]")],
            files_examined=1,
        )
        verdict = certin.check(code_result=object(), certin=evidence)
        c = next(x for x in verdict.checks if x.name == "no_hardcoded_secrets")
        assert c.passed is False
        assert "redacted" in c.detail

    def test_a_credential_logged_fails(self):
        evidence = CertInEvidence(credentials_logged=[hit(detail="a log call carries password")], files_examined=1)
        verdict = certin.check(code_result=object(), certin=evidence)
        c = next(x for x in verdict.checks if x.name == "no_credentials_written_to_logs")
        assert c.passed is False

    def test_weak_tls_fails(self):
        evidence = CertInEvidence(weak_tls=[hit(detail="TLSv1")], files_examined=1)
        verdict = certin.check(code_result=object(), certin=evidence)
        c = next(x for x in verdict.checks if x.name == "no_deprecated_transport_security")
        assert c.passed is False


class TestOverallVerdict:
    def test_a_fully_compliant_setup_scores_1(self):
        evidence = CertInEvidence(
            ntp_servers=[hit("samay1.nic.in")],
            uses_approved_ntp=True,
            log_retention=[hit("365")],
            storage_regions=[hit("ap-south-1")],
            has_indian_region=True,
            logging_frameworks=[hit("winston")],
            alert_sinks=[hit("pagerduty")],
            files_examined=5,
        )
        verdict = certin.check(code_result=object(), certin=evidence)
        assert verdict.status == "compliant"
        assert verdict.score == 1.0

    def test_a_wholly_unconfigured_setup_scores_low_but_stays_a_verdict(self):
        # Absence-based checks (no secrets found, no weak TLS found) still pass
        # with zero evidence either way, so an empty checkout lands in the gap
        # band rather than at a hard zero.
        evidence = CertInEvidence(files_examined=5)
        verdict = certin.check(code_result=object(), certin=evidence)
        assert verdict.status == "gap"
        assert 0.0 < verdict.score < 1.0
