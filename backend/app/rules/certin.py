"""CERTIN: the CERT-In Directions of 28 April 2022, read from a checkout.

Issued under s.70B(6) of the Information Technology Act 2000 and binding on
every body corporate in India, so they sit alongside the DPDP obligations rather
than instead of them. Four of them can be decided from infrastructure files:

    clock sync    NIC or NPL time servers, without which log timestamps across
                  systems cannot be reconciled and no breach timeline exists
    logging       enabled, retained 180 days, held in Indian jurisdiction
    reporting     a reportable incident reaching CERT-In within six hours
    cryptography  no hardcoded secrets, no credentials in logs, no dead TLS

Assessed only from a code scan. A crawl cannot see a Dockerfile, so a web scan
returns not_applicable rather than guessing.
"""

from app.contracts import CertInEvidence, CodeScanResult, RuleCheck, RuleVerdict, WebScanResult
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "CERTIN"
RULE_NAME = "CERT-In Directions"
DPDP_SECTION = "s.8(5)"
DPDP_RULE = "Rule 6"

# The Directions are not in the DPDP corpus, so citations point at the DPDP
# provisions the same evidence also bears on: safeguards and breach intimation.
# The Direction itself is named in each detail string instead.
RETRIEVAL_SECTION_IDS: list[str] = ["s.8(5)", "s.8(6)", "rule_6", "rule_7"]

# 180 days for ICT logs under the Directions. DPDP pushes logs of access to
# personal data to a year, so the shorter one is the floor and the longer one is
# reported as the standard to aim at.
CERTIN_LOG_RETENTION_DAYS = 180
DPDP_ACCESS_LOG_RETENTION_DAYS = 365

# Six hours from becoming aware of a reportable incident.
REPORTING_WINDOW_HOURS = 6


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list | None = None,
    certin: CertInEvidence | None = None,
) -> RuleVerdict:
    if code_result is None or certin is None or not certin.examined:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=(
                "The CERT-In Directions are assessed from configuration and "
                "infrastructure files, which only a code scan reads. No such "
                "scan was supplied, so clock synchronisation, log retention, "
                "incident reporting and cryptographic posture were not assessed."
            ),
        )

    checks = [
        _clock_sync(certin),
        _log_retention(certin),
        _log_sovereignty(certin),
        _logging_enabled(certin),
        _incident_reporting(certin),
        _no_hardcoded_secrets(certin),
        _no_credentials_in_logs(certin),
        _transport_security(certin),
    ]
    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=[c for c in checks if c is not None],
        notes=[
            f"Assessed against the CERT-In Directions of 28 April 2022 across "
            f"{certin.files_examined} configuration and source file(s)."
        ],
    )


def _clock_sync(certin: CertInEvidence) -> RuleCheck:
    if certin.uses_approved_ntp:
        hit = next(
            (h for h in certin.ntp_servers if "nic.in" in h.value or "nplindia" in h.value),
            certin.ntp_servers[0],
        )
        return RuleCheck(
            name="ntp_synchronised_to_nic_or_npl",
            passed=True,
            detail=f"clock synchronised to {hit.value} at {ev.loc(hit.file_path, hit.line_number)}",
            file_path=hit.file_path,
            line_number=hit.line_number,
        )
    if certin.ntp_servers:
        hit = certin.ntp_servers[0]
        return RuleCheck(
            name="ntp_synchronised_to_nic_or_npl",
            passed=False,
            detail=(
                f"time is synchronised to {hit.value}, not to an NIC or NPL server; "
                "the Directions name samay1.nic.in, samay2.nic.in and "
                "time.nplindia.org, and a clock outside that set cannot be "
                "reconciled with other systems during an investigation"
            ),
            file_path=hit.file_path,
            line_number=hit.line_number,
        )
    return RuleCheck(
        name="ntp_synchronised_to_nic_or_npl",
        passed=False,
        detail=(
            "no time synchronisation is configured anywhere in the scanned "
            "infrastructure; without a common clock, log timestamps cannot "
            "establish the order of events in a breach timeline"
        ),
    )


def _log_retention(certin: CertInEvidence) -> RuleCheck | None:
    if not certin.log_retention:
        return RuleCheck(
            name="logs_retained_180_days",
            passed=False,
            detail=(
                "no log retention period is configured; the Directions require "
                f"ICT logs to be retained for {CERTIN_LOG_RETENTION_DAYS} days, "
                "and a default that nobody set is not a retention policy"
            ),
        )
    shortest = certin.shortest_retention()
    if shortest is None:
        return None
    days = int(shortest.value)
    if days >= CERTIN_LOG_RETENTION_DAYS:
        suffix = (
            ""
            if days >= DPDP_ACCESS_LOG_RETENTION_DAYS
            else (
                f"; logs of access to personal data are expected to run to "
                f"{DPDP_ACCESS_LOG_RETENTION_DAYS} days, so check this covers them"
            )
        )
        return RuleCheck(
            name="logs_retained_180_days",
            passed=True,
            detail=(
                f"the shortest configured retention is {days} days at "
                f"{ev.loc(shortest.file_path, shortest.line_number)}{suffix}"
            ),
            file_path=shortest.file_path,
            line_number=shortest.line_number,
        )
    return RuleCheck(
        name="logs_retained_180_days",
        passed=False,
        detail=(
            f"logs are retained for {days} days at "
            f"{ev.loc(shortest.file_path, shortest.line_number)}, short of the "
            f"{CERTIN_LOG_RETENTION_DAYS} days the Directions require"
        ),
        file_path=shortest.file_path,
        line_number=shortest.line_number,
    )


def _log_sovereignty(certin: CertInEvidence) -> RuleCheck | None:
    if not certin.storage_regions:
        return None
    if certin.has_indian_region:
        hit = next(
            (h for h in certin.storage_regions if h not in certin.foreign_regions()),
            certin.storage_regions[0],
        )
        return RuleCheck(
            name="logs_held_in_indian_jurisdiction",
            passed=True,
            detail=f"a storage region inside India is configured ({hit.value}) at {ev.loc(hit.file_path, hit.line_number)}",
            file_path=hit.file_path,
            line_number=hit.line_number,
        )
    foreign = certin.foreign_regions()[0]
    return RuleCheck(
        name="logs_held_in_indian_jurisdiction",
        passed=False,
        detail=(
            f"every configured storage region sits outside India, the first being "
            f"{foreign.value} at {ev.loc(foreign.file_path, foreign.line_number)}; "
            "the Directions require logs to be maintained within Indian jurisdiction"
        ),
        file_path=foreign.file_path,
        line_number=foreign.line_number,
    )


def _logging_enabled(certin: CertInEvidence) -> RuleCheck:
    if certin.logging_frameworks:
        names = ev.join_names([h.value for h in certin.logging_frameworks], limit=3)
        return RuleCheck(
            name="logging_enabled",
            passed=True,
            detail=f"logging is configured through {names}",
            file_path=certin.logging_frameworks[0].file_path,
            line_number=certin.logging_frameworks[0].line_number,
        )
    return RuleCheck(
        name="logging_enabled",
        passed=False,
        detail=(
            "no logging framework or collector was found; the Directions "
            "require ICT system logs to be enabled before anything can be "
            "retained or handed over"
        ),
    )


def _incident_reporting(certin: CertInEvidence) -> RuleCheck:
    if certin.alert_sinks:
        names = ev.join_names([h.value for h in certin.alert_sinks], limit=3)
        hit = certin.alert_sinks[0]
        detail = f"an incident can reach a responder through {names}"
        if certin.swallowed_errors:
            first = certin.swallowed_errors[0]
            detail += (
                f"; {len(certin.swallowed_errors)} error path(s) still end without "
                f"raising or notifying, the first at "
                f"{ev.loc(first.file_path, first.line_number)}"
            )
        return RuleCheck(
            name="incident_reaches_a_responder",
            passed=True,
            detail=detail,
            file_path=hit.file_path,
            line_number=hit.line_number,
        )
    first = certin.swallowed_errors[0] if certin.swallowed_errors else None
    return RuleCheck(
        name="incident_reaches_a_responder",
        passed=False,
        detail=(
            "no alerting or incident escalation path was found, so a detected "
            f"incident has nowhere to go inside the {REPORTING_WINDOW_HOURS} hour "
            "reporting window the Directions set"
            + (
                f"; an error path at {ev.loc(first.file_path, first.line_number)} "
                "ends without raising or notifying"
                if first
                else ""
            )
        ),
        file_path=first.file_path if first else None,
        line_number=first.line_number if first else None,
    )


def _no_hardcoded_secrets(certin: CertInEvidence) -> RuleCheck:
    if not certin.hardcoded_secrets:
        return RuleCheck(
            name="no_hardcoded_secrets",
            passed=True,
            detail="no credential literal was found in the scanned files",
        )
    first = certin.hardcoded_secrets[0]
    return RuleCheck(
        name="no_hardcoded_secrets",
        passed=False,
        detail=(
            f"{len(certin.hardcoded_secrets)} credential literal(s) are committed to "
            f"the repository, the first being {first.detail} at "
            f"{ev.loc(first.file_path, first.line_number)}"
        ),
        file_path=first.file_path,
        line_number=first.line_number,
    )


def _no_credentials_in_logs(certin: CertInEvidence) -> RuleCheck:
    if not certin.credentials_logged:
        return RuleCheck(
            name="no_credentials_written_to_logs",
            passed=True,
            detail="no log call was found carrying a credential or a government identifier",
        )
    first = certin.credentials_logged[0]
    return RuleCheck(
        name="no_credentials_written_to_logs",
        passed=False,
        detail=(
            f"{len(certin.credentials_logged)} log call(s) carry a credential or "
            f"identifier in clear text, the first at "
            f"{ev.loc(first.file_path, first.line_number)}; logs retained for "
            f"{CERTIN_LOG_RETENTION_DAYS} days then hold it for that long too"
        ),
        file_path=first.file_path,
        line_number=first.line_number,
    )


def _transport_security(certin: CertInEvidence) -> RuleCheck:
    if not certin.weak_tls:
        return RuleCheck(
            name="no_deprecated_transport_security",
            passed=True,
            detail="no deprecated TLS or SSL version was configured in the scanned files",
        )
    first = certin.weak_tls[0]
    return RuleCheck(
        name="no_deprecated_transport_security",
        passed=False,
        detail=(
            f"{len(certin.weak_tls)} configuration(s) permit a deprecated transport "
            f"protocol, the first being {first.detail} at "
            f"{ev.loc(first.file_path, first.line_number)}"
        ),
        file_path=first.file_path,
        line_number=first.line_number,
    )
