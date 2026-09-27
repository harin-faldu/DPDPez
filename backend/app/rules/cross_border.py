"""XBORDER Cross-Border Transfer, DPDP Act s.16; Rule 15.  OWNER: Prerana

Where personal data comes to rest is a fact a checkout's own infrastructure
files declare, the same fact CERT-In's log-sovereignty check reads for a
different reason: the Directions require Indian jurisdiction for ICT logs
specifically, s.16 restricts where personal data itself may be sent. Both
obligations can be broken by the same Terraform region string, which is why
this rule and CERTIN can both fire off one piece of evidence.

Assessed only from a code scan, since a crawl cannot see a Terraform file.
Silent about a checkout with no declared region at all: a PaaS deployment with
no infrastructure-as-code in its own repository is not a violation, it is
evidence this scan cannot reach either way.
"""

from app.contracts import CertInEvidence, CodeScanResult, RuleCheck, RuleVerdict, WebScanResult
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "XBORDER"
RULE_NAME = "Cross-Border Transfer"
DPDP_SECTION = "s.16"
DPDP_RULE = "Rule 15"

# s.16 of the Act is the transfer restriction DPDP_SECTION names, but the
# statutory corpus only holds sections sourced and verified against the
# gazette text (see app/corpus/dpdp_act.py's own note: "If a provision could
# not be sourced it was left out rather than approximated"), and s.16 is not
# among them yet. rule_15 of the notified Rules, which restates the same
# restriction and is sourced, is what the AI layer is actually allowed to cite.
RETRIEVAL_SECTION_IDS: list[str] = ["rule_15"]


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list | None = None,
    certin: CertInEvidence | None = None,
) -> RuleVerdict:
    if code_result is None or certin is None or not certin.examined or not certin.storage_regions:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason=(
                "No storage or processing region is declared anywhere in the "
                "scanned infrastructure files, so whether personal data leaves "
                "India cannot be confirmed either way from a code scan."
            ),
        )

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=[_region_check(certin)],
    )


def _region_check(certin: CertInEvidence) -> RuleCheck:
    # Unlike CERTIN's log-sovereignty check, one Indian region alongside a
    # foreign one does not excuse the foreign one: s.16 restricts sending
    # personal data outside India at all, so a second, foreign copy is still a
    # transfer that occurred, not offset by a first copy that stayed home.
    foreign = certin.foreign_regions()
    if foreign:
        f = foreign[0]
        return RuleCheck(
            name="no_undeclared_cross_border_transfer",
            passed=False,
            detail=(
                f"a storage region outside India is configured ({f.value}) at "
                f"{ev.loc(f.file_path, f.line_number)}; s.16 restricts transfer "
                "of personal data outside India, and nothing else in this "
                "checkout documents a lawful basis for it"
            ),
            file_path=f.file_path,
            line_number=f.line_number,
        )
    hit = certin.storage_regions[0]
    return RuleCheck(
        name="no_undeclared_cross_border_transfer",
        passed=True,
        detail=(
            f"every configured storage region sits inside India ({hit.value}) "
            f"at {ev.loc(hit.file_path, hit.line_number)}"
        ),
        file_path=hit.file_path,
        line_number=hit.line_number,
    )
