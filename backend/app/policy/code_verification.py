"""Testing what a site says against what its own code does.

Stage 2 already resolved most claims from the live page. What is left is what a
browser cannot see: how long a row survives, where a breach gets reported,
whether a region outside India is configured, a recipient reached only from the
server, a rights route sitting behind a sign in, and encryption of data at
rest. This stage reads the code scan and the CERT-In infrastructure evidence
for exactly those, and only for claims still unresolved after stage 2 — a claim
the web stage already supported or contradicted is left as it was.

The same discipline as stage 2 applies, made stricter: this stage only ever
moves a claim from not_observable to supported, or to contradicted where the
codebase is the authoritative source (a storage region literally configured in
Terraform). It never contradicts on absence alone. A managed database's
encryption at rest, or a deletion job running outside this repository, would
not show up in an AST pass, so their absence here proves nothing.
"""

from app.context.pii_flow import EDGE_API_SEND
from app.contracts import CertInEvidence, CodeScanResult, PolicyClaim
from app.policy import verification as pv
from app.policy.verification import CONTRADICTED, NOT_OBSERVABLE, SUPPORTED

CODE = "code"

_NO_TRANSFER_MARKERS = (
    "no cross-border", "not transferred", "does not transfer",
    "within india", "stored in india", "india only",
)


def verify_against_code(
    claims: list[PolicyClaim],
    code: CodeScanResult | None,
    *,
    certin: CertInEvidence | None = None,
) -> list[PolicyClaim]:
    """Resolve what stage 2 left not_observable, using code evidence.

    Claims stage 2 already decided (supported or contradicted) are copied
    through unchanged: a page-load finding does not get overwritten by a
    codebase that may implement it differently in a path the scan did not
    reach. Only claims still unset or not_observable are handed to a handler.
    """
    if code is None and certin is None:
        return [pv._copy(c) for c in claims]

    resolved: list[PolicyClaim] = []
    for claim in claims:
        if claim.verification not in (None, NOT_OBSERVABLE):
            resolved.append(pv._copy(claim))
            continue
        handler = _HANDLERS.get(claim.claim_type)
        outcome = handler(claim, code, certin) if handler else None
        if outcome is None:
            resolved.append(pv._copy(claim))
            continue
        verdict, detail = outcome
        resolved.append(_record(claim, verdict, detail))
    return resolved


def _retention(claim: PolicyClaim, code: CodeScanResult | None, certin) -> tuple[str, str] | None:
    if code is None:
        return None
    columns = [col for model in code.db_models for col in model.columns]
    expiring = [c for c in columns if c.has_expiry]
    if not expiring:
        # A cleanup job outside the schema, or one this scan's file set did not
        # reach, would not show up here either. Silence proves nothing.
        return None
    col = expiring[0]
    return SUPPORTED, (
        f"the schema defines an expiry on {col.name} ({col.column_type}), "
        "consistent with a retention limit"
    )


def _breach(claim: PolicyClaim, code: CodeScanResult | None, certin: CertInEvidence | None) -> tuple[str, str] | None:
    if certin is not None and certin.alert_sinks:
        sink = certin.alert_sinks[0]
        return SUPPORTED, (
            f"the codebase wires an alerting path ({sink.value}) an incident "
            "could reach, consistent with a working breach notification process"
        )
    if code is not None:
        for route in code.routes:
            haystack = f"{route.path} {route.handler_name}".lower()
            if "breach" in haystack or "incident" in haystack:
                return SUPPORTED, (
                    f"a route ({route.http_method} {route.path}) handles breach "
                    "or incident reporting"
                )
    return None


def _cross_border(claim: PolicyClaim, code: CodeScanResult | None, certin: CertInEvidence | None) -> tuple[str, str] | None:
    if certin is None or not certin.storage_regions:
        return None
    haystack = f"{claim.subject or ''} {claim.value or ''} {claim.quote or ''}".lower()
    if not any(marker in haystack for marker in _NO_TRANSFER_MARKERS):
        # A claim naming a specific foreign destination is not something a
        # region string in Terraform can confirm or refute on its own.
        return None
    foreign = certin.foreign_regions()
    if foreign:
        return CONTRADICTED, (
            "the notice states data does not leave India, yet the codebase "
            f"configures a storage region outside India ({foreign[0].value})"
        )
    if certin.has_indian_region:
        return SUPPORTED, "every configured storage region sits inside India"
    return None


def _third_party(claim: PolicyClaim, code: CodeScanResult | None, certin) -> tuple[str, str] | None:
    if code is None:
        return None
    name = (claim.value or "").strip()
    if not name:
        return None
    api_hosts = [
        edge.sink_symbol
        for edge in code.data_flow_edges
        if edge.edge_type == EDGE_API_SEND and edge.sink_symbol
    ]
    if not api_hosts:
        return None
    match = pv._hosts_matching(name, api_hosts)
    if not match:
        return None
    return SUPPORTED, f"the notice names {name} and the code sends requests to {match[0]}"


def _rights(claim: PolicyClaim, code: CodeScanResult | None, certin) -> tuple[str, str] | None:
    if code is None or not code.routes:
        return None
    offered = (claim.value or claim.subject or "").lower()
    words = pv._RIGHT_WORDS.get(offered, (offered,))
    for route in code.routes:
        haystack = f"{route.path} {route.handler_name}".lower()
        if route.has_auth and any(word in haystack for word in words):
            return SUPPORTED, (
                f"a route behind authentication ({route.http_method} {route.path}) "
                f"implements {offered}"
            )
    return None


def _security(claim: PolicyClaim, code: CodeScanResult | None, certin) -> tuple[str, str] | None:
    if code is None:
        return None
    haystack = f"{claim.subject or ''} {claim.value or ''}".lower()
    if "encrypt" not in haystack:
        return None
    encrypted = [
        col for model in code.db_models for col in model.columns if col.is_encrypted
    ]
    if not encrypted:
        return None
    col = encrypted[0]
    return SUPPORTED, (
        f"the schema marks {col.name} as encrypted, consistent with the "
        "notice's claim about stored data"
    )


_HANDLERS = {
    "retention": _retention,
    "breach": _breach,
    "cross_border": _cross_border,
    "third_party": _third_party,
    "rights": _rights,
    "security": _security,
}


def _record(claim: PolicyClaim, verdict: str, detail: str) -> PolicyClaim:
    copied = pv._copy(claim)
    copied.verified_by = CODE
    copied.verification = verdict
    copied.verification_detail = detail
    return copied
