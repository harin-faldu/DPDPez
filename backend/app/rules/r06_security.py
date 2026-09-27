"""R6 Security Safeguards, DPDP Act s.8(5); Rule 6.  OWNER: Prerana"""

from app.contracts import (
    CodeScanResult,
    PIIFlowPathInfo,
    RuleCheck,
    RuleVerdict,
    WebScanResult,
)
from app.rules import evidence as ev
from app.rules.engine import build_verdict

RULE_ID = "R6"
RULE_NAME = "Security Safeguards"
DPDP_SECTION = "s.8(5)"
DPDP_RULE = "Rule 6"

# Pin retrieval for this rule so the AI layer cannot cite an unrelated provision.
# s.8(4) requires appropriate technical and organisational measures, s.8(5)
# the safeguards themselves.
RETRIEVAL_SECTION_IDS: list[str] = ["s.8(4)", "s.8(5)", "rule_6"]

_PASSWORD_KEYWORDS: tuple[str, ...] = ("password", "passwd", "pwd_hash", "secret_answer")

# Slow key derivation functions. A plain digest is fast by design, which is
# exactly what makes it unsuitable for storing credentials.
_STRONG_KDF_MARKERS: tuple[str, ...] = ("bcrypt", "argon2", "scrypt", "pbkdf2")
_WEAK_DIGEST_MARKERS: tuple[str, ...] = (
    "hashlib.md5",
    "hashlib.sha1",
    "hashlib.sha256",
    "md5(",
    "sha1(",
)

_PII_ROUTE_KEYWORDS: tuple[str, ...] = ev.PII_COLUMN_KEYWORDS + (
    "user",
    "users",
    "profile",
    "profiles",
    "account",
    "accounts",
    "customer",
    "customers",
    "patient",
    "patients",
    "kyc",
    "onboard",
    "me",
)

_REQUIRED_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
)

_RECOMMENDED_HEADERS: tuple[str, ...] = ("referrer-policy", "permissions-policy")

# A cookie without Secure travels over plain HTTP on the first request that
# escapes TLS, and one without SameSite rides along on cross-site requests.
# HttpOnly is listed as recommended rather than required because an analytics
# cookie is read by the page's own script by design, so requiring it everywhere
# would report a finding on every site that has one.
_REQUIRED_COOKIE_FLAGS: tuple[str, ...] = ("Secure", "SameSite")


def check(
    *,
    web_result: WebScanResult | None = None,
    code_result: CodeScanResult | None = None,
    flows: list[PIIFlowPathInfo] | None = None,
) -> RuleVerdict:
    """Evaluate R6 and return a deterministic verdict.

    Checks:
      - PII columns are encrypted at rest
      - passwords are hashed with a slow KDF, not a plain digest
      - PII is not written to logs in plaintext
      - endpoints handling PII are behind authentication
      - traffic is served over HTTPS
      - baseline security headers are present
      - cookies carry Secure and SameSite
      - sensitive category fields are collected with extra care

    Note: This rule carries the highest penalty exposure under the Act, so it
    shares the top weight with consent. Read column.is_encrypted and
    column.is_hashed from the scanner's ModelInfo rather than guessing
    from names. The log_output edge type in data_flow_edges is what
    catches PII in log lines, which nothing else in the pipeline sees.
    """
    flows = flows or []

    if web_result is None and code_result is None:
        return build_verdict(
            rule_id=RULE_ID,
            rule_name=RULE_NAME,
            dpdp_section=DPDP_SECTION,
            dpdp_rule=DPDP_RULE,
            checks=[],
            not_applicable_reason="No web or code evidence was supplied.",
        )

    checks: list[RuleCheck] = []
    notes: list[str] = []
    override: str | None = None

    if code_result is not None:
        encryption_check, plaintext_critical = _encryption_check(code_result, flows)
        checks.append(encryption_check)
        checks.append(_password_check(code_result))
        checks.append(_logging_check(code_result))
        checks.append(_auth_check(code_result))
        if plaintext_critical is not None:
            # Rules 2025 rule 6 requires encryption, obfuscation, masking or
            # virtual tokens over personal data. A national identifier held in
            # clear text is the case that requirement exists for, so it is
            # graded as a breach of s.8(5) rather than averaged away by the
            # other five checks passing.
            model, column, category = plaintext_critical
            override = (
                f"{model.class_name}.{column.name} stores {category} data in plaintext at "
                f"{ev.loc(model.file_path, column.line_number)} with neither encryption nor "
                "hashing applied."
            )
    else:
        notes.append(
            "No code scan was supplied, so storage encryption, password hashing, log hygiene "
            "and endpoint authentication were not assessed."
        )

    if ev.web_observable(web_result):
        checks.append(_https_check(web_result))
        checks.append(_headers_check(web_result))
        checks.extend(_cookie_flag_checks(web_result))
        checks.extend(_sensitive_field_checks(web_result))
    elif web_result is not None:
        # A blocked crawl means the headers and cookies observed belong to
        # whatever turned the crawler away, not to the application.
        notes.append(ev.crawl_blocked_reason(web_result))
    else:
        notes.append(
            "No web scan was supplied, so transport security and response headers were not "
            "assessed."
        )

    return build_verdict(
        rule_id=RULE_ID,
        rule_name=RULE_NAME,
        dpdp_section=DPDP_SECTION,
        dpdp_rule=DPDP_RULE,
        checks=checks,
        notes=notes,
        override_reason=override,
        not_applicable_reason=(
            "Neither the repository nor the published site could be examined for safeguards."
        ),
    )


def _encryption_check(code_result, flows):
    """Return the encryption check plus the first plaintext critical column found."""
    columns = ev.pii_columns(code_result)
    if not columns:
        unencrypted_flows = ev.flows_without(flows, "has_encryption")
        if flows and unencrypted_flows:
            return (
                RuleCheck(
                    name="pii_encrypted_at_rest",
                    passed=False,
                    detail=(
                        f"{len(unencrypted_flows)} of {len(flows)} personal data flows reach a "
                        f"sink with no encryption applied: "
                        f"{ev.flow_label(unencrypted_flows[0])}"
                    ),
                ),
                None,
            )
        return (
            RuleCheck(
                name="pii_encrypted_at_rest",
                passed=True,
                detail=(
                    f"no personal data columns found across {len(code_result.db_models)} database "
                    "model(s), so there is nothing stored in clear text"
                ),
            ),
            None,
        )

    plaintext = [
        (model, column, category)
        for model, column, category in columns
        if not column.is_encrypted and not column.is_hashed
    ]
    critical = [entry for entry in plaintext if ev.is_critical_category(entry[2])]

    if not plaintext:
        rendered = ev.join_names([f"{m.class_name}.{c.name}" for m, c, _ in columns])
        return (
            RuleCheck(
                name="pii_encrypted_at_rest",
                passed=True,
                detail=(
                    f"all {len(columns)} personal data column(s) are encrypted or hashed at rest "
                    f"({rendered})"
                ),
            ),
            None,
        )

    reported = critical or plaintext
    first_model, first_column, first_category = reported[0]
    rendered = ev.join_names(
        [
            f"{model.class_name}.{column.name} ({category}) at "
            f"{ev.loc(model.file_path, column.line_number)}"
            for model, column, category in reported
        ],
        limit=3,
    )
    return (
        RuleCheck(
            name="pii_encrypted_at_rest",
            passed=False,
            detail=(
                f"{len(plaintext)} of {len(columns)} personal data column(s) are stored in "
                f"plaintext: {rendered}"
            ),
            file_path=first_model.file_path,
            line_number=first_column.line_number,
        ),
        (first_model, first_column, first_category) if critical else None,
    )


def _password_check(code_result) -> RuleCheck:
    columns = ev.find_columns(code_result, _PASSWORD_KEYWORDS)
    weak = ev.find_symbols_by_source(code_result, _WEAK_DIGEST_MARKERS)
    strong = ev.find_symbols_by_source(code_result, _STRONG_KDF_MARKERS)

    if not columns:
        return RuleCheck(
            name="passwords_hashed_with_kdf",
            passed=True,
            detail=(
                f"no password column found across {len(code_result.db_models)} database model(s), "
                "so no credential storage obligation arises here"
            ),
        )

    model, column = columns[0]
    location = ev.loc(model.file_path, column.line_number)

    if not column.is_hashed:
        # Encryption is reversible by whoever holds the key, so an encrypted
        # password column is still a credential the fiduciary can read back.
        state = "encrypted but not hashed" if column.is_encrypted else "stored in plaintext"
        return RuleCheck(
            name="passwords_hashed_with_kdf",
            passed=False,
            detail=(
                f"{model.class_name}.{column.name} is {state} at {location}; credentials must be "
                "put through a one way slow key derivation function"
            ),
            file_path=model.file_path,
            line_number=column.line_number,
        )

    if weak and not strong:
        symbol = weak[0]
        return RuleCheck(
            name="passwords_hashed_with_kdf",
            passed=False,
            detail=(
                f"{model.class_name}.{column.name} at {location} is hashed, but {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)} uses a fast general purpose "
                "digest rather than a slow key derivation function"
            ),
            file_path=symbol.file_path,
            line_number=symbol.line_number,
        )

    if strong:
        symbol = strong[0]
        return RuleCheck(
            name="passwords_hashed_with_kdf",
            passed=True,
            detail=(
                f"{model.class_name}.{column.name} at {location} is hashed and {symbol.name} at "
                f"{ev.loc(symbol.file_path, symbol.line_number)} uses a slow key derivation "
                "function"
            ),
            file_path=model.file_path,
            line_number=column.line_number,
        )

    return RuleCheck(
        name="passwords_hashed_with_kdf",
        passed=True,
        detail=(
            f"{model.class_name}.{column.name} at {location} is marked hashed by the scanner; the "
            "key derivation function in use was not visible in the captured source"
        ),
        file_path=model.file_path,
        line_number=column.line_number,
    )


def _logging_check(code_result) -> RuleCheck:
    all_log_edges = ev.find_edges(code_result, "log_output")
    edges = [edge for edge in all_log_edges if edge.pii_categories]
    if not edges:
        return RuleCheck(
            name="pii_not_logged_in_plaintext",
            passed=True,
            detail=(
                f"none of the {len(all_log_edges)} logging call(s) traced by the scanner carry "
                "personal data"
            ),
        )
    edge = edges[0]
    rendered = ev.join_names(
        [
            f"{e.source_symbol} at {ev.loc(e.source_file, e.source_line)} logs "
            f"{ev.join_names(e.pii_categories)}"
            for e in edges
        ],
        limit=3,
    )
    return RuleCheck(
        name="pii_not_logged_in_plaintext",
        passed=False,
        detail=f"{len(edges)} logging call(s) write personal data in clear text: {rendered}",
        file_path=edge.source_file,
        line_number=edge.source_line,
    )


def _auth_check(code_result) -> RuleCheck:
    pii_files = [ref.file_path for ref in code_result.pii_fields if ref.file_path]
    candidates = [
        route
        for route in code_result.routes
        if route.file_path in pii_files
        or ev.matches(route.path, _PII_ROUTE_KEYWORDS)
        or ev.matches(route.handler_name, _PII_ROUTE_KEYWORDS)
    ]
    if not candidates:
        return RuleCheck(
            name="pii_endpoints_authenticated",
            passed=True,
            detail=(
                f"none of the {len(code_result.routes)} route(s) found handle personal data, so "
                "no authentication obligation arises on them"
            ),
        )
    open_routes = [route for route in candidates if not route.has_auth]
    if not open_routes:
        first = candidates[0]
        return RuleCheck(
            name="pii_endpoints_authenticated",
            passed=True,
            detail=(
                f"all {len(candidates)} personal data endpoint(s) require authentication, "
                f"including {first.http_method} {first.path} at "
                f"{ev.loc(first.file_path, first.line_number)}"
            ),
        )
    route = open_routes[0]
    rendered = ev.join_names(
        [
            f"{r.http_method} {r.path} at {ev.loc(r.file_path, r.line_number)}"
            for r in open_routes
        ],
        limit=3,
    )
    return RuleCheck(
        name="pii_endpoints_authenticated",
        passed=False,
        detail=(
            f"{len(open_routes)} of {len(candidates)} personal data endpoint(s) are reachable "
            f"without authentication: {rendered}"
        ),
        file_path=route.file_path,
        line_number=route.line_number,
    )


def _https_check(web_result) -> RuleCheck:
    insecure_forms = [form for form in web_result.forms if not form.submits_over_https]
    if web_result.served_over_https and not insecure_forms:
        return RuleCheck(
            name="https_enforced",
            passed=True,
            detail=(
                f"{web_result.entry_url} is served over HTTPS and all {len(web_result.forms)} "
                "form(s) submit over HTTPS"
            ),
        )
    if not web_result.served_over_https:
        return RuleCheck(
            name="https_enforced",
            passed=False,
            detail=f"{web_result.entry_url} is served over plain HTTP",
        )
    rendered = ev.join_names([form.action for form in insecure_forms])
    return RuleCheck(
        name="https_enforced",
        passed=False,
        detail=(
            f"{len(insecure_forms)} form(s) submit personal data over plain HTTP "
            f"(posting to {rendered})"
        ),
    )


def _headers_check(web_result) -> RuleCheck:
    # The scanner reports every header it looked for, using an empty value for
    # the ones the server did not send. Iterating the keys therefore counts an
    # absent header as present, which graded a site missing CSP, referrer-policy
    # and x-content-type-options as fully compliant.
    present = [
        ev.normalise(name)
        for name, value in web_result.security_headers.items()
        if (value or "").strip()
    ]
    missing = [name for name in _REQUIRED_HEADERS if ev.normalise(name) not in present]
    missing_recommended = [
        name for name in _RECOMMENDED_HEADERS if ev.normalise(name) not in present
    ]
    if missing:
        detail = (
            f"{len(missing)} baseline security header(s) missing on {web_result.entry_url}: "
            f"{ev.join_names(missing)}"
        )
        if missing_recommended:
            detail = f"{detail}; also missing recommended {ev.join_names(missing_recommended)}"
        return RuleCheck(name="security_headers_present", passed=False, detail=detail)
    detail = f"all baseline security headers present on {web_result.entry_url}"
    if missing_recommended:
        detail = f"{detail}; recommended {ev.join_names(missing_recommended)} not set"
    return RuleCheck(name="security_headers_present", passed=True, detail=detail)


def _cookie_flag_checks(web_result) -> list[RuleCheck]:
    """A cookie is a stored identifier, so its flags are a s.8(5) safeguard."""
    if not web_result.cookies:
        return []

    unflagged: list[str] = []
    for cookie in web_result.cookies:
        weaknesses: list[str] = []
        if not cookie.secure:
            weaknesses.append("no Secure flag")
        same_site = (cookie.same_site or "").strip()
        if not same_site:
            weaknesses.append("no SameSite attribute")
        elif same_site.lower() == "none":
            # The browser reports an explicit SameSite=None as the string None.
            # It is set, but it permits exactly what the attribute exists to
            # prevent, so it is reported rather than counted as protection.
            weaknesses.append("SameSite=None which does not restrict cross-site sending")
        if weaknesses:
            unflagged.append(
                f'"{cookie.name}" on {cookie.domain} with {" and ".join(weaknesses)}'
            )
    no_http_only = [
        f'"{cookie.name}" on {cookie.domain}'
        for cookie in web_result.cookies
        if not cookie.http_only
    ]

    if unflagged:
        detail = (
            f"{len(unflagged)} of {len(web_result.cookies)} cookie(s) on {web_result.entry_url} "
            f"are missing a protective flag: {ev.join_names(unflagged, limit=3)}"
        )
        if no_http_only:
            detail = (
                f"{detail}; {len(no_http_only)} cookie(s) are also readable by script with no "
                f"HttpOnly flag ({ev.join_names(no_http_only, limit=3)})"
            )
        return [RuleCheck(name="cookies_carry_secure_flags", passed=False, detail=detail)]

    detail = (
        f"all {len(web_result.cookies)} cookie(s) on {web_result.entry_url} are set with Secure "
        "and a SameSite attribute that restricts cross-site sending"
    )
    if no_http_only:
        detail = (
            f"{detail}; {len(no_http_only)} of them are still readable by script with no HttpOnly "
            f"flag ({ev.join_names(no_http_only, limit=3)})"
        )
    return [RuleCheck(name="cookies_carry_secure_flags", passed=True, detail=detail)]


def _sensitive_field_checks(web_result) -> list[RuleCheck]:
    """Fields the Act expects extra care around must not be collected carelessly.

    A crawl can see two things about that care: whether the field leaves the
    browser over TLS, and whether it is posted to somebody else's host. Both are
    checked per field so the finding names the field rather than the site.
    """
    fields = ev.sensitive_fields(web_result)
    if not fields:
        return []

    entry_host = _host_of(web_result.entry_url)
    exposed: list[str] = []
    for field in fields:
        if not web_result.served_over_https:
            exposed.append(
                f'"{field.name}" collected on a page served over plain HTTP'
            )
            continue
        for form in ev.forms_collecting(web_result, field.name):
            if not form.submits_over_https:
                exposed.append(
                    f'"{field.name}" submitted over plain HTTP by the form posting to {form.action}'
                )
                continue
            action_host = _host_of(form.action)
            if action_host and entry_host and action_host != entry_host:
                exposed.append(
                    f'"{field.name}" posted off-site to {action_host} by the form at {form.action}'
                )

    names = ev.join_names([field.name for field in fields], limit=4)
    if exposed:
        return [
            RuleCheck(
                name="sensitive_fields_collected_with_care",
                passed=False,
                detail=(
                    f"{len(fields)} sensitive category field(s) are collected on "
                    f"{web_result.entry_url} ({names}) and "
                    f"{ev.join_names(list(dict.fromkeys(exposed)), limit=3)}"
                ),
            )
        ]
    return [
        RuleCheck(
            name="sensitive_fields_collected_with_care",
            passed=True,
            detail=(
                f"{len(fields)} sensitive category field(s) are collected on "
                f"{web_result.entry_url} ({names}), each over HTTPS and to the site's own host; "
                "a reviewer still has to confirm how they are stored"
            ),
        )
    ]


def _host_of(url: str) -> str:
    """Host part of a URL, empty for a relative action that stays on this site."""
    if "//" not in url:
        return ""
    remainder = url.split("//", 1)[1]
    return remainder.split("/", 1)[0].split("@")[-1].lower()
