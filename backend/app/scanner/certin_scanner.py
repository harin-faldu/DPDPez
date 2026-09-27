"""Evidence for the CERT-In Directions of 28 April 2022.

The AST scanner reads source. These obligations live somewhere else: in
Dockerfiles, Terraform, Helm charts, CI config and logging setup. A compliance
tool that only parses application code cannot see any of them, which is why this
reads the infrastructure files directly.

Four areas, taken from the Directions:

  clock sync      every ICT system clock must synchronise to NIC or NPL. Without
                  it, log timestamps across systems cannot be reconciled and a
                  breach timeline cannot be established at all.
  logging         logs enabled and retained 180 days, within Indian
                  jurisdiction. DPDP pushes access logs for personal data to a
                  year.
  reporting       a reportable incident must reach CERT-In within six hours, so
                  an error path that writes to local disk and stops cannot meet
                  it.
  cryptography    no hardcoded secrets, no credentials in logs, no deprecated
                  TLS.

Collects evidence only. Whether any of it amounts to compliance is the rule
engine's decision, as everywhere else in this codebase.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path

from app.contracts import CertInEvidence, CertInHit

# NTP servers the Directions actually name. Anything else, including the public
# pool, is a finding: the requirement is not "some NTP" but these.
APPROVED_NTP_HOSTS: tuple[str, ...] = (
    "samay1.nic.in",
    "samay2.nic.in",
    "time.nplindia.org",
    "samay.nic.in",
    "nplindia.org",
)

# Files that are an NTP config by name alone; a real chrony.conf lists
# "server ... iburst" lines and never has to say "chrony" in its own body.
_NTP_DEFINITE_FILES = ("chrony.conf", "ntp.conf", "timesyncd.conf")
# Generic files that only count as NTP-relevant alongside a textual clue,
# since ".tf" or "values.yaml" on their own describe almost anything.
_NTP_FILE_MARKERS = _NTP_DEFINITE_FILES + (
    "dockerfile", ".tf", ".yaml", ".yml", ".sh", "helmfile", "values.yaml",
)
_NTP_DIRECTIVE_RE = re.compile(
    r"(?:^|\s)(?:server|pool|NTP|ntp_servers?|timeServers?)\s*[=:]?\s*"
    r"[\"']?([A-Za-z0-9.\-]+\.[A-Za-z]{2,}|\d{1,3}(?:\.\d{1,3}){3})",
    re.I | re.M,
)
_NTP_CONTEXT_RE = re.compile(r"ntp|chrony|timesync|time\.?server|clock", re.I)

# Retention, wherever it is configured. Named settings rather than any number,
# so a page size or a port does not become a retention period.
_RETENTION_RE = re.compile(
    r"(retention_in_days|retention_days|retentionindays|log_retention|"
    r"retention_period|retentionperiod|ilm_delete_after|delete_after|"
    r"expiration_days|max_age_days|rotate_days|retention)"
    r"\s*[=:]\s*[\"']?(\d{1,5})\s*(d|days?)?",
    re.I,
)
_ROTATE_COUNT_RE = re.compile(r"^\s*(daily|weekly|monthly)\s*$|^\s*rotate\s+(\d+)", re.I | re.M)

# Indian regions, for the sovereignty half of the logging obligation.
INDIAN_REGIONS: tuple[str, ...] = (
    "ap-south-1", "ap-south-2", "centralindia", "southindia", "westindia",
    "asia-south1", "asia-south2", "in-mum", "in-hyd", "india",
)
_REGION_RE = re.compile(
    r"(?:region|location|zone|placement)\s*[=:]\s*[\"']?"
    r"([a-z]{2,}[-a-z0-9]*\d?|[A-Za-z ]+)[\"']?",
    re.I,
)

LOGGING_FRAMEWORKS: tuple[str, ...] = (
    "winston", "log4j", "log4js", "serilog", "logback", "bunyan", "pino",
    "fluentbit", "fluentd", "logstash", "filebeat", "opentelemetry",
    "structlog", "loguru", "zap", "logrus", "nlog", "cloudwatch",
)

# Sinks that reach a human quickly enough to matter inside six hours.
ALERT_SINKS: tuple[str, ...] = (
    "pagerduty", "opsgenie", "victorops", "xmatters", "splunk", "sentry",
    "datadog", "newrelic", "sns.publish", "sns_topic", "slack_webhook",
    "hooks.slack.com", "webhook_url", "alertmanager", "siem", "qradar",
    "arcsight", "elastalert", "incident", "notify_oncall",
)

# An error path that ends here has nowhere to escalate from.
_SWALLOW_RE = re.compile(
    r"except[^\n:]*:\s*(?:#[^\n]*)?\n\s*(pass|return\s*(?:None)?)\s*(?:#|$)"
    r"|catch\s*\([^)]*\)\s*\{\s*\}"
    r"|catch\s*\([^)]*\)\s*\{\s*//[^\n]*\n\s*\}",
    re.M,
)

_SECRET_RE = re.compile(
    r"(?P<key>aws_secret_access_key|aws_access_key_id|api[_-]?key|apikey|"
    r"secret[_-]?key|client[_-]?secret|private[_-]?key|password|passwd|token|"
    r"auth[_-]?token|bearer)\s*[=:]\s*[\"']"
    r"(?P<val>[A-Za-z0-9/+_\-\.]{12,})[\"']",
    re.I,
)
# Values that are obviously not a secret, so a template does not read as a leak.
_SECRET_PLACEHOLDERS = (
    "changeme", "your_", "xxx", "placeholder", "example", "dummy", "sample",
    "replace", "todo", "none", "null", "test", "fake", "redacted", "<", "${",
    "{{", "os.environ", "process.env", "getenv", "secret_name", "vault",
)

# A trailing (?!\.?\d) keeps "TLSv1.2"/"TLSv1.3" out: both contain "TLSv1" as a
# literal prefix, and without the lookahead the current, non-deprecated
# protocol would be flagged for merely starting with the deprecated one's name.
_WEAK_TLS_RE = re.compile(
    r"(TLSv1(?:\.[01])?(?!\.?\d)|SSLv[23]|PROTOCOL_TLSv1(?:_1)?"
    r"|ssl_version\s*=\s*[\"']?TLSv1(?:\.[01])?(?!\.?\d)"
    r"|minimum_tls_version\s*[=:]\s*[\"']?(?:1\.0|1\.1)|min_tls_version\s*[=:]\s*[\"']?(?:1\.0|1\.1))",
    re.I,
)

_CREDENTIAL_LOG_RE = re.compile(
    r"(log(?:ger)?\.\w+|console\.(?:log|info|warn|error)|print|printf|fmt\.Print\w*)"
    r"\s*\([^)\n]{0,160}?\b(password|passwd|secret|token|api[_-]?key|otp|cvv|"
    r"aadhaar|private[_-]?key)\b",
    re.I,
)

# Files worth opening. Everything else is application source the AST pass reads.
_CONFIG_SUFFIXES = frozenset(
    {".tf", ".tfvars", ".yaml", ".yml", ".json", ".conf", ".cfg", ".ini",
     ".toml", ".env", ".properties", ".sh", ".bash", ".ps1", ".hcl"}
)
_CONFIG_NAMES = frozenset(
    {"dockerfile", "docker-compose.yml", "docker-compose.yaml", "makefile",
     "chrony.conf", "ntp.conf", "timesyncd.conf", "logrotate.conf"}
)
_SOURCE_SUFFIXES = frozenset({".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".go", ".rb", ".php", ".cs"})

SKIP_DIRECTORIES = frozenset(
    {"node_modules", ".git", "venv", ".venv", "__pycache__", "dist", "build",
     "vendor", ".next", "coverage", ".terraform", "site-packages"}
)

MAX_FILES = 4000
MAX_FILE_BYTES = 400_000


@dataclass
class _Scan:
    evidence: CertInEvidence = field(default_factory=CertInEvidence)


def scan_directory(root_path: str) -> CertInEvidence:
    """Walk a checkout for the infrastructure facts the Directions turn on."""
    state = _Scan()
    root = Path(root_path)
    if not root.exists():
        return state.evidence

    seen = 0
    for path in sorted(root.rglob("*")):
        if seen >= MAX_FILES:
            break
        if not path.is_file() or any(p in SKIP_DIRECTORIES for p in path.parts):
            continue
        name, suffix = path.name.lower(), path.suffix.lower()
        is_config = name in _CONFIG_NAMES or suffix in _CONFIG_SUFFIXES or name.startswith("dockerfile")
        is_source = suffix in _SOURCE_SUFFIXES
        if not (is_config or is_source):
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        seen += 1
        rel = str(path.relative_to(root)).replace("\\", "/")
        if is_config:
            _read_clock_sync(state, rel, text)
            _read_retention(state, rel, text)
            _read_regions(state, rel, text)
        _read_logging(state, rel, text)
        _read_alerting(state, rel, text)
        _read_crypto(state, rel, text, is_source=is_source)

    state.evidence.files_examined = seen
    return state.evidence


def _line_of(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _hit(file_path: str, text: str, index: int, detail: str, value: str = "") -> CertInHit:
    return CertInHit(
        file_path=file_path, line_number=_line_of(text, index), detail=detail, value=value
    )


# ------------------------------------------------------------- clock sync


def _read_clock_sync(state: _Scan, rel: str, text: str) -> None:
    name = rel.lower()
    is_definite_file = any(m in name for m in _NTP_DEFINITE_FILES)
    looks_relevant = is_definite_file or (
        any(m in name for m in _NTP_FILE_MARKERS) and _NTP_CONTEXT_RE.search(text)
    )
    if not looks_relevant:
        return
    for match in _NTP_DIRECTIVE_RE.finditer(text):
        host = match.group(1).strip().lower()
        if "." not in host or host.endswith((".com", ".io")) and "ntp" not in host and "time" not in host:
            # A directive line in a config full of hostnames is not necessarily
            # an NTP server. Only keep ones that read like one.
            window = text[max(0, match.start() - 120) : match.end() + 40]
            if not _NTP_CONTEXT_RE.search(window):
                continue
        approved = any(host.endswith(a) or host == a for a in APPROVED_NTP_HOSTS)
        state.evidence.ntp_servers.append(
            _hit(rel, text, match.start(), f"time source {host}", value=host)
        )
        if approved:
            state.evidence.uses_approved_ntp = True


# --------------------------------------------------------------- logging


def _read_retention(state: _Scan, rel: str, text: str) -> None:
    for match in _RETENTION_RE.finditer(text):
        setting, raw = match.group(1), match.group(2)
        try:
            days = int(raw)
        except ValueError:
            continue
        # A retention of zero or one is a default nobody set, not a policy.
        if days <= 0:
            continue
        state.evidence.log_retention.append(
            _hit(rel, text, match.start(), f"{setting} set to {days} day(s)", value=str(days))
        )


def _read_regions(state: _Scan, rel: str, text: str) -> None:
    for match in _REGION_RE.finditer(text):
        raw = (match.group(1) or "").strip().lower()
        if not raw or len(raw) > 24:
            continue
        indian = any(r in raw for r in INDIAN_REGIONS)
        state.evidence.storage_regions.append(
            _hit(rel, text, match.start(), f"region {raw}", value=raw)
        )
        if indian:
            state.evidence.has_indian_region = True


def _read_logging(state: _Scan, rel: str, text: str) -> None:
    lowered = text.lower()
    for framework in LOGGING_FRAMEWORKS:
        if framework in lowered:
            index = lowered.find(framework)
            state.evidence.logging_frameworks.append(
                _hit(rel, text, index, f"logging via {framework}", value=framework)
            )
            break


# -------------------------------------------------------------- reporting


def _read_alerting(state: _Scan, rel: str, text: str) -> None:
    lowered = text.lower()
    for sink in ALERT_SINKS:
        if sink in lowered:
            index = lowered.find(sink)
            state.evidence.alert_sinks.append(
                _hit(rel, text, index, f"alert path via {sink}", value=sink)
            )
            break
    for match in _SWALLOW_RE.finditer(text):
        state.evidence.swallowed_errors.append(
            _hit(rel, text, match.start(), "an error path ends without raising or notifying")
        )


# ----------------------------------------------------------- cryptography


def _looks_like_placeholder(value: str) -> bool:
    low = value.lower()
    return any(p in low for p in _SECRET_PLACEHOLDERS)


def _read_crypto(state: _Scan, rel: str, text: str, *, is_source: bool) -> None:
    for match in _SECRET_RE.finditer(text):
        value = match.group("val")
        if _looks_like_placeholder(value):
            continue
        # The value is never stored. Only that one was there, and how long.
        state.evidence.hardcoded_secrets.append(
            _hit(
                rel,
                text,
                match.start(),
                f"{match.group('key').lower()} assigned a literal value "
                f"[redacted, {len(value)} characters]",
            )
        )
    for match in _WEAK_TLS_RE.finditer(text):
        state.evidence.weak_tls.append(
            _hit(rel, text, match.start(), f"deprecated transport security: {match.group(0)[:40]}")
        )
    if is_source:
        for match in _CREDENTIAL_LOG_RE.finditer(text):
            state.evidence.credentials_logged.append(
                _hit(rel, text, match.start(), f"a log call carries {match.group(2).lower()}")
            )
