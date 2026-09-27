from enum import StrEnum


class ScanType(StrEnum):
    # Stage 1 of the pipeline: what the organisation says about itself, read
    # before anything observes what it actually does.
    POLICY = "policy"
    WEB = "web"
    CODE = "code"


class ScanStatus(StrEnum):
    PENDING = "pending"
    SCANNING = "scanning"
    ANALYZING = "analyzing"
    COMPLETE = "complete"
    FAILED = "failed"


class RuleStatus(StrEnum):
    COMPLIANT = "compliant"
    GAP = "gap"
    VIOLATION = "violation"
    NOT_APPLICABLE = "not_applicable"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Sensitivity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EdgeType(StrEnum):
    CALLS = "calls"
    IMPORTS = "imports"
    DATA_PASS = "data_pass"
    DB_WRITE = "db_write"
    DB_READ = "db_read"
    API_SEND = "api_send"
    LOG_OUTPUT = "log_output"


class CorpusSource(StrEnum):
    ACT = "act"
    RULES = "rules"
