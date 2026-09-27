"""Evidence must not expose the server's filesystem.

An uploaded archive is extracted under a per-scan workspace directory, so
code_result.root_path is an absolute server path. Interpolating it into a
detail string put it in the API response, the dashboard and the PDF report.
"""

import re

from app.contracts import CodeScanResult, FileInfo
from app.rules import engine

WORKSPACE_ROOT = r"C:\Users\someone\app\backend\workspace\0c2f\src"

ABSOLUTE_PATH = re.compile(r"(?:[A-Za-z]:[\\/])|(?:/(?:home|Users|var|tmp|root)/)")


def _code_result() -> CodeScanResult:
    return CodeScanResult(
        root_path=WORKSPACE_ROOT,
        files=[
            FileInfo(path="app.py", language="python", line_count=40),
            FileInfo(path="models.py", language="python", line_count=30),
        ],
    )


def test_no_verdict_evidence_contains_the_workspace_root():
    for verdict in engine.run_all(code_result=_code_result(), flows=[]):
        assert WORKSPACE_ROOT not in verdict.evidence, verdict.rule_id


def test_no_check_detail_contains_the_workspace_root():
    for verdict in engine.run_all(code_result=_code_result(), flows=[]):
        for check in verdict.checks:
            assert WORKSPACE_ROOT not in check.detail, f"{verdict.rule_id}/{check.name}"


def test_no_evidence_string_looks_like_an_absolute_path():
    """Catches any new checker that interpolates a root or an absolute path.

    File references in evidence are meant to be repo-relative, like
    models.py:43, so that a reader can find them in their own checkout.
    """
    offenders = []
    for verdict in engine.run_all(code_result=_code_result(), flows=[]):
        if ABSOLUTE_PATH.search(verdict.evidence):
            offenders.append(f"{verdict.rule_id} evidence")
        for check in verdict.checks:
            if ABSOLUTE_PATH.search(check.detail):
                offenders.append(f"{verdict.rule_id}/{check.name}")
            if check.file_path and ABSOLUTE_PATH.search(check.file_path):
                offenders.append(f"{verdict.rule_id}/{check.name} file_path")
    assert not offenders, f"absolute paths in evidence: {offenders}"
