"""The cookie jar is a point-in-time reading, so one snapshot is not enough.

Found live on a consent management platform's own site. A Google Ads cookie was
written while the entry page loaded, and by the end of a ten page crawl it was
gone, almost certainly cleared by the site's own consent manager once it found
no stored choice. Reading only the final jar reported it as never written.

Those are different findings. "An advertising cookie was set before any choice
was offered, and later withdrawn" is real and weaker. "No advertising cookie
was set" is false. Taking the union of the entry snapshot and the final one
keeps both facts, and the flag keeps them apart.
"""

from app.contracts import CookieInfo, WebScanResult


def cookie(name: str, **kw) -> CookieInfo:
    base = dict(
        domain=".example.test",
        secure=True,
        http_only=False,
        set_before_consent=True,
    )
    base.update(kw)
    return CookieInfo(name=name, **base)


class TestWithdrawnCookiesAreStillReported:
    def test_a_withdrawn_cookie_still_counts_as_set_before_consent(self):
        result = WebScanResult(
            entry_url="https://example.test",
            cookies=[
                cookie("_gcl_au", classification="advertising", withdrawn_during_crawl=True)
            ],
        )
        assert len(result.cookies_before_consent) == 1
        assert result.cookies_before_consent[0].name == "_gcl_au"

    def test_the_withdrawal_is_recorded_rather_than_implied(self):
        withdrawn = cookie("_gcl_au", classification="advertising", withdrawn_during_crawl=True)
        persistent = cookie("_ga", classification="analytics")
        assert withdrawn.withdrawn_during_crawl
        assert not persistent.withdrawn_during_crawl

    def test_default_is_not_withdrawn(self):
        # A cookie seen in the final jar is present, and must never be labelled
        # withdrawn by omission.
        assert cookie("_ga").withdrawn_during_crawl is False


class TestSnapshotUnion:
    """The merge itself, expressed over the two snapshots the scanner takes."""

    @staticmethod
    def _merge(entry: dict, final: dict) -> list[tuple[str, bool]]:
        merged = dict(entry)
        merged.update(final)
        return [(key, key in entry and key not in final) for key in merged]

    def test_a_cookie_only_in_the_entry_snapshot_survives_the_merge(self):
        merged = self._merge({("_gcl_au", ".x"): {}}, {})
        assert merged == [(("_gcl_au", ".x"), True)]

    def test_a_cookie_only_in_the_final_snapshot_is_kept_and_not_flagged(self):
        merged = self._merge({}, {("_ga", ".x"): {}})
        assert merged == [(("_ga", ".x"), False)]

    def test_a_cookie_in_both_is_not_flagged(self):
        merged = self._merge({("_ga", ".x"): {}}, {("_ga", ".x"): {}})
        assert merged == [(("_ga", ".x"), False)]

    def test_the_final_value_wins_for_a_cookie_in_both(self):
        entry = {("sid", ".x"): {"value": "old"}}
        final = {("sid", ".x"): {"value": "new"}}
        merged = dict(entry)
        merged.update(final)
        assert merged[("sid", ".x")]["value"] == "new"
