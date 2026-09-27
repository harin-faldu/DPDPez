"""Finding the document at all, which is most of stage 1's job.

Every case here comes from a real site that defeated an earlier version.
"""

from app.policy import discovery


class TestLocalePrefixedProbing:
    """A notice under a locale prefix is invisible to origin-only probing.

    recharge.com publishes at /en/in/privacy-statement. Probing only the origin
    asked for /privacy-statement, got a soft 404, and reported a large payments
    site as publishing no policy at all.
    """

    def test_the_origin_is_always_a_base(self):
        bases = discovery.probe_bases("https://example.test/en/in")
        assert "https://example.test/" in bases

    def test_a_locale_prefix_becomes_a_base(self):
        bases = discovery.probe_bases("https://example.test", "https://example.test/en/in")
        assert any(b.rstrip("/").endswith("/en/in") for b in bases)

    def test_a_single_segment_prefix_becomes_a_base(self):
        bases = discovery.probe_bases("https://example.test", "https://example.test/en-in/")
        assert any(b.rstrip("/").endswith("/en-in") for b in bases)

    def test_deep_paths_do_not_become_bases(self):
        # A landing page five levels down is not a locale root, and probing
        # beneath it would spend the budget on nothing.
        bases = discovery.probe_bases(
            "https://example.test", "https://example.test/a/b/c/d/e"
        )
        assert all(b.count("/") <= 5 for b in bases)

    def test_probes_are_generated_for_each_base_without_duplicates(self):
        records = discovery.probe_candidates(
            "https://example.test", "https://example.test/en/in"
        )
        urls = [r["url"] for r in records]
        assert len(urls) == len(set(urls))
        assert any("/en/in/privacy" in u for u in urls)
        assert any(u.rstrip("/").endswith("example.test/privacy") for u in urls)


class TestSuppliedPolicyUrls:
    """The fallback when discovery cannot reach the document.

    A client rendered notice returns an empty shell over plain HTTP. Guessing
    harder does not fix that, so the caller can name the document instead.
    """

    def test_a_supplied_url_becomes_a_candidate(self):
        records = discovery.supplied_candidates(["https://example.test/legal/privacy"])
        assert len(records) == 1
        assert records[0]["via"] == discovery.VIA_SUPPLIED

    def test_the_kind_is_read_from_the_path(self):
        records = discovery.supplied_candidates(["https://example.test/cookie-policy"])
        assert records[0]["kind"] == "cookie"

    def test_an_unclassifiable_path_defaults_to_the_privacy_notice(self):
        records = discovery.supplied_candidates(["https://example.test/doc/1234"])
        assert records[0]["kind"] == "privacy"

    def test_a_supplied_url_is_never_recorded_as_linked(self):
        """Someone pasting a link is not evidence the site links it.

        Whether the notice precedes collection is a separate finding, and
        marking a supplied document linked would answer it wrongly.
        """
        records = discovery.supplied_candidates(["https://example.test/privacy"])
        assert records[0]["linked"] is False
        assert records[0]["footer_only"] is False

    def test_empty_and_unfetchable_entries_are_dropped(self):
        records = discovery.supplied_candidates(
            ["", "   ", "javascript:void(0)", "#top", None]
        )
        assert records == []

    def test_a_supplied_url_outranks_a_probe_at_the_same_path(self):
        supplied = discovery.supplied_candidates(["https://example.test/privacy"])
        candidates = discovery.build_candidates("https://example.test", [], supplied)
        key = discovery.normalise_url("https://example.test/privacy")
        assert candidates[key]["via"] == discovery.VIA_SUPPLIED

    def test_a_supplied_url_is_never_crowded_out_of_the_budget(self):
        # The reason one was supplied is that discovery already failed, so it
        # must not lose the fetch budget to the guesses that already missed.
        supplied = discovery.supplied_candidates(["https://example.test/hidden/notice"])
        candidates = discovery.build_candidates("https://example.test", [], supplied)
        ordered = discovery.order_candidates(candidates)
        assert ordered[0]["via"] == discovery.VIA_SUPPLIED


class TestBoilerplateRejection:
    def test_a_page_that_is_mostly_the_homepage_is_furniture(self):
        home = "About Us\nCareers and Openings\nContact Our Team\nPrivacy Policy Link"
        page = "About Us\nCareers and Openings\nContact Our Team"
        assert discovery.mostly_boilerplate(page, home)

    def test_a_page_with_its_own_prose_is_not(self):
        home = "About Us\nCareers and Openings\nContact Our Team"
        page = (
            "About Us\n"
            "We collect your name, email address and payment details.\n"
            "We retain those records for ninety days after account closure.\n"
            "You may withdraw consent at any time by writing to our officer.\n"
        )
        assert not discovery.mostly_boilerplate(page, home)

    def test_an_empty_page_counts_as_furniture(self):
        assert discovery.mostly_boilerplate("", "About Us\nCareers Here Now")
