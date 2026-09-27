"""The scanner fetches a URL a user supplies, so it must not become an SSRF proxy."""

import pytest

from app.scanner.url_guard import (
    UnsafeURLError,
    registrable_domain,
    same_site,
    validate_scan_url,
)


class TestScheme:
    def test_rejects_file_scheme(self):
        with pytest.raises(UnsafeURLError):
            validate_scan_url("file:///etc/passwd")

    def test_rejects_gopher_scheme(self):
        with pytest.raises(UnsafeURLError):
            validate_scan_url("gopher://example.com")

    def test_assumes_https_when_scheme_is_omitted(self):
        assert validate_scan_url("example.com").startswith("https://")


class TestPrivateAddresses:
    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1:8000",
            "http://localhost:8000",
            "http://10.0.0.1",
            "http://192.168.1.1",
            "http://172.16.0.1",
            "http://[::1]",
        ],
    )
    def test_rejects_internal_targets(self, url):
        with pytest.raises(UnsafeURLError):
            validate_scan_url(url)

    def test_rejects_cloud_metadata_endpoint(self):
        # 169.254.169.254 is the instance metadata address on every major cloud.
        # Reaching it from a scanner would hand over instance credentials.
        with pytest.raises(UnsafeURLError):
            validate_scan_url("http://169.254.169.254/latest/meta-data/")

    def test_rejects_metadata_hostname(self):
        with pytest.raises(UnsafeURLError):
            validate_scan_url("http://metadata.google.internal/")

    def test_rejects_a_public_name_that_resolves_to_loopback(self):
        # Resolution happens before the check precisely because a public
        # hostname is allowed to point anywhere, including 127.0.0.1.
        with pytest.raises(UnsafeURLError):
            validate_scan_url("http://localtest.me")


class TestUnresolvable:
    def test_rejects_a_hostname_that_does_not_resolve(self):
        with pytest.raises(UnsafeURLError):
            validate_scan_url("https://this-host-should-not-exist.invalid")

    def test_rejects_url_without_hostname(self):
        with pytest.raises(UnsafeURLError):
            validate_scan_url("https://")


class TestSameSite:
    def test_same_host(self):
        assert same_site("https://example.com/a", "https://example.com/b")

    def test_subdomain_counts_as_same_site(self):
        assert same_site("https://shop.example.com/a", "https://example.com/")

    def test_different_host_does_not(self):
        assert not same_site("https://evil.com/a", "https://example.com/")

    def test_handles_malformed_input(self):
        assert not same_site("not a url", "https://example.com/")


class TestPrivateTargetOptIn:
    """Scanning your own app on localhost is the product's main use.

    The guard exists to stop a hosted instance being used as a proxy into its
    own network. A developer self-checking on their machine is a different
    deployment, so the escape hatch is explicit and off by default.
    """

    def test_off_by_default(self):
        from app.config import settings

        assert settings.allow_private_scan_targets is False

    def test_localhost_allowed_when_opted_in(self, monkeypatch):
        from app.config import settings

        monkeypatch.setattr(settings, "allow_private_scan_targets", True)
        assert validate_scan_url("http://127.0.0.1:5000/signup").startswith("http://")

    def test_scheme_still_enforced_when_opted_in(self, monkeypatch):
        from app.config import settings

        monkeypatch.setattr(settings, "allow_private_scan_targets", True)
        with pytest.raises(UnsafeURLError):
            validate_scan_url("file:///etc/passwd")

    def test_metadata_hostname_still_blocked_when_opted_in(self, monkeypatch):
        # An explicit deny by name survives the opt-in, because nobody enables a
        # local self-check in order to read cloud instance credentials.
        from app.config import settings

        monkeypatch.setattr(settings, "allow_private_scan_targets", True)
        with pytest.raises(UnsafeURLError):
            validate_scan_url("http://metadata.google.internal/")


class TestRegistrableDomain:
    """Third-party status decides the data-sharing findings, so the domain
    comparison has to match organisations, not string suffixes.

    Found live: analytics.python.org was reported as a third party receiving
    data from www.python.org. They are the same organisation. Comparing the
    last two labels alone would fix that but break .ac.in, where two unrelated
    universities would both reduce to "ac.in" and look like one site.
    """

    def test_subdomains_share_a_registrable_domain(self):
        assert registrable_domain("analytics.python.org") == "python.org"
        assert registrable_domain("www.python.org") == "python.org"
        assert registrable_domain("python.org") == "python.org"

    def test_indian_academic_domains_stay_distinct(self):
        assert registrable_domain("www.nfsu.ac.in") == "nfsu.ac.in"
        assert registrable_domain("portal.nfsu.ac.in") == "nfsu.ac.in"
        assert registrable_domain("www.iitb.ac.in") == "iitb.ac.in"
        assert registrable_domain("www.nfsu.ac.in") != registrable_domain("www.iitb.ac.in")

    def test_indian_commercial_and_government_domains(self):
        assert registrable_domain("shop.example.co.in") == "example.co.in"
        assert registrable_domain("data.example.gov.in") == "example.gov.in"

    def test_hosting_suffixes_do_not_merge_unrelated_tenants(self):
        a = registrable_domain("alpha.github.io")
        b = registrable_domain("beta.github.io")
        assert a == "alpha.github.io" and b == "beta.github.io" and a != b

    def test_ip_literal_is_returned_unchanged(self):
        assert registrable_domain("127.0.0.1") == "127.0.0.1"

    def test_empty_host(self):
        assert registrable_domain(None) == ""


class TestSameSiteByOrganisation:
    def test_sibling_subdomains_are_same_site(self):
        assert same_site("https://analytics.python.org/x", "https://www.python.org/")

    def test_unrelated_academic_sites_are_not_same_site(self):
        assert not same_site("https://www.iitb.ac.in/", "https://www.nfsu.ac.in/")

    def test_genuine_third_party_is_not_same_site(self):
        assert not same_site("https://media.ethicalads.io/x", "https://www.python.org/")
