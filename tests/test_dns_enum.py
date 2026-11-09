
import pytest
import dns.resolver

from reconx.modules.dns_enum import enumerate_dns


def test_enumerate_dns_rejects_empty_target():
    with pytest.raises(ValueError):
        enumerate_dns("")


def test_enumerate_dns_rejects_invalid_timeout():
    with pytest.raises(ValueError):
        enumerate_dns("example.com", timeout=0)


def test_enumerate_dns_rejects_boolean_timeout():
    with pytest.raises(ValueError):
        enumerate_dns("example.com", timeout=True)


def test_enumerate_dns_returns_records(monkeypatch):

    class FakeAnswer:
        def to_text(self):
            return "192.0.2.1"

    class FakeAnswers:
        rrset = True

        def __iter__(self):
            return iter([FakeAnswer()])

    class FakeResolver:
        timeout = None
        lifetime = None

        def resolve(self, target, record_type, **kwargs):
            if record_type == "A":
                return FakeAnswers()

            raise dns.resolver.NoAnswer

    monkeypatch.setattr(
        "reconx.modules.dns_enum.dns.resolver.Resolver",
        FakeResolver,
    )

    result = enumerate_dns("example.com")

    assert result["target"] == "example.com"
    assert result["records"]["A"] == ["192.0.2.1"]
    assert result["records"]["AAAA"] == []


def test_enumerate_dns_handles_nxdomain(monkeypatch):
    class FakeResolver:
        timeout = None
        lifetime = None

        def resolve(self, target, record_type, **kwargs):
            raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(
        "reconx.modules.dns_enum.dns.resolver.Resolver",
        FakeResolver,
    )

    result = enumerate_dns("nonexistent.example")

    assert result["records"]["A"] == []
    assert result["records"]["error"] == "Domain does not exist."


def test_enumerate_dns_handles_timeout(monkeypatch):
    class FakeResolver:
        timeout = None
        lifetime = None

        def resolve(self, target, record_type, **kwargs):
            raise dns.exception.Timeout

    monkeypatch.setattr(
        "reconx.modules.dns_enum.dns.resolver.Resolver",
        FakeResolver,
    )

    result = enumerate_dns("example.com")

    assert all(
        result["records"][record_type] == []
        for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
    )


def test_enumerate_dns_handles_nameserver_failure(monkeypatch):
    class FakeResolver:
        timeout = None
        lifetime = None

        def resolve(self, target, record_type, **kwargs):
            raise dns.resolver.NoNameservers

    monkeypatch.setattr(
        "reconx.modules.dns_enum.dns.resolver.Resolver",
        FakeResolver,
    )

    result = enumerate_dns("example.com")

    assert all(
        result["records"][record_type] == []
        for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
    )


def test_enumerate_dns_formats_mx_records(monkeypatch):
    class FakeMX:
        preference = 10
        exchange = "mail.example.com."

    class FakeAnswers:
        rrset = True

        def __iter__(self):
            return iter([FakeMX()])

    class FakeResolver:
        timeout = None
        lifetime = None

        def resolve(self, target, record_type, **kwargs):
            if record_type == "MX":
                return FakeAnswers()
            raise dns.resolver.NoAnswer

    monkeypatch.setattr(
        "reconx.modules.dns_enum.dns.resolver.Resolver",
        FakeResolver,
    )

    result = enumerate_dns("example.com")

    assert result["records"]["MX"] == [
        {
            "priority": 10,
            "exchange": "mail.example.com.",
        }
    ]


def test_enumerate_dns_formats_txt_records(monkeypatch):
    class FakeTXT:
        def to_text(self):
            return '"v=spf1 -all"'

    class FakeAnswers:
        rrset = True

        def __iter__(self):
            return iter([FakeTXT()])

    class FakeResolver:
        timeout = None
        lifetime = None

        def resolve(self, target, record_type, **kwargs):
            if record_type == "TXT":
                return FakeAnswers()
            raise dns.resolver.NoAnswer

    monkeypatch.setattr(
        "reconx.modules.dns_enum.dns.resolver.Resolver",
        FakeResolver,
    )

    result = enumerate_dns("example.com")

    assert result["records"]["TXT"] == ['"v=spf1 -all"']


def test_enumerate_dns_normalizes_target(monkeypatch):
    class FakeResolver:
        timeout = None
        lifetime = None

        def resolve(self, target, record_type, **kwargs):
            assert target == "example.com"
            raise dns.resolver.NoAnswer

    monkeypatch.setattr(
        "reconx.modules.dns_enum.dns.resolver.Resolver",
        FakeResolver,
    )

    result = enumerate_dns("  example.com.  ")

    assert result["target"] == "example.com"
