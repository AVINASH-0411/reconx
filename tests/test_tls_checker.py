
import ssl
import pytest

from reconx.modules.tls_checker import check_tls


def test_check_tls_rejects_empty_target():
    with pytest.raises(ValueError):
        check_tls("")


def test_check_tls_rejects_invalid_port():
    with pytest.raises(ValueError):
        check_tls("example.com", port=70000)


def test_check_tls_rejects_boolean_port():
    with pytest.raises(ValueError):
        check_tls("example.com", port=True)


def test_check_tls_rejects_invalid_timeout():
    with pytest.raises(ValueError):
        check_tls("example.com", timeout=0)


def test_check_tls_rejects_boolean_timeout():
    with pytest.raises(ValueError):
        check_tls("example.com", timeout=True)


def test_check_tls_returns_certificate_details(monkeypatch):
    class FakeTLSSocket:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

        def getpeercert(self):
            return {
                "notBefore": "Jan  1 00:00:00 2025 GMT",
                "notAfter": "Jan  1 00:00:00 2035 GMT",
                "subject": ((("commonName", "example.com"),),),
                "issuer": ((("commonName", "Test CA"),),),
            }

        def cipher(self):
            return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

        def version(self):
            return "TLSv1.3"

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    class FakeContext:
        def wrap_socket(self, connection, server_hostname):
            assert server_hostname == "example.com"
            return FakeTLSSocket()

    monkeypatch.setattr(
        "reconx.modules.tls_checker.ssl.create_default_context",
        lambda: FakeContext(),
    )

    monkeypatch.setattr(
        "reconx.modules.tls_checker.socket.create_connection",
        lambda address, timeout: FakeConnection(),
    )

    result = check_tls("example.com")

    assert result["target"] == "example.com"
    assert result["tls_version"] == "TLSv1.3"
    assert result["cipher"] == "TLS_AES_256_GCM_SHA384"
    assert result["certificate_valid"] is True
    assert result["hostname_verified"] is True
    assert result["verification"] == "passed"


def test_check_tls_handles_verification_failure(monkeypatch):
    class FakeContext:
        def wrap_socket(self, connection, server_hostname):
            raise ssl.SSLCertVerificationError(
                "Certificate verification failed"
            )

    class FakeConnection:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            pass

    monkeypatch.setattr(
        "reconx.modules.tls_checker.ssl.create_default_context",
        lambda: FakeContext(),
    )

    monkeypatch.setattr(
        "reconx.modules.tls_checker.socket.create_connection",
        lambda address, timeout: FakeConnection(),
    )

    with pytest.raises(ValueError, match="verification failed"):
        check_tls("example.com")
