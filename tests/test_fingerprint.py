"""Fingerprint computation.

The JA3 vector below is a golden test: the string and its MD5 are frozen
literals, not recomputed here. If the format, the ordering, the field
separators or the GREASE handling ever change, this fails — which is the point,
since these strings are compared byte-for-byte by the servers that read them.
"""
import hashlib

import pytest

from mimic.fingerprint import (
    Fingerprint,
    akamai,
    from_client_hello,
    from_flow,
    is_grease,
    ja3_hash,
    ja3_string,
    ja4,
)

# A realistic modern ClientHello. 2570 and 6682 are GREASE placeholders that a
# correct JA3 must drop.
VERSION = 771
CIPHERS = [4865, 4866, 4867, 4868, 49195, 49199, 49196, 49200,
           49162, 49161, 49171, 49172, 157, 53, 56]
EXTENSIONS = [0, 23, 65281, 10, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513,
              2570, 6682]
CURVES = [29, 23, 24]
POINT_FORMATS = [0]

EXPECTED_JA3 = ("771,4865-4866-4867-4868-49195-49199-49196-49200-49162-49161-"
                "49171-49172-157-53-56,"
                "0-23-65281-10-35-16-5-13-18-51-45-43-27-17513,"
                "29-23-24,0")
EXPECTED_JA3_HASH = "0539a808b9fcb8433311b60c2bf64011"


# ---- JA3 --------------------------------------------------------------------
def test_ja3_string_is_exact():
    assert ja3_string(VERSION, CIPHERS, EXTENSIONS, CURVES, POINT_FORMATS) \
        == EXPECTED_JA3


def test_ja3_hash_is_exact():
    assert ja3_hash(VERSION, CIPHERS, EXTENSIONS, CURVES, POINT_FORMATS) \
        == EXPECTED_JA3_HASH


def test_the_hash_is_the_md5_of_the_string():
    """Pins the relationship, so the two golden values can't drift apart."""
    assert ja3_hash(VERSION, CIPHERS, EXTENSIONS, CURVES, POINT_FORMATS) == \
        hashlib.md5(EXPECTED_JA3.encode()).hexdigest()


@pytest.mark.parametrize("value", [2570, 6682, 10794, 64250])
def test_grease_values_are_detected(value):
    assert is_grease(value)


@pytest.mark.parametrize("value", [0, 5, 21, 23, 29, 17513, 65281, 4865, 771])
def test_real_values_are_not_mistaken_for_grease(value):
    assert not is_grease(value)


def test_grease_is_excluded_from_ja3():
    """Clients pad their lists with GREASE to trip up middleboxes; including it
    would make an identical handshake hash differently."""
    got = ja3_string(VERSION, CIPHERS, EXTENSIONS, CURVES, POINT_FORMATS)
    assert "2570" not in got and "6682" not in got


def test_ja3_keeps_extension_order_as_sent():
    """Order is what JA3 measures — JA4 exists because it is unstable."""
    assert ja3_string(771, [], [0, 11, 10, 5], [], []) == "771,,0-11-10-5,,"


def test_ja3_of_a_bare_hello():
    assert ja3_string(771, [4865], [0], [], []) == "771,4865,0,,"


# ---- JA4 --------------------------------------------------------------------
def test_ja4_string_is_exact():
    assert ja4(VERSION, "api.example.com", (b"h2",), CIPHERS, EXTENSIONS,
               [0x0403, 0x0804]) == "t12d1514H_ed735d5b1c09_66b9695e3a1c"


def test_ja4_ignores_extension_order():
    """The whole point of JA4: shuffled extensions hash the same."""
    assert ja4(771, "x.com", (b"h2",), [1, 2], [0, 11, 10]) == \
        ja4(771, "x.com", (b"h2",), [2, 1], [11, 10, 0])


def test_ja4_marks_a_missing_sni_as_an_ip_target():
    assert ja4(771, None, (b"h2",), [1], [0]).startswith("t12i")


def test_ja4_counts_exclude_grease():
    """15 real ciphers but 16 offered extensions, two of which are GREASE."""
    assert ja4(771, "x", (b"h2",), CIPHERS, EXTENSIONS).startswith("t12d1514H")


def test_ja4_reports_tls13_when_supported():
    assert ja4(0x0304, "x", (b"h2",), [1], [0]).startswith("t13d")


def test_ja4_with_no_alpn():
    """A client offering no ALPN is marked '0' rather than given a fake value."""
    assert ja4(771, "x", (), [1], [0]).startswith("t12d01010")


# ---- Akamai -----------------------------------------------------------------
def test_akamai_string_is_exact():
    assert akamai([(1, 131072), (2, 0), (4, 4194304), (5, 16384)], 65535, (),
                  [":method", ":authority", ":scheme", ":path"]) == \
        "1:131072;2:0;4:4194304;5:16384|65535|0|:method,:authority,:scheme,:path"


def test_akamai_preserves_settings_order():
    """Settings order is part of the fingerprint; re-sorting it would hide a
    client from exactly the check meant to spot it."""
    assert akamai([(4, 1), (1, 2)], 0).split("|")[0] == "4:1;1:2"


def test_akamai_with_priority_frames():
    assert akamai([(1, 1)], 0, ["3:0:0:201", "5:0:0:100"]).split("|")[2] == \
        "3:0:0:201,5:0:0:100"


def test_akamai_of_an_unknown_preface():
    assert akamai() == "0|0|0|0"


# ---- extraction -------------------------------------------------------------
class FakeHello:
    """Shaped like mitmproxy.tls.ClientHello."""

    def __init__(self, ciphers=None, extensions=None, sni=None, alpn=(),
                 version=None, groups=(), point_formats=(), sig_algs=(),
                 versions=()):
        self.cipher_suites = ciphers if ciphers is not None else CIPHERS
        self.extensions = [(e, b"") for e in
                           (extensions if extensions is not None else EXTENSIONS)]
        self.sni = sni
        self.alpn_protocols = alpn
        inner = type("Parsed", (), {})()
        inner.legacy_version = version if version is not None else VERSION
        inner.extension_supported_groups = type("G", (), {"groups": list(groups)})()
        inner.extension_ec_point_formats = \
            type("P", (), {"ec_point_formats": list(point_formats)})()
        inner.extension_signature_algorithms = \
            type("S", (), {"sig_and_hash_algs": list(sig_algs)})()
        inner.extension_supported_versions = \
            type("V", (), {"versions": list(versions)})()
        self._client_hello = inner


def test_extracting_a_fingerprint_from_a_client_hello():
    got = from_client_hello(
        FakeHello(sni="api.example.com", alpn=(b"h2",), groups=CURVES,
                  point_formats=POINT_FORMATS, sig_algs=[0x0403, 0x0804],
                  versions=[0x0303, 0x0304]),
        h2={"settings": [(1, 131072)], "window_update": 65535,
            "pseudo_headers": [":method", ":path"]},
    )
    assert got.ja3 == EXPECTED_JA3
    assert got.ja3_hash == EXPECTED_JA3_HASH
    assert got.sni == "api.example.com"
    assert got.akamai == "1:131072|65535|0|:method,:path"
    assert not got.is_empty


def test_a_client_hello_we_can_only_partly_read_still_yields_a_fingerprint():
    """A ClientHello without curves must not crash mid-capture."""
    got = from_client_hello(FakeHello(ciphers=[4865], extensions=[0, 11]))
    assert got.ja3 == "771,4865,0-11,,"
    assert got.ja3_hash  # hashing still happened


def test_from_client_hello_survives_an_unexpected_object():
    """Nothing readable means no fingerprint — not a hollow `771,,,,`."""
    got = from_client_hello(object())
    assert got.is_empty
    assert got.curl_kwargs() == {}


# ---- Fingerprint value object ----------------------------------------------
def test_curl_kwargs_pass_only_what_was_measured():
    partial = Fingerprint(ja3="771,4865,0,,")
    assert partial.curl_kwargs() == {"ja3": "771,4865,0,,"}
    assert Fingerprint().curl_kwargs() == {}
    assert Fingerprint(akamai="1:1|0|0|0").curl_kwargs() == {"akamai": "1:1|0|0|0"}


def test_an_empty_fingerprint_says_so():
    assert str(Fingerprint()) == "no fingerprint"
    assert "ja3" in str(Fingerprint(ja3="x", ja3_hash="abc"))


# ---- the honest limit -------------------------------------------------------
def test_from_flow_reports_what_a_flow_record_can_and_cannot_support():
    """mitmweb's flow JSON carries the negotiated SNI and ALPN but not the
    offered ciphers, so the JA3 half is genuinely unavailable here."""
    flow = {"client_conn": {"sni": "api.example.com", "alpn": "h2,http/1.1",
                            "tls_version": "TLSv1.3"}}
    got = from_flow(flow)
    assert got.sni == "api.example.com"
    assert got.alpn == ("h2", "http/1.1")
    assert got.ja3 == "" and got.ja4 == "" and got.akamai == ""
    assert got.curl_kwargs() == {}


def test_from_flow_on_a_plaintext_flow():
    assert from_flow({}).sni == ""
