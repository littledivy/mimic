"""The client fingerprint of an app, recovered from a capture.

Replaying a session gets the credentials right but says nothing about the shape
of the TLS handshake underneath them. Servers that fingerprint clients read that
shape instead: JA3 from the ClientHello, JA4 from the same data plus ALPN, and
the Akamai HTTP/2 string from the connection preface. A client that replays
credentials but handshakes like `requests` is trivially distinguishable, no
matter how correct the bearer token is.

Everything here is pure computation over data already in hand — the point is
that the fingerprint is *measured*, not guessed from a user-agent string. The
one thing a capture cannot always supply is covered honestly at the bottom of
this module: see `from_client_hello` and `from_flow`.

Formats, all documented publicly:

JA3   `version,ciphers,extensions,curves,point_formats`, hashed with MD5.
JA4   `t13d1516h2_<12 hex>_<12 hex>` — version, SNI-vs-IP, cipher and extension
      counts, first ALPN character, then truncated digests of the *sorted* lists
      so that the extension-order shuffling Chrome does doesn't change the hash.
Akamai `settings|window_update|priority|pseudo_headers`, the four client-chosen
      parts of an HTTP/2 connection preface.
"""
import hashlib
from dataclasses import dataclass, field

#: TLS 1.3 as it appears in a ClientHello's legacy_version field.
TLS_1_3_LEGACY = 0x0304
#: The version most clients actually put in legacy_version.
TLS_1_2_LEGACY = 0x0303


def is_grease(value):
    """True for a GREASE value, which is a placeholder a client always omits.

    Chrome and Safari sprinkle these through every list to catch middleboxes
    that mishandle unknown codes. Including them would make an otherwise
    identical handshake hash differently, so both JA3 and JA4 drop them.
    """
    return (value & 0x0F0F) == 0x0A0A and ((value >> 8) & 0xFF) == (value & 0xFF)


def _ints(values, drop_grease=True):
    out = []
    for v in values or ():
        try:
            v = int(v)
        except (TypeError, ValueError):
            continue
        if drop_grease and is_grease(v):
            continue
        out.append(v)
    return out


def ja3_string(version, ciphers, extensions, curves=(), point_formats=()):
    """The canonical JA3 string for a ClientHello's five fields.

    GREASE values are dropped, matching the reference implementation. Extension
    order is preserved as sent — that is what JA3 measures, and the JA4 variants
    exist precisely because the order is unstable across clients.
    """
    return ",".join((
        str(int(version)),
        "-".join(str(c) for c in _ints(ciphers)),
        "-".join(str(e) for e in _ints(extensions)),
        "-".join(str(c) for c in _ints(curves)),
        "-".join(str(p) for p in _ints(point_formats)),
    ))


def ja3_hash(version, ciphers, extensions, curves=(), point_formats=()):
    """The MD5 of `ja3_string` — what servers actually compare."""
    raw = ja3_string(version, ciphers, extensions, curves, point_formats)
    return hashlib.md5(raw.encode()).hexdigest()


def _trunc12(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


def ja4(version, sni, alpn, ciphers, extensions, sig_algs=()):
    """The JA4 fingerprint string.

    Deliberately built from *sorted* cipher and extension lists, so the same
    client hashes the same however it shuffles extension order — which is the
    whole point of JA4 over JA3.
    """
    ciphers = sorted(_ints(ciphers))
    extensions = sorted(_ints(extensions))
    sig_algs = sorted(_ints(sig_algs))

    proto = "13" if int(version) >= TLS_1_3_LEGACY else "12"
    target = "d" if sni else "i"
    # The ALPN character is uppercased, and a client offering no ALPN is "00".
    first_alpn = "0"
    if alpn:
        raw = alpn[0]
        first_alpn = (raw.decode("ascii", "replace") if isinstance(raw, bytes)
                      else str(raw))[:1].upper() or "0"

    cipher_part = _trunc12(",".join(str(c) for c in ciphers))
    ext_part = _trunc12(
        ",".join(str(e) for e in extensions)
        + ("," + ",".join(str(a) for a in sig_algs) if sig_algs else "")
    )
    return (f"t{proto}{target}{len(ciphers):02d}{len(extensions):02d}"
            f"{first_alpn}_{cipher_part}_{ext_part}")


def akamai(settings=(), window_update=None, priority=(), pseudo_headers=()):
    """The Akamai HTTP/2 fingerprint: the four client-chosen preface values.

    `settings` is the initial SETTINGS frame as ``(id, value)`` pairs in wire
    order, `priority` is the PRIORITY frames as already-formatted tuples, and
    `pseudo_headers` is the order the client sent its pseudo-headers in.
    """
    settings_part = ";".join(f"{i}:{v}" for i, v in settings or ()) or "0"
    return "|".join((
        settings_part,
        str(int(window_update or 0)),
        ",".join(priority or ()) or "0",
        ",".join(pseudo_headers or ()) or "0",
    ))


#: IANA TLS SignatureScheme code -> the name curl-impersonate uses for it.
#: curl cannot apply a JA3 on its own; it needs to be told which signature
#: algorithms to pair with the offered ciphers, so a measured fingerprint has
#: to carry this half too.
SIGNATURE_ALGORITHMS = {
    0x0201: "rsa_pkcs1_sha1",
    0x0203: "ecdsa_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0704: "ed25519",
    0x0708: "ed448",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0808: "rsa_pss_pss_sha256",
    0x0809: "rsa_pss_pss_sha384",
    0x080A: "rsa_pss_pss_sha512",
}


@dataclass(frozen=True)
class Fingerprint:
    """A measured client fingerprint, ready to hand to a transport.

    Every field is optional: a capture may yield some of this and not the rest,
    and a transport should pass on whatever it has rather than refuse.
    """

    ja3: str = ""
    ja3_hash: str = ""
    ja4: str = ""
    akamai: str = ""
    sni: str = ""
    alpn: tuple = field(default_factory=tuple)
    sig_algs: tuple = field(default_factory=tuple)

    @property
    def is_empty(self):
        return not (self.ja3 or self.ja4 or self.akamai)

    def curl_kwargs(self):
        """The subset curl_cffi accepts, omitting anything we didn't measure.

        Sending a half-known fingerprint is still far better than sending
        curl's own, so partial data is passed through rather than discarded.
        """
        kwargs = {}
        if self.ja3:
            kwargs["ja3"] = self.ja3
        if self.akamai:
            kwargs["akamai"] = self.akamai
        named = [SIGNATURE_ALGORITHMS[a] for a in self.sig_algs
                 if a in SIGNATURE_ALGORITHMS]
        if named:
            # curl needs these to make sense of the cipher list; a JA3 alone is
            # not enough to build a ClientHello it can send.
            kwargs["extra_fp"] = {"tls_signature_algorithms": named}
        return kwargs

    def __str__(self):
        bits = []
        if self.ja3:
            bits.append(f"ja3 {self.ja3_hash or self.ja3}")
        if self.ja4:
            bits.append(f"ja4 {self.ja4}")
        if self.akamai:
            bits.append(f"h2  {self.akamai}")
        return ", ".join(bits) if bits else "no fingerprint"


def from_client_hello(hello, h2=None):
    """Measure a fingerprint from a parsed ClientHello.

    Written against `mitmproxy.tls.ClientHello`, duck-typed rather than
    imported, so it also accepts anything exposing the same shape. That object
    publishes `cipher_suites` and `extensions`; the TLS version, curves and
    point formats live on its parsed structure, which is read defensively — a
    ClientHello we can only partly read yields the parts we can rather than
    raising mid-capture.

    `h2` is the optional HTTP/2 preface data for the Akamai half.
    """
    ciphers = _ints(getattr(hello, "cipher_suites", ()))
    # `extensions` is [(type, raw_bytes)]; JA3 only wants the types.
    extensions = _ints(t for t, _ in (getattr(hello, "extensions", ()) or ()))

    inner = getattr(hello, "_client_hello", None)
    version = getattr(inner, "legacy_version", None) or TLS_1_2_LEGACY
    curves = _ints(_attr(inner, "extension_supported_groups", "groups"))
    point_formats = _ints(_attr(inner, "extension_ec_point_formats",
                                "ec_point_formats"))
    sig_algs = _ints(_attr(inner, "extension_signature_algorithms",
                           "sig_and_hash_algs"))
    supported = _ints(_attr(inner, "extension_supported_versions", "versions"))

    sni = getattr(hello, "sni", None)
    alpn = tuple(getattr(hello, "alpn_protocols", ()) or ())

    if not ciphers:
        # Nothing measurable. Handing curl a hollow `771,,,,` would be worse
        # than handing it none — an empty ClientHello is a fingerprint too.
        return Fingerprint(sni=sni or "", alpn=alpn)

    # JA4 quotes the version the client can actually negotiate, which is the
    # highest supported version rather than the legacy field.
    ja4_version = max(supported) if supported else version

    h2_data = h2 or {}
    return Fingerprint(
        ja3=ja3_string(version, ciphers, extensions, curves, point_formats),
        ja3_hash=ja3_hash(version, ciphers, extensions, curves, point_formats),
        ja4=ja4(ja4_version, sni, alpn, ciphers, extensions, sig_algs),
        akamai=akamai(
            settings=h2_data.get("settings", ()),
            window_update=h2_data.get("window_update"),
            priority=h2_data.get("priority", ()),
            pseudo_headers=h2_data.get("pseudo_headers", ()),
        ),
        sni=sni or "",
        alpn=alpn,
        sig_algs=tuple(sig_algs),
    )


def _attr(obj, name, sub):
    """`getattr(getattr(obj, name, None), sub, ())` without the nesting."""
    return getattr(getattr(obj, name, None), sub, ()) or ()


def from_flow(flow):
    """Whatever fingerprint a flow record alone can support.

    Be honest about the limit: mitmweb's flow JSON carries the negotiated SNI,
    ALPN and TLS version, but not the offered cipher suites or extensions. So
    this returns a `Fingerprint` with `alpn`/`sni` populated and the JA3/JA4/
    Akamai parts empty — enough to *select* a matching impersonation profile,
    not enough to reproduce the handshake. For the real thing you need the
    ClientHello; see `from_client_hello`.
    """
    conn = flow.get("client_conn") or {}
    raw_alpn = conn.get("alpn") or ""
    return Fingerprint(
        sni=conn.get("sni") or "",
        alpn=tuple(p for p in raw_alpn.split(",") if p),
    )
