"""Persona coherence — the load-time gate.

The contract under test: headers that contradict each other are rejected *by
name*, before a request is sent, and nothing is ever invented to make a
profile look complete.

A profile assembled by hand is the normal case, not an edge case — that is why
the check lives at load time and names both headers.
"""
import importlib.util

import pytest

from conftest import Loopback
from mimic import MimicError, Persona, PersonaConflict, Profile, Session

#: Only the two tests that drive a real vault are gated on its extra — the rest
#: of persona coherence needs nothing but the standard library.
HAS_CRYPTO = importlib.util.find_spec("cryptography") is not None
needs_crypto = pytest.mark.skipif(not HAS_CRYPTO, reason="needs the vault extra")

IPHONE_UA = "MyApp/2.1.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"


# ---- contradictory headers are rejected, by name ----------------------------
def test_a_version_that_contradicts_the_user_agent_is_rejected():
    """The whole point: name the two headers, not just 'inconsistent'."""
    persona = Persona.from_headers(
        {"user-agent": IPHONE_UA, "x-app-version": "3.0.0"}
    )
    with pytest.raises(PersonaConflict) as exc:
        persona.validate()
    assert exc.value.conflicts[0].fields == ("user-agent", "x-app-version")
    assert "2.1.0" in str(exc.value) and "3.0.0" in str(exc.value)


def test_the_name_is_the_header_the_capture_actually_sent():
    """`x-app-version` and `x-client-version` both carry a version; blaming the
    wrong one sends the reader to a header the app never sent."""
    persona = Persona.from_headers(
        {"user-agent": IPHONE_UA, "x-client-version": "3.0.0"}
    )
    with pytest.raises(PersonaConflict) as exc:
        persona.validate()
    named = exc.value.conflicts[0].fields
    assert named == ("user-agent", "x-client-version")
    assert "x-app-version" not in named


def test_a_platform_that_contradicts_the_user_agent_is_rejected():
    persona = Persona.from_headers(
        {"user-agent": IPHONE_UA, "x-platform": "Android"}
    )
    with pytest.raises(PersonaConflict) as exc:
        persona.validate()
    assert exc.value.conflicts[0].fields == ("user-agent", "x-platform")
    assert "ios" in str(exc.value) and "android" in str(exc.value)


def test_a_device_model_from_another_os_is_rejected():
    """The model is its own observation, so it conflicts even when the platform
    field was inferred from the User-Agent."""
    persona = Persona.from_headers(
        {"user-agent": IPHONE_UA, "x-device-model": "Pixel 8"}
    )
    assert "platform" in persona.inferred  # read out of the UA…
    with pytest.raises(PersonaConflict) as exc:  # …and still checked against it
        persona.validate()
    assert exc.value.conflicts[0].fields == ("user-agent", "x-device-model")


def test_every_conflicting_header_is_reported_not_just_the_first():
    persona = Persona.from_headers({
        "user-agent": IPHONE_UA,
        "x-app-version": "3.0.0",
        "x-platform": "Android",
    })
    with pytest.raises(PersonaConflict) as exc:
        persona.validate()
    assert len(exc.value.conflicts) == 2


def test_headers_that_agree_produce_no_conflict():
    persona = Persona.from_headers({
        "user-agent": IPHONE_UA,
        "x-app-version": "2.1.0",
        "x-platform": "iOS",
        "x-device-model": "iPhone15,2",
    })
    assert persona.validate() is persona


# ---- nothing is invented, nothing inferred is trusted ------------------------
def test_a_device_id_the_capture_never_showed_stays_absent():
    persona = Persona.from_headers({"user-agent": IPHONE_UA})
    assert persona.device_id == ""


def test_a_value_read_out_of_one_header_never_contradicts_itself():
    """Version, platform and OS version all come from the UA, so there is
    nothing independent for them to disagree with."""
    persona = Persona.from_headers({"user-agent": IPHONE_UA})
    assert persona.inferred == frozenset({"app_version", "platform", "os_version"})
    assert persona.app_version == "2.1.0"
    assert persona.platform == "ios"
    assert persona.validate() is persona


def test_an_observed_header_overrides_the_user_agent_and_is_not_inferred():
    persona = Persona.from_headers(
        {"user-agent": IPHONE_UA, "x-app-version": "2.1.0"}
    )
    assert persona.app_version == "2.1.0"
    assert "app_version" not in persona.inferred


def test_a_user_agent_with_nothing_to_parse_yields_nothing():
    persona = Persona.from_headers({"user-agent": "curl/8.4.0"})
    assert persona.app_version == "8.4.0"  # curl's own version, read normally
    assert persona.platform == ""
    persona.validate()  # no platform claim on either side: nothing to check


def test_header_lookup_is_case_insensitive_like_http():
    persona = Persona.from_headers({
        "User-Agent": IPHONE_UA,
        "X-Client-Version": "3.0.0",
    })
    with pytest.raises(PersonaConflict) as exc:
        persona.validate()
    assert exc.value.conflicts[0].fields == ("user-agent", "x-client-version")


# ---- the profile document ---------------------------------------------------
def _profile():
    return Profile.from_capture(
        "hinge-iphone",
        {"user-agent": IPHONE_UA, "authorization": "Bearer t",
         "x-device-id": "D-1"},
        base_url="https://api.example.com",
        host="api.example.com",
    )


def test_a_profile_round_trips_byte_for_byte():
    """Stable bytes are what make a stored profile verifiable rather than
    merely plausible."""
    original = _profile()
    restored = Profile.from_bytes(original.to_bytes())
    assert restored.to_bytes() == original.to_bytes()


def test_a_loaded_profile_still_names_the_header_that_was_captured():
    """The load-time gate is on the way *in*, not just at assembly time, so the
    record of which header said what has to survive the round trip."""
    # from_capture refuses to assemble this, so hand-build the document to prove
    # one that somehow reached disk still fails when it is read back.
    smuggled = Profile(
        name="bad",
        base_url="https://api.example.com",
        headers=tuple({"user-agent": IPHONE_UA,
                       "x-client-version": "3.0.0"}.items()),
        persona=Persona.from_headers(
            {"user-agent": IPHONE_UA, "x-client-version": "2.1.0"}
        ),
    )
    with pytest.raises(PersonaConflict) as exc:
        Profile.from_bytes(smuggled.to_bytes()).validate()
    assert exc.value.conflicts[0].fields == ("user-agent", "x-client-version")


def test_a_profile_in_an_unknown_format_is_refused():
    profile = _profile()
    document = profile.to_bytes().replace(b'"version":1', b'"version":99')
    with pytest.raises(MimicError) as exc:
        Profile.from_bytes(document)
    assert "99" in str(exc.value)


def test_describe_marks_what_was_inferred_and_what_is_missing():
    lines = _profile().persona.describe().splitlines()
    assert any("app_version" in line and "(inferred)" in line for line in lines)
    assert any("device_model" in line and "(absent)" in line for line in lines)


# ---- the bridge into a Session ----------------------------------------------
@needs_crypto
def test_from_profile_builds_a_session_that_really_replays(tmp_path, loopback):
    """End to end: encrypt a profile, load it back, make a request that lands."""
    from mimic import Vault

    loopback.route("/rec/v2", Loopback.respond({"ok": True}))
    vault = Vault(tmp_path, passphrase="hunter2", n=2 ** 8)
    profile = Profile.from_capture(
        "hinge-iphone",
        {"user-agent": IPHONE_UA, "authorization": "Bearer t"},
        base_url=loopback.base_url,
        host="127.0.0.1",
    )
    vault.save("hinge-iphone", profile.to_bytes())

    session = Session.from_profile("hinge-iphone", vault)
    assert session.get("/rec/v2") == {"ok": True}
    assert loopback.calls[0].headers["Authorization"] == "Bearer t"
    assert session.profile.name == "hinge-iphone"


@needs_crypto
def test_from_profile_rejects_a_contradiction_it_reads_back(tmp_path):
    """A profile that reached disk incoherent fails at load, naming the headers,
    instead of turning into an unexplained 403 later."""
    from mimic import Vault

    vault = Vault(tmp_path, passphrase="hunter2", n=2 ** 8)
    vault.save("bad", Profile(
        name="bad", base_url="https://api.example.com",
        headers=(("user-agent", IPHONE_UA), ("x-client-version", "3.0.0")),
        persona=Persona(user_agent=IPHONE_UA, app_version="2.1.0"),
    ).to_bytes())

    with pytest.raises(PersonaConflict) as exc:
        Session.from_profile("bad", vault)
    assert "x-client-version" in str(exc.value)


def test_from_profile_takes_any_object_that_can_load_a_name():
    """Duck-typed on purpose, so session.py never imports the vault."""
    class Memory:
        def load(self, name):
            return _profile().to_bytes()

    session = Session.from_profile("hinge-iphone", Memory())
    assert session.base_url == "https://api.example.com"
    assert session.headers["x-device-id"] == "D-1"