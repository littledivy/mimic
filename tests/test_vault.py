"""Encrypted profile storage.

The contract under test: what goes in comes back byte for byte, and anything
that isn't the file we wrote fails to open rather than decrypting into
plausible garbage. A wrong passphrase and a modified file are the same
failure on purpose — that is what authenticated encryption is for, and a vault
that guesses which one it was would be lying.

Tests that need the optional extra skip when it isn't installed; the
missing-extra error is tested unconditionally, by simulating its absence.
"""
import base64
import importlib.util
import json
import sys

import pytest

from mimic import Vault, VaultError
from mimic.vault import SCRYPT_N

HAS_CRYPTO = importlib.util.find_spec("cryptography") is not None
needs_crypto = pytest.mark.skipif(not HAS_CRYPTO, reason="needs the vault extra")

#: The shipped cost is deliberately slow. These tests are about the vault's
#: behaviour, not its work factor, so they turn it down and leave one test at
#: the real default to prove the default itself works.
FAST = 2 ** 8
PROFILE = b'{"version":1,"name":"hinge","headers":{"authorization":"Bearer t"}}'


@pytest.fixture
def vault(tmp_path):
    from mimic.vault import Vault as _Vault

    return _Vault(tmp_path, passphrase="hunter2", n=FAST)


def _flip(path, field, index=0):
    """Corrupt one byte of a base64 field in a stored envelope, in place."""
    envelope = json.loads(path.read_bytes())
    raw = bytearray(base64.b64decode(envelope[field]))
    raw[index] ^= 0xFF
    envelope[field] = base64.b64encode(bytes(raw)).decode()
    path.write_text(json.dumps(envelope))


# ---- the four properties the module exists for ------------------------------
@needs_crypto
def test_a_profile_round_trips_byte_for_byte(vault):
    vault.save("hinge", PROFILE)
    assert vault.load("hinge") == PROFILE


@needs_crypto
def test_a_modified_ciphertext_fails_authentication_rather_than_opening(vault):
    """The difference between encrypting and authenticating: a flipped bit must
    raise, not yield a body with a flipped bit in it."""
    vault.save("hinge", PROFILE)
    _flip(vault.path_for("hinge"), "ct")

    with pytest.raises(VaultError) as exc:
        vault.load("hinge")
    # It must not claim to know which went wrong; it genuinely cannot.
    assert "modified" in str(exc.value) and "passphrase is wrong" in str(exc.value)


@needs_crypto
def test_a_swapped_nonce_fails_authentication(vault):
    vault.save("hinge", PROFILE)
    _flip(vault.path_for("hinge"), "nonce")
    with pytest.raises(VaultError):
        vault.load("hinge")


@needs_crypto
def test_a_modified_salt_fails_authentication(vault):
    vault.save("hinge", PROFILE)
    _flip(vault.path_for("hinge"), "salt")


@needs_crypto
def test_the_wrong_passphrase_fails_instead_of_opening(tmp_path):
    from mimic.vault import Vault as _Vault

    _Vault(tmp_path, passphrase="right", n=FAST).save("hinge", PROFILE)
    with pytest.raises(VaultError):
        _Vault(tmp_path, passphrase="wrong", n=FAST).load("hinge")


@needs_crypto
def test_the_profile_name_is_authenticated_too(vault):
    """Copying a file to a new name must not yield a profile under a name
    nobody chose."""
    vault.save("hinge", PROFILE)
    vault.path_for("other").write_bytes(vault.path_for("hinge").read_bytes())
    with pytest.raises(VaultError):
        vault.load("other")


@needs_crypto
def test_each_write_uses_fresh_material(vault):
    """Same plaintext twice must not produce the same ciphertext twice.

    The salt and the nonce are pinned separately, not just "the file changed":
    a fresh salt alone would change the bytes while leaving the nonce constant,
    and the nonce is the half GCM's security actually rests on.
    """
    def envelope():
        vault.save("hinge", PROFILE)
        return json.loads(vault.path_for("hinge").read_bytes())

    first, second = envelope(), envelope()
    assert first["salt"] != second["salt"]
    assert first["nonce"] != second["nonce"]
    assert first["ct"] != second["ct"]
    assert len(base64.b64decode(first["nonce"])) == 12
    assert len(base64.b64decode(first["salt"])) == 16


@needs_crypto
def test_the_stored_file_is_not_the_profile(vault):
    vault.save("hinge", PROFILE)
    stored = vault.path_for("hinge").read_bytes()
    assert PROFILE not in stored
    assert b"Bearer t" not in stored


@needs_crypto
def test_the_written_file_is_not_world_readable(vault):
    path = vault.save("hinge", PROFILE)
    assert path.stat().st_mode & 0o077 == 0


@needs_crypto
def test_the_shipped_work_factor_actually_works(tmp_path):
    """One save/load at the real cost, so the default isn't merely untested."""
    v = Vault(tmp_path, passphrase="hunter2")
    assert v._n == SCRYPT_N
    v.save("hinge", PROFILE)
    assert v.load("hinge") == PROFILE


@needs_crypto
def test_an_interrupted_save_leaves_no_partial_file(vault, monkeypatch):
    """The write is atomic, so the only thing a failure can damage is the
    temporary file — and it must not survive to be mistaken for a profile."""
    vault.save("hinge", PROFILE)
    original = vault.path_for("hinge").read_bytes()

    def interrupted(src, dst):
        raise OSError("interrupted")

    monkeypatch.setattr("mimic.vault.os.replace", interrupted)
    with pytest.raises(OSError):
        vault.save("other", PROFILE)

    assert vault.path_for("hinge").read_bytes() == original
    assert [p.name for p in vault.directory.iterdir()] == ["hinge.json"]


# ---- refusal paths ----------------------------------------------------------
def test_an_empty_passphrase_is_refused(tmp_path):
    """It would encrypt with a key anyone can derive from the file itself."""
    with pytest.raises(VaultError) as exc:
        Vault(tmp_path, passphrase="   ").save("hinge", PROFILE)
    assert "empty passphrase" in str(exc.value)


def test_a_missing_profile_says_so(tmp_path):
    with pytest.raises(VaultError) as exc:
        Vault(tmp_path, passphrase="x", n=FAST).load("absent")
    assert "no profile named 'absent'" in str(exc.value)


@pytest.mark.parametrize("name", [
    "../escape", "a/b", "", ".", "..", "with space", "null\x00byte",
])
def test_a_name_can_never_escape_the_vault_directory(tmp_path, name):
    """A profile name is a filename, never a path — it can arrive from a command
    line."""
    with pytest.raises(VaultError):
        Vault(tmp_path, passphrase="x", n=FAST).path_for(name)


@needs_crypto
def test_a_file_that_is_not_a_vault_envelope_is_refused(vault):
    vault.save("hinge", PROFILE)
    vault.path_for("hinge").write_text('{"hello": "there"}')
    with pytest.raises(VaultError) as exc:
        vault.load("hinge")
    assert "vault format" in str(exc.value)


@needs_crypto
def test_a_corrupt_vault_file_is_refused_not_half_read(vault):
    vault.save("hinge", PROFILE)
    vault.path_for("hinge").write_bytes(b"{not json")
    with pytest.raises(VaultError):
        vault.load("hinge")


# ---- the optional dependency ------------------------------------------------
@pytest.fixture
def no_crypto(monkeypatch):
    """Make `import cryptography` fail without touching what is installed.

    A `None` in sys.modules only blocks the top-level name, so the already
    imported submodules have to go too.
    """
    for name in [n for n in sys.modules if n.split(".")[0] == "cryptography"]:
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.setitem(sys.modules, "cryptography", None)


def test_the_module_imports_without_the_extra():
    """`import mimic` must work on a machine that has never heard of
    `cryptography`, or every other command is gated on a vault feature."""
    import mimic.vault

    assert mimic.vault.Vault is Vault


def test_the_missing_extra_names_the_install_command(no_crypto, tmp_path):
    with pytest.raises(VaultError) as exc:
        Vault(tmp_path, passphrase="x").save("hinge", PROFILE)
    assert "pip install" in str(exc.value) and "cryptography" in str(exc.value)


def test_a_missing_extra_is_reported_when_reading_too(no_crypto, tmp_path):
    (tmp_path / "hinge.json").write_text(json.dumps({
        "version": 1, "kdf": {"name": "scrypt", "n": FAST, "r": 8, "p": 1},
        "salt": base64.b64encode(b"0" * 16).decode(),
        "nonce": base64.b64encode(b"0" * 12).decode(),
        "ct": base64.b64encode(b"0" * 32).decode(),
    }))
    with pytest.raises(VaultError) as exc:
        Vault(tmp_path, passphrase="x").load("hinge")
    assert "pip install" in str(exc.value)


def test_a_missing_profile_is_reported_before_the_extra_is(no_crypto, tmp_path):
    """The more specific failure comes first — nothing to open is a better
    message than a missing package."""
    with pytest.raises(VaultError) as exc:
        Vault(tmp_path, passphrase="x").load("absent")
    assert "no profile named" in str(exc.value)


def test_listing_profiles_needs_neither_the_extra_nor_the_passphrase(
        no_crypto, tmp_path):
    assert Vault(tmp_path, passphrase="x").names() == []


# ---- the small surface ------------------------------------------------------
def test_names_is_empty_before_anything_is_saved(tmp_path):
    assert Vault(tmp_path, passphrase="x", n=FAST).names() == []


@needs_crypto
def test_names_and_delete_work_on_a_populated_vault(vault):
    vault.save("b", PROFILE)
    vault.save("a", PROFILE)
    assert vault.names() == ["a", "b"]
    vault.delete("a")
    assert vault.names() == ["b"]
    with pytest.raises(VaultError):
        vault.delete("a")


def test_the_default_home_follows_the_environment(monkeypatch, tmp_path):
    from mimic.vault import default_home

    monkeypatch.setenv("MIMIC_HOME", str(tmp_path / "elsewhere"))
    assert default_home() == tmp_path / "elsewhere"
    assert Vault().directory == tmp_path / "elsewhere" / "profiles"


def test_the_passphrase_is_asked_for_once(monkeypatch, tmp_path):
    asked = []

    def fake(prompt=""):
        asked.append(prompt)
        return "hunter2"

    monkeypatch.setattr("getpass.getpass", fake)
    v = Vault(tmp_path, n=FAST)
    v._secret()
    v._secret()
    assert len(asked) == 1