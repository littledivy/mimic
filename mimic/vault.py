"""Profiles encrypted at rest.

A saved profile is a bearer credential: it holds the session token your real
phone sent. Writing it to disk as plain JSON would mean any process, backup, or
sync agent on the machine can replay your account, so the vault stores
ciphertext and nothing else.

    from mimic.vault import Vault
    v = Vault()                       # ~/.mimic/profiles, passphrase prompted
    v.save("hinge-iphone", profile.to_bytes())
    data = v.load("hinge-iphone")

Four properties this buys, in the order they matter:

- **Authenticated.** AES-GCM, not a bare encrypt. A modified file fails to
  open rather than decrypting into plausible garbage — see `_open`.
- **Fresh material per write.** A new salt and a new nonce every time, so the
  same profile never produces the same ciphertext twice and key reuse can't
  leak the key.
- **Bound to its name.** The profile name is the AEAD's additional data, so
  copying `hinge.json` to `hinge2.json` makes it fail to open rather than
  yielding a profile under a name nobody chose.
- **Atomic.** Written to a temporary file in the same directory and renamed
  over the target, so an interrupted save can't leave half a profile behind.

The module takes bytes in and gives bytes back. It deliberately knows nothing
about what a profile *is* — that shape lives in `mimic.identity`, and the one
line that joins them is `mimic.session.Session.from_profile`. That is also why
nothing here imports at module scope from `cryptography`: the whole package has
to stay importable for someone who never touches a vault.
"""
import base64
import getpass
import json
import os
import re
import tempfile
from pathlib import Path

from .errors import VaultError


#: scrypt cost. 2**14 with r=8 is ~16 MiB and ~0.1s per call: slow enough that
#: an offline guess at the passphrase is expensive, fast enough to be invisible
#: on an interactive command.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SALT_BYTES = 16
NONCE_BYTES = 12  # GCM's standard nonce; 96 bits, and never reused by accident
KEY_BYTES = 32

_ENVELOPE_VERSION = 1

#: A profile name is a filename, never a path. Rejecting separators and `..`
#: here means the vault directory can't be escaped by anything that can reach
#: `save()` — including a profile name typed on a command line.
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

_INSTALL_HINT = "pip install 'mimic-client[vault]'  # or: pip install cryptography"


def default_home():
    """`$MIMIC_HOME`, else `~/.mimic`. The one place the location is decided."""
    return Path(os.environ.get("MIMIC_HOME") or "~/.mimic").expanduser()


def _require_crypto():
    """Import the AEAD primitives, or say exactly what to install.

    Deferred rather than guarded at import time so `import mimic` — and every
    other module in the package — works on a machine that has never heard of
    `cryptography`.
    """
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    except ImportError:
        raise VaultError(
            f"encrypting profiles needs the `cryptography` package — {_INSTALL_HINT}"
        )
    return AESGCM, Scrypt, InvalidTag


class Vault:
    """Encrypted profile storage in one directory, one file per profile.

    `directory` defaults to `$MIMIC_HOME/profiles`. With no `passphrase`, one is
    taken from `$MIMIC_VAULT_PASSPHRASE`, else read from the terminal without
    echo; an empty passphrase is refused, since it would make the ciphertext
    decryptable by anyone who reads the file.
    """

    def __init__(self, directory=None, passphrase=None, n=SCRYPT_N):
        self.directory = Path(directory) if directory else default_home() / "profiles"
        self._passphrase = passphrase
        self._n = n

    # -- key material --------------------------------------------------------
    def _secret(self):
        """The passphrase, from the argument, the environment, or the terminal.

        The environment comes before the prompt because `mimic run` exists to be
        scripted, and a scripted run has no terminal to prompt. getpass raises a
        bare EOFError when there isn't one, which reaches the user as a
        traceback with no indication of what to set.
        """
        if self._passphrase is None:
            self._passphrase = os.environ.get("MIMIC_VAULT_PASSPHRASE")
        if self._passphrase is None:
            try:
                self._passphrase = getpass.getpass("vault passphrase: ")
            except (EOFError, OSError):
                raise VaultError(
                    "no terminal to read a vault passphrase from — set "
                    "MIMIC_VAULT_PASSPHRASE to run this without one"
                )
        if not self._passphrase.strip():
            raise VaultError(
                "an empty passphrase encrypts the profile with a key anyone can "
                "derive from the file itself — pass one, or use a real vault"
            )
        return self._passphrase

    def _key(self, passphrase, salt, n, r, p):
        _, Scrypt, _ = _require_crypto()
        return Scrypt(salt=salt, length=KEY_BYTES, n=n, r=r, p=p).derive(
            passphrase.encode("utf-8")
        )

    # -- sealing and opening -------------------------------------------------
    def _seal(self, passphrase, name, plaintext):
        """Encrypt under a fresh salt and nonce. Returns the file envelope."""
        AESGCM, _, _ = _require_crypto()
        salt, nonce = os.urandom(SALT_BYTES), os.urandom(NONCE_BYTES)
        key = self._key(passphrase, salt, self._n, SCRYPT_R, SCRYPT_P)
        blob = AESGCM(key).encrypt(nonce, plaintext, name.encode("utf-8"))
        return {
            "version": _ENVELOPE_VERSION,
            "kdf": {"name": "scrypt", "n": self._n, "r": SCRYPT_R, "p": SCRYPT_P},
            "salt": _b64(salt),
            "nonce": _b64(nonce),
            "ct": _b64(blob),
        }

    def _open(self, passphrase, name, envelope):
        """Decrypt and authenticate. Never returns unverified bytes.

        A wrong passphrase and a modified file are the same failure — that is
        the property authenticated encryption is for, and there is deliberately
        no way to tell them apart. The message says so rather than guessing,
        because guessing wrong sends the reader chasing a bug that isn't there.
        """
        AESGCM, _, InvalidTag = _require_crypto()
        try:
            kdf = envelope["kdf"]
            key = self._key(passphrase, _unb64(envelope["salt"]),
                            kdf["n"], kdf["r"], kdf["p"])
            return AESGCM(key).decrypt(_unb64(envelope["nonce"]),
                                       _unb64(envelope["ct"]),
                                       name.encode("utf-8"))
        except InvalidTag:
            raise VaultError(
                f"could not open profile {name!r} — the passphrase is wrong, or "
                f"the file has been modified since it was written"
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise VaultError(f"profile {name!r} is not a readable vault file: {exc}")

    # -- the four operations -------------------------------------------------
    def path_for(self, name):
        """Where `name` lives, after checking it can't escape the vault."""
        if not _NAME.match(name or ""):
            raise VaultError(
                f"{name!r} is not a valid profile name — use letters, digits, "
                f"'-', '_' and '.'"
            )
        return self.directory / f"{name}.json"

    def save(self, name, data):
        """Encrypt `data` and write it as `name`. Returns the path."""
        path = self.path_for(name)
        envelope = self._seal(self._secret(), name, bytes(data))
        self.directory.mkdir(parents=True, exist_ok=True)
        blob = json.dumps(envelope).encode("utf-8")
        # Same directory so the rename below stays within one filesystem, where
        # it is atomic. mkstemp creates 0600 regardless of umask, which is the
        # right mode for a credential's shadow without a chmod to forget.
        fd, tmp = tempfile.mkstemp(dir=str(self.directory), prefix=".mimic-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(blob)
            os.replace(tmp, path)
        except BaseException:
            if os.path.exists(tmp):
                os.unlink(tmp)
            raise
        return path

    def load(self, name):
        """Decrypt `name` and return the exact bytes that were saved."""
        path = self.path_for(name)
        if not path.exists():
            raise VaultError(f"no profile named {name!r} in {self.directory}")
        try:
            envelope = json.loads(path.read_bytes().decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise VaultError(f"profile {name!r} at {path} isn't valid vault JSON: {exc}")
        if not isinstance(envelope, dict) or envelope.get("version") != _ENVELOPE_VERSION:
            raise VaultError(
                f"profile {name!r} is in vault format {envelope.get('version')!r}, "
                f"which this version of mimic can't read"
            )
        return self._open(self._secret(), name, envelope)

    def names(self):
        """Every profile in the vault, sorted. No passphrase needed."""
        if not self.directory.is_dir():
            return []
        return sorted(p.stem for p in self.directory.glob("*.json")
                      if _NAME.match(p.stem))

    def delete(self, name):
        """Remove a profile. Raises if there was nothing to remove."""
        path = self.path_for(name)
        if not path.exists():
            raise VaultError(f"no profile named {name!r} in {self.directory}")
        path.unlink()


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _unb64(text):
    return base64.b64decode(text.encode("ascii"), validate=True)