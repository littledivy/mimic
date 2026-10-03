"""The errors mimic raises instead of a bare requests exception.

A replayed request fails in ways plain HTTP errors don't describe: the session
died, the app signed the request so it can't be replayed, the server pushed us
into a backoff, or the endpoint answered 200 with a body that isn't what it used
to send. Each of those gets its own type carrying the fields you need to act on
(retry_after, field, expected, got) rather than a message you have to parse.

`RequestError` and everything under it also subclass ``requests.HTTPError``, so
existing code catching that keeps working unchanged.

    MimicError
    ├── RequestError          a request came back wrong
    │   ├── AuthError         401 that a re-pull couldn't fix
    │   │   └── SignatureError  the endpoint signs its own requests
    │   ├── RateLimitError    429 that survived the retry budget
    │   └── SchemaDriftError  2xx whose body isn't the shape the app used to send
    ├── PinBlocked            capture-side: the app refused the proxy's certificate
    ├── PersonaConflict       load-side: the headers describe different clients
    ├── VaultError            local: a profile could not be encrypted or read
    ├── DpopError             local: a DPoP proof could not be produced
    ├── ToolchainError        local: an external tool an operation needs isn't here
    ├── RecipeError           a run spec names something the capture can't answer
    └── GeneratorError        a requested code generator isn't installed or failed

The last five are not response-side failures and carry no HTTP response; they
happen before anything is sent, and each names the fields involved.
"""
import requests


class MimicError(Exception):
    """Base for every error mimic raises.

    Carries the shape of the mismatch when there is one, so callers can branch
    on ``field``/``expected``/``got`` instead of matching on the message.
    """

    def __init__(self, message, field=None, expected=None, got=None):
        super().__init__(message)
        self.field = field
        self.expected = expected
        self.got = got


class RequestError(MimicError, requests.HTTPError):
    """A request came back wrong. Still a ``requests.HTTPError``.

    It mixes in ``requests.HTTPError`` (and defines ``__init__`` to bypass the
    OSError that ``HTTPError`` would otherwise delegate to) so that a caller
    written against mimic's old "failures raise requests.HTTPError" contract
    keeps working while new code can catch the richer types.
    """

    def __init__(self, message, response=None, request=None, **meta):
        MimicError.__init__(self, message, **meta)
        self.response = response
        self.request = request


class AuthError(RequestError):
    """Credentials were rejected and could not be refreshed."""


class SignatureError(AuthError):
    """The endpoint signs its own requests, so the capture can't be replayed.

    Per-request signing (AWS SigV4, a nonce + timestamp pair, DPoP) means a
    copied request is rejected no matter how fresh the session is. mimic refuses
    to send the captured values and says which header gave it away; the fix is a
    signer, not a new capture.
    """

    def __init__(self, message, headers=(), **meta):
        super().__init__(message, **meta)
        self.headers = tuple(headers)


class RateLimitError(RequestError):
    """Rate limited, and the retry budget ran out before the server relented.

    ``retry_after`` is the server's own ``Retry-After`` in seconds when it sent
    one, else None.
    """

    def __init__(self, message, retry_after=None, **meta):
        super().__init__(message, **meta)
        self.retry_after = retry_after


class SchemaDriftError(RequestError):
    """A 2xx response whose body isn't what the endpoint used to send.

    The app changed its response format under a client that was generated
    against the old one. ``field``/``expected``/``got`` describe the mismatch.
    """

    @property
    def diff(self):
        """A one-line description of the mismatch, for logs."""
        if self.field is None:
            return str(self)
        parts = [self.field]
        if self.expected is not None:
            parts.append(f"expected {self.expected}")
        if self.got is not None:
            parts.append(f"got {self.got}")
        return " ".join(parts)


class PersonaConflict(MimicError):
    """Captured headers that contradict each other, rejected at load time.

    A User-Agent from one client and an ``x-app-version`` from another describe
    two different apps. Replaying that gets a generic 403 from whichever server
    checks consistency, with nothing pointing at the header that broke it — so
    the contradiction is caught where the profile is built instead.

    ``conflicts`` holds one `mimic.identity.Conflict` per disagreement, naming
    the two headers and what each one said. A wrong passphrase and a modified
    vault file are indistinguishable to any authenticated cipher, so this
    deliberately has no separate "probably tampered" mode.
    """

    def __init__(self, message, conflicts=(), **meta):
        super().__init__(message, **meta)
        self.conflicts = tuple(conflicts)


class VaultError(MimicError):
    """A profile could not be encrypted, written, or read.

    Local storage, not HTTP: no response, no retry. Covers the missing optional
    dependency, a passphrase that fails to open the file, and a vault entry that
    isn't there.
    """


class DpopError(MimicError):
    """A DPoP proof could not be produced, and nothing was sent.

    Never a silent downgrade. The entire point of a proof is that it is bound
    to one key, so every way this can fail — a device that isn't answering, a
    Secure Enclave key that can't be extracted, a clock the server will reject,
    a key file whose halves don't match — is a case where quietly sending the
    request unsigned (or signed by something else) would come back as a 401 the
    caller reads as a revoked session. Naming the problem here is the difference
    between "plug the phone in" and "re-capture your whole session".

    Local, like `VaultError`: there is no HTTP response to attach.
    """


class ToolchainError(MimicError):
    """An external tool this operation needs isn't installed.

    Every other mimic extra degrades by naming itself rather than by vanishing:
    `curl_cffi` missing says `pip install curl_cffi`, and mitmproxy missing says
    what to run. This is the same rule for the capture-side toolchain — frida,
    adb, reflutter, the Android SDK — because the alternative is a command that
    appears to work, attaches to nothing, and reports the app as unpinned.

    ``tool`` is the thing that is missing and ``install`` the command that puts
    it there, so a caller can branch on the first and print the second.
    """

    def __init__(self, message, tool=None, install=None, **meta):
        super().__init__(message, **meta)
        self.tool = tool
        self.install = install


class RecipeError(MimicError):
    """A run spec cannot be carried out, and here is every reason why.

    Reported in full and up front: a recipe that names an endpoint the capture
    never saw should fail before the first request, listing all of its problems,
    not one at a time partway through a run.
    """

    def __init__(self, message, problems=(), **meta):
        super().__init__(message, **meta)
        self.problems = tuple(problems)


class GeneratorError(MimicError):
    """The code generator you asked for isn't here, or didn't work.

    Raised rather than papered over. Silently substituting the deterministic
    generator for one the user explicitly chose would produce a file that looks
    like the AI's work and isn't — the one failure mode here that can't be
    detected by reading the output.
    """


class PinBlocked(MimicError):
    """The app rejected the proxy's certificate, so nothing was captured.

    Capture-side, not response-side: there is no HTTP response to attach, so
    this one is a plain ``MimicError`` rather than a ``RequestError``. See
    docs/pinning.md.
    """
