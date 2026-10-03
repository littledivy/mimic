"""mimic — intercept any app, then call it from Python like a library.

    from mimic import Session, App

Capture your own session with mitmproxy, and mimic reuses your real auth so the
server can't tell your script from the app. Point it at a host and let the AI
write an ergonomic client:  `mimic gen <host>`.

Failures raise a subclass of `requests.HTTPError` — catch `MimicError` from here
when you want to tell a dead session (AuthError) from a rate limit
(RateLimitError) or a response shape that changed under you (SchemaDriftError).

    from mimic import Session, AuthError
"""
from .errors import (
    AuthError,
    DpopError,
    GeneratorError,
    MimicError,
    PersonaConflict,
    PinBlocked,
    RateLimitError,
    RecipeError,
    RequestError,
    SchemaDriftError,
    SignatureError,
    ToolchainError,
    VaultError,
)
from .fingerprint import Fingerprint, akamai, ja3_hash, ja3_string, ja4
from .identity import Persona, Profile
from .session import App, Session
from .shapes import diff, shape_of
from .transport import Transport
from .vault import Vault

__all__ = [
    "Session",
    "App",
    "Transport",
    "Fingerprint",
    "ja3_string",
    "ja3_hash",
    "ja4",
    "akamai",
    "shape_of",
    "diff",
    "Persona",
    "Profile",
    "Vault",
    "MimicError",
    "RequestError",
    "AuthError",
    "SignatureError",
    "RateLimitError",
    "SchemaDriftError",
    "PinBlocked",
    "PersonaConflict",
    "VaultError",
    "DpopError",
    "ToolchainError",
    "RecipeError",
    "GeneratorError",
]
__version__ = "0.1.0"
