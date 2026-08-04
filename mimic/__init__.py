"""mimic — intercept any app, then call it from Python like a library.

    from mimic import Session, App

Capture your own session with mitmproxy, and mimic reuses your real auth so the
server can't tell your script from the app. Point it at a host and let the AI
write an ergonomic client:  `mimic gen <host>`.
"""
from .agent import AgentPolicy, AgentSession
from .control import ControlPlane
from .session import App, ResponseTooLarge, ScopeViolation, Session

__all__ = [
    "AgentPolicy",
    "AgentSession",
    "ControlPlane",
    "App",
    "ResponseTooLarge",
    "ScopeViolation",
    "Session",
]
__version__ = "0.1.0"
