"""Persona coherence: do these headers tell the same story?

A captured session is a bundle of headers that the real app wrote together, so
they agree — the User-Agent, the device id, the app version, the locale, the
platform. Assemble a profile from headers that contradict each other and the
result isn't a valid client of anything: it claims to be one app while
announcing another's version. Plenty of servers check that consistency, and
the rejection they send back is a generic 403 with nothing pointing at the
header that broke it.

So persona checks are a *load-time* gate, not a runtime retry: catch the
contradiction where the profile is built, name both headers, and stop.

Three rules this module deliberately does not break:

- **Nothing is invented.** A device id that never appeared in the capture stays
  absent. Inventing one would produce a request that looks coherent and isn't.
- **Inference is labelled.** A value derived from the User-Agent is marked
  inferred, because it is a reading of one header rather than a second,
  independent observation — and only independent observations can contradict
  each other. An inferred value never raises a conflict.
- **The name is the observed one.** `x-app-version` and `x-client-version` both
  carry a version, and a message that names the wrong one sends the reader to a
  header that was never sent. Every value therefore remembers the header it
  came from.

`Profile` is the document these live in: a persona plus the base URL and
headers it belongs to. It is what `mimic.vault` stores as opaque bytes and what
`mimic.session.Session` builds itself from — the vault never learns the shape.
"""
import json
import re
from dataclasses import dataclass, field

from .errors import MimicError, PersonaConflict


#: `MyApp/2.1.0` at the head of a User-Agent.
_UA_APP = re.compile(r"^\s*(?P<name>[^\s/]+)/(?P<version>[0-9][0-9A-Za-z.\-]*)")

#: OS tokens, most specific first. `iPhone OS 17_0` and `iOS/17.0` are both iOS,
#: but `iPhone OS` is the older Safari spelling and must be tried first or
#: nothing matches.
_OS_PATTERNS = (
    (re.compile(r"iPhone OS ([\d_]+)", re.I), "iOS"),
    (re.compile(r"CPU OS ([\d_]+)", re.I), "iOS"),
    (re.compile(r"\biOS[ /]([\d_.]+)", re.I), "iOS"),
    (re.compile(r"\bAndroid[ /]([\d.]+)", re.I), "Android"),
    (re.compile(r"\bWindows NT ([\d.]+)", re.I), "Windows"),
)

#: Device-model prefixes that pin a family even when the UA doesn't say so.
_DEVICE_FAMILY = (
    (re.compile(r"^iP(hone|ad|od)", re.I), "ios"),
    (re.compile(r"^Pixel\b|^SM-|^Nexus\b|^Redmi|^OnePlus", re.I), "android"),
)

_VERSION_HEADERS = ("x-app-version", "x-client-version", "x-version")
_DEVICE_ID_HEADERS = ("x-device-id", "x-installation-id", "x-device-uuid",
                      "x-advertising-id", "idfa", "x-ios-device-id")
_PLATFORM_HEADERS = ("x-platform", "x-os", "x-os-platform")
_DEVICE_MODEL_HEADERS = ("x-device-model", "x-device-name")
_OS_VERSION_HEADERS = ("x-os-version", "x-os-version-name")

#: Wire format of a saved profile. Bumped when the document changes shape; a
#: stored profile outlives the code that wrote it, so it is stamped.
_PROFILE_VERSION = 1


def _observed(headers, names):
    """`(value, header_name)` for the first present header among `names`.

    The name comes back with the value because a conflict message that blames
    the wrong header is worse than one that names no header at all.
    """
    lowered = {k.lower(): v for k, v in (headers or {}).items()}
    for name in names:
        if lowered.get(name):
            return lowered[name], name
    return "", ""


def _normalize_platform(value):
    """`iOS`, `IOS`, `ios` all mean the same family; anything unknown is None."""
    v = (value or "").strip().lower()
    if v.startswith("ios") or v in ("iphone", "ipad"):
        return "ios"
    if v.startswith("android"):
        return "android"
    if v.startswith("win"):
        return "windows"
    if v in ("macos", "mac", "darwin"):
        return "macos"
    return None


def parse_user_agent(ua):
    """What a User-Agent claims: app, version, OS family, OS version.

    Returns a dict with `app`, `version`, `os`, `os_family`, `os_version`.
    Absent information is empty rather than guessed.
    """
    out = {"app": "", "version": "", "os": "", "os_family": None, "os_version": ""}
    if not ua:
        return out
    match = _UA_APP.match(ua)
    if match:
        out["app"] = match.group("name")
        out["version"] = match.group("version").strip()
    for pattern, os_name in _OS_PATTERNS:
        found = pattern.search(ua)
        if found:
            out["os"] = os_name
            out["os_family"] = _normalize_platform(os_name)
            out["os_version"] = found.group(1).replace("_", ".")
            break
    return out


@dataclass(frozen=True)
class Conflict:
    """One disagreement between two independently observed fields."""

    fields: tuple
    reason: str

    def __str__(self):
        return f"{' vs '.join(self.fields)}: {self.reason}"


@dataclass(frozen=True)
class Persona:
    """The identity a capture claims, and how it was established.

    `inferred` holds the names of fields whose value was *read out of* another
    header rather than observed in its own right. Those never raise a conflict:
    two readings of the same header can't disagree with each other.

    `sources` maps a field name to the header it was read from, so a conflict
    can name the header the app actually sent.
    """

    user_agent: str = ""
    device_id: str = ""
    app_version: str = ""
    platform: str = ""
    locale: str = ""
    device_model: str = ""
    os_version: str = ""
    inferred: frozenset = field(default_factory=frozenset)
    sources: dict = field(default_factory=dict)

    @classmethod
    def from_headers(cls, headers):
        """Build a persona from captured headers.

        Observed values win outright. Where a header is missing but the
        User-Agent answers the question, the value is taken and marked
        inferred. Where nothing answers it, the field stays empty — a device id
        is never synthesised, because a made-up one is worse than none.
        """
        headers = headers or {}
        ua, ua_name = _observed(headers, ("user-agent",))
        parsed = parse_user_agent(ua)
        inferred, sources = set(), {}

        def take(names, field_name):
            """First observed header among `names`, remembering which one."""
            value, name = _observed(headers, names)
            if value:
                sources[field_name] = name
            return value

        version = take(_VERSION_HEADERS, "app_version")
        if not version and parsed["version"]:
            version, inferred = parsed["version"], inferred | {"app_version"}

        platform = _normalize_platform(take(_PLATFORM_HEADERS, "platform"))
        if not platform and parsed["os_family"]:
            platform, inferred = parsed["os_family"], inferred | {"platform"}

        os_version = take(_OS_VERSION_HEADERS, "os_version")
        if not os_version and parsed["os_version"]:
            os_version, inferred = parsed["os_version"], inferred | {"os_version"}

        device_id = take(_DEVICE_ID_HEADERS, "device_id")
        device_model = take(_DEVICE_MODEL_HEADERS, "device_model")
        locale = take(("accept-language",), "locale")
        if ua:
            sources["user_agent"] = ua_name
        return cls(
            user_agent=ua,
            device_id=device_id,
            app_version=version,
            platform=platform or "",
            locale=locale,
            device_model=device_model,
            os_version=os_version,
            inferred=frozenset(inferred),
            sources=sources,
        )

    # -- coherence -----------------------------------------------------------
    def validate(self):
        """Raise `PersonaConflict` if two observed fields contradict.

        Returns self, so it can be chained onto construction.
        """
        conflicts = list(self._conflicts())
        if conflicts:
            raise PersonaConflict(
                "these captured headers describe different clients: "
                + "; ".join(str(c) for c in conflicts),
                conflicts=conflicts,
            )
        return self

    def _conflicts(self):
        """Yield one `Conflict` per pair of headers that disagree.

        Only independently observed values are compared: a field marked
        inferred came out of the very header it would be checked against, so
        comparing them could only ever agree.
        """
        parsed = parse_user_agent(self.user_agent)
        ua_version = "" if self._is_inferred("app_version") else parsed["version"]
        ua_family = None if self._is_inferred("platform") else parsed["os_family"]

        # App version: the User-Agent and a dedicated header must agree.
        if ua_version and self.app_version and self.app_version != ua_version:
            yield Conflict(
                ("user-agent", self._source("app_version")),
                f"user-agent says {parsed['app']} {ua_version}, but "
                f"{self._source('app_version')} says {self.app_version}",
            )

        # Platform: same check, at the family level.
        declared = _normalize_platform(self.platform)
        if ua_family and declared and declared != ua_family:
            yield Conflict(
                ("user-agent", self._source("platform")),
                f"user-agent says {ua_family}, but "
                f"{self._source('platform')} says {declared}",
            )

        # A device model names a family of its own; it has to match the UA's.
        # Read straight off the UA rather than through `ua_family`: the model
        # came from its own header, so this is two independent observations
        # even when the platform field itself was inferred from the UA.
        claimed = parsed["os_family"]
        if claimed and self.device_model:
            for pattern, family in _DEVICE_FAMILY:
                if pattern.search(self.device_model):
                    if family != claimed:
                        yield Conflict(
                            ("user-agent", self._source("device_model")),
                            f"user-agent says {claimed}, but "
                            f"{self._source('device_model')} "
                            f"{self.device_model!r} is {family}",
                        )
                    break

    def _is_inferred(self, name):
        return name in self.inferred

    def _source(self, name):
        """The header a value came from; the field name when hand-built."""
        return self.sources.get(name, name)

    # -- reporting -----------------------------------------------------------
    def describe(self):
        """A one-line-per-field summary for `mimic profile load`."""
        lines = []
        for name in ("user_agent", "device_id", "app_version", "platform",
                     "device_model", "os_version", "locale"):
            value = getattr(self, name)
            if not value:
                lines.append(f"  {name:13s} (absent)")
                continue
            mark = " (inferred)" if name in self.inferred else ""
            lines.append(f"  {name:13s} {value}{mark}")
        return "\n".join(lines)

    def to_dict(self):
        return {
            "user_agent": self.user_agent,
            "device_id": self.device_id,
            "app_version": self.app_version,
            "platform": self.platform,
            "locale": self.locale,
            "device_model": self.device_model,
            "os_version": self.os_version,
            "inferred": sorted(self.inferred),
            "sources": dict(self.sources),
        }

    @classmethod
    def from_dict(cls, data):
        data = data or {}
        return cls(
            user_agent=data.get("user_agent", ""),
            device_id=data.get("device_id", ""),
            app_version=data.get("app_version", ""),
            platform=data.get("platform", ""),
            locale=data.get("locale", ""),
            device_model=data.get("device_model", ""),
            os_version=data.get("os_version", ""),
            inferred=frozenset(data.get("inferred") or ()),
            sources=dict(data.get("sources") or {}),
        )


@dataclass(frozen=True)
class Profile:
    """A persona plus the request material that belongs with it.

    Where to send the replay, what headers to send, and which client those
    headers claim to be. The vault stores `to_bytes()` and hands them back
    untouched; `Session.from_profile` is the only thing that reads the shape.
    """

    name: str = ""
    base_url: str = ""
    host: str = ""
    headers: tuple = ()  # ((name, value), …), sorted, so bytes are stable
    persona: Persona = field(default_factory=Persona)

    @classmethod
    def from_capture(cls, name, headers, base_url="", host=""):
        """Assemble a profile from captured headers.

        Validated on the way out, so a contradictory capture can't be saved in
        the first place.
        """
        headers = dict(headers or {})
        return cls(
            name=name,
            base_url=base_url or "",
            host=host or "",
            headers=tuple(sorted(headers.items())),
            persona=Persona.from_headers(headers),
        ).validate()

    def validate(self):
        """Raise `PersonaConflict` if this doesn't describe a single client.

        Both halves are checked: the persona as stored, and a fresh reading of
        the headers actually being sent. They come from the same capture, so
        agreeing is the normal case — but a profile is a document that outlives
        the code that wrote it, and one whose two halves name different clients
        is exactly what this is here to catch on the way back in.
        """
        self.persona.validate()
        if self.headers:
            Persona.from_headers(self.as_headers()).validate()
        return self

    def as_headers(self):
        """The header mapping a Session replays."""
        return dict(self.headers)

    def to_dict(self):
        return {
            "version": _PROFILE_VERSION,
            "name": self.name,
            "base_url": self.base_url,
            "host": self.host,
            "headers": self.as_headers(),
            "persona": self.persona.to_dict(),
        }

    def to_bytes(self):
        """Canonical JSON, so the same profile is the same bytes every time.

        Sorted keys and no incidental whitespace: byte-identical round trips are
        what make a stored profile verifiable rather than merely plausible.
        """
        return json.dumps(self.to_dict(), sort_keys=True,
                          separators=(",", ":")).encode()

    @classmethod
    def from_bytes(cls, data):
        """Rebuild from `to_bytes()` output. Does not validate — call `validate`
        when the document came from somewhere you didn't just write."""
        doc = json.loads(data.decode("utf-8") if isinstance(data, (bytes, bytearray))
                         else data)
        if doc.get("version") != _PROFILE_VERSION:
            raise MimicError(
                f"profile {doc.get('name')!r} was saved in format "
                f"{doc.get('version')!r}, which this version of mimic can't read",
                expected=_PROFILE_VERSION, got=doc.get("version"),
            )
        return cls(
            name=doc.get("name", ""),
            base_url=doc.get("base_url", ""),
            host=doc.get("host", ""),
            headers=tuple(sorted((doc.get("headers") or {}).items())),
            persona=Persona.from_dict(doc.get("persona")),
        )