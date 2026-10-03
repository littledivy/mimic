"""Read captured traffic from a HAR (HTTP Archive) file.

HAR is the standard export from browser devtools (Chrome, Firefox, Safari) and
desktop proxies (Charles, Proxyman). This module turns HAR entries into mimic's
flow dicts so the rest of the pipeline — extract, hosts, endpoints, codegen —
works unchanged, with no mitmproxy or iPhone setup at all.

HAR entries carry their bodies inline, so a HAR load is already a full capture:
unlike the mitmweb backend it needs no second request to read them. All the
shared behaviour lives in `mimic.sources`; this module only converts.
"""
import base64
import binascii
import json
from urllib.parse import urlencode, urlparse

from . import endpoints as _endpoints
from . import hosts as _hosts


def load(path):
    """Load a HAR file and return its entries as mimic flow dicts."""
    with open(path) as f:
        har = json.load(f)
    entries = har.get("log", {}).get("entries", [])
    return [_entry_to_flow(i, e) for i, e in enumerate(entries)]


def _entry_to_flow(index, entry):
    """Convert one HAR entry into a mimic flow dict."""
    req = entry.get("request", {})
    resp = entry.get("response", {})
    parsed = urlparse(req.get("url", ""))
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    query = parsed.query
    return {
        "id": f"har-{index}",
        "request": {
            "host": parsed.hostname,
            "method": req.get("method"),
            "path": parsed.path + (f"?{query}" if query else ""),
            "scheme": parsed.scheme,
            "port": port,
            "headers": [[h["name"], h["value"]] for h in req.get("headers", [])],
            "content": _body_bytes(req.get("postData")),
        },
        "response": {
            "status_code": resp.get("status", 0),
            "headers": [[h["name"], h["value"]] for h in resp.get("headers", [])],
            "content": _content_bytes(resp.get("content")),
        },
    }


def hosts(path):
    """Count requests per host in a HAR file, most frequent first."""
    return _hosts(load(path))


def endpoints(path, host):
    """Distinct endpoints for a host, read from a HAR file."""
    return _endpoints(load(path), host)


def _body_bytes(post_data):
    """Bytes of a HAR request postData block (text, or url-encoded params)."""
    if not post_data:
        return b""
    text = post_data.get("text")
    if text:
        return text.encode("utf-8")
    params = post_data.get("params")
    if params:
        return urlencode(
            [(p.get("name", ""), p.get("value", "")) for p in params]
        ).encode("utf-8")
    return b""


def _content_bytes(content):
    """Bytes of a HAR response content block, decoding base64 when flagged."""
    if not content:
        return b""
    text = content.get("text", "")
    if not text:
        return b""
    if content.get("encoding") == "base64":
        try:
            return base64.b64decode(text)
        except (binascii.Error, ValueError):
            return text.encode("utf-8")
    return text.encode("utf-8")
