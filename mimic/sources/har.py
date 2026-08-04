"""Read captured traffic from a HAR (HTTP Archive) file.

HAR is the standard export from browser devtools (Chrome, Firefox, Safari) and
desktop proxies (Charles, Proxyman). This module turns HAR entries into mimic's
flow dicts so the rest of the pipeline (extract, hosts, endpoints, codegen)
works unchanged, with no mitmproxy or iPhone setup at all.
"""
import base64
import binascii
import json
from urllib.parse import urlencode, urlparse

from . import mitm


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
    request_body = _body_bytes(req.get("postData"))
    response_body = _content_bytes(resp.get("content"))
    request_headers = [[h["name"], h["value"]] for h in req.get("headers", [])]
    response_headers = [[h["name"], h["value"]] for h in resp.get("headers", [])]
    _add_content_type(request_headers, (req.get("postData") or {}).get("mimeType"))
    _add_content_type(response_headers, (resp.get("content") or {}).get("mimeType"))
    return {
        "id": f"har-{index}",
        "request": {
            "host": parsed.hostname,
            "method": req.get("method"),
            "path": parsed.path + (f"?{query}" if query else ""),
            "scheme": parsed.scheme,
            "port": port,
            "headers": request_headers,
            "contentLength": len(request_body),
        },
        "response": {
            "status_code": resp.get("status", 0),
            "headers": response_headers,
            "contentLength": len(response_body),
        },
    }


def hosts(path):
    """Count requests per host in a HAR file, most frequent first."""
    return mitm.hosts(load(path))


def endpoints(
    path,
    host,
    *,
    include_bodies=True,
    include_telemetry=False,
    max_samples=mitm.DEFAULT_MAX_SAMPLES_PER_ENDPOINT,
):
    """Normalize HAR entries through the same pipeline as live captures."""
    with open(path) as f:
        archive = json.load(f)
    flows = []
    bodies = {}
    for index, entry in enumerate(archive.get("log", {}).get("entries", [])):
        flow = _entry_to_flow(index, entry)
        flows.append(flow)
        bodies[(flow["id"], "request")] = _body_bytes(
            (entry.get("request") or {}).get("postData")
        )
        bodies[(flow["id"], "response")] = _content_bytes(
            (entry.get("response") or {}).get("content")
        )
    return mitm.endpoints(
        _Bodies(bodies),
        flows,
        host,
        include_bodies=include_bodies,
        include_telemetry=include_telemetry,
        max_samples=max_samples,
    )


class _Bodies:
    def __init__(self, bodies):
        self.bodies = bodies

    def body(self, flow_id, side):
        return self.bodies.get((flow_id, side), b"")


def _add_content_type(headers, mime_type):
    if mime_type and not any(name.lower() == "content-type" for name, _ in headers):
        headers.append(["Content-Type", mime_type])


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
