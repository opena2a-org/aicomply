"""Adapter between aicomply and @nanomind/daemon (port of nanomind-adapter.ts).

POSTs to ``/v1/infer`` and maps the daemon's ``attackClass`` enum into aicomply's
three-valued verdict. Wire-format parity with the TS adapter is mandatory (same
endpoint, same intent string, same block contract). On ANY failure (network,
non-2xx, malformed JSON, schema violation, timeout) this returns ``None`` so the
dual-layer silently falls back to regex-only - the daemon is a defense-in-depth
layer and its absence must never fail a request.

Trust boundary (CHIEF-CSR): the daemon is a separate process and its responses
are an attack surface. ``evidence`` / ``remediation`` are NEVER copied into a
Violation value; only the structured ``attackClass`` enum becomes the type.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from dataclasses import dataclass

from ...types import ClassifierResult, Violation

NON_EMPTY_ATTACK_CLASSES = frozenset(
    {"exfiltration_pattern", "prompt_injection", "tool_misuse", "data_extraction"}
)

# Block threshold per AIM FGA Step 5: a non-empty attackClass only promotes to
# VIOLATION when confidence exceeds 0.8.
BLOCK_CONFIDENCE_THRESHOLD = 0.8

DEFAULT_NANOMIND_DAEMON_URL = "http://127.0.0.1:47200"
DEFAULT_NANOMIND_TIMEOUT_MS = 5000
NANOMIND_INFER_ENDPOINT = "/v1/infer"
NANOMIND_DEFAULT_INTENT = "INTENT_CHECK"


@dataclass
class NanoMindAdapterOptions:
    base_url: str | None = None
    timeout_ms: int | None = None
    agent_id: str | None = None


def _validate_infer_response(raw: object) -> dict | None:
    """Validate a parsed JSON body matches NanoMindInferResponse. None on any miss."""
    if not isinstance(raw, dict):
        return None
    if not isinstance(raw.get("intent"), str):
        return None
    if not isinstance(raw.get("result"), str):
        return None
    conf = raw.get("confidence")
    # bool is a subclass of int/float in Python - reject it explicitly.
    if not isinstance(conf, (int, float)) or isinstance(conf, bool):
        return None
    if conf < 0 or conf > 1:
        return None
    ac = raw.get("attackClass")
    if not isinstance(ac, str):
        return None
    if ac != "" and ac not in NON_EMPTY_ATTACK_CLASSES:
        return None
    lat = raw.get("latencyMs")
    if not isinstance(lat, (int, float)) or isinstance(lat, bool) or lat < 0:
        return None
    mv = raw.get("modelVersion")
    if not isinstance(mv, str) or len(mv) == 0:
        return None
    if "evidence" in raw and not isinstance(raw["evidence"], str):
        return None
    if "remediation" in raw and not isinstance(raw["remediation"], str):
        return None
    return raw


def map_infer_response_to_classifier_result(
    response: dict, content_length: int
) -> ClassifierResult:
    """Map a validated infer response into a ClassifierResult the dual-layer merges."""
    is_benign = response["attackClass"] == ""
    above_threshold = response["confidence"] > BLOCK_CONFIDENCE_THRESHOLD

    if is_benign or not above_threshold:
        return ClassifierResult(classifier="guard", verdict="CLEAN", violations=[])

    violation = Violation(
        type=response["attackClass"],
        value="***GUARD***",
        start=0,
        end=content_length,
        confidence=response["confidence"],
        classifier="guard",
    )
    return ClassifierResult(classifier="guard", verdict="VIOLATION", violations=[violation])


def _resolve_base_url(options: NanoMindAdapterOptions) -> str:
    return (
        options.base_url
        or os.environ.get("MOCK_NANOMIND_URL")
        or DEFAULT_NANOMIND_DAEMON_URL
    )


def classify_with_nanomind_daemon(
    content: str, options: NanoMindAdapterOptions | None = None
) -> ClassifierResult | None:
    """One classification call against the daemon. None on any failure."""
    opts = options or NanoMindAdapterOptions()
    base_url = _resolve_base_url(opts)
    timeout_ms = opts.timeout_ms or DEFAULT_NANOMIND_TIMEOUT_MS
    url = base_url.rstrip("/") + NANOMIND_INFER_ENDPOINT

    # Skip the daemon for empty/whitespace input (the daemon 400s on pad-only
    # token sequences; calling out is wasted work).
    if len(content.strip()) == 0:
        return None

    body: dict = {"intent": NANOMIND_DEFAULT_INTENT, "input": content}
    if opts.agent_id is not None:
        body["context"] = {"agentId": opts.agent_id}

    req = urllib.request.Request(
        url,
        data=json.dumps(body).encode("utf-8"),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_ms / 1000) as res:
            if not (200 <= res.status < 300):
                return None
            try:
                parsed = json.loads(res.read().decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                return None
    except (urllib.error.URLError, OSError, TimeoutError):
        # Network failure, non-2xx (HTTPError), connection refused, timeout.
        return None

    validated = _validate_infer_response(parsed)
    if validated is None:
        return None
    return map_infer_response_to_classifier_result(validated, len(content))


def is_nanomind_daemon_available(
    options: NanoMindAdapterOptions | None = None,
) -> bool:
    """Liveness probe against /health. True only on a 2xx within the timeout."""
    opts = options or NanoMindAdapterOptions()
    base_url = _resolve_base_url(opts)
    timeout_ms = min(opts.timeout_ms or 200, DEFAULT_NANOMIND_TIMEOUT_MS)
    url = base_url.rstrip("/") + "/health"
    try:
        with urllib.request.urlopen(url, timeout=timeout_ms / 1000) as res:
            return 200 <= res.status < 300
    except (urllib.error.URLError, OSError, TimeoutError):
        return False
