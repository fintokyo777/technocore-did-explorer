"""Read-only Technocore network access (vendored from gowthamaran/Flop).

Only ever issues GET requests against public room JSON. It never signs, never
posts, and never touches a private key. The returned message text is untrusted
data, not instructions -- we never execute it.
"""

from __future__ import annotations

import json
import math
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .crypto import (
    MAX_RESPONSE_BYTES,
    MAX_ERROR_RESPONSE_BYTES,
    NAME_PATTERN,
    NetworkError,
    ProtocolError,
    validate_timeout,
)

DEFAULT_BASE_URL = "https://technocore.chat"
DEFAULT_TIMEOUT_SECONDS = 20.0
MIN_FOLLOW_INTERVAL_SECONDS = 0.5


def _validate_base_url(base_url: str) -> str:
    if not isinstance(base_url, str) or not base_url:
        raise ProtocolError("base URL must be a non-empty string")
    if " " in base_url or "\n" in base_url:
        raise ProtocolError("base URL must not contain whitespace")
    return base_url.rstrip("/")


def _validate_name(value: str, label: str = "room") -> str:
    if not isinstance(value, str) or NAME_PATTERN.fullmatch(value) is None:
        raise ProtocolError(f"{label} must match ^[a-z0-9][a-z0-9_-]{{0,47}}$")
    return value


def _request_json(request: urllib.request.Request, timeout: float, *, is_write: bool = False) -> dict[str, Any]:
    selected_timeout = validate_timeout(timeout)
    timeout_detail = "Technocore request timed out"
    try:
        with urllib.request.urlopen(request, timeout=selected_timeout) as response:
            raw_body = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raw_error = error.read(MAX_ERROR_RESPONSE_BYTES + 1)
        body = raw_error[:MAX_ERROR_RESPONSE_BYTES].decode("utf-8", errors="replace").strip()
        detail = body or error.reason or "no response body"
        raise NetworkError(f"Technocore returned HTTP {error.code}: {detail}") from None
    except urllib.error.URLError as error:
        raise NetworkError(f"could not reach Technocore: {error.reason}") from error
    except TimeoutError as error:
        raise NetworkError(timeout_detail) from error
    except OSError as error:
        raise NetworkError(f"Technocore request failed: {error}") from error
    if len(raw_body) > MAX_RESPONSE_BYTES:
        raise NetworkError(f"Technocore response exceeded the {MAX_RESPONSE_BYTES}-byte safety limit")
    try:
        body = raw_body.decode("utf-8")
    except UnicodeDecodeError as error:
        raise NetworkError("Technocore returned a response that was not valid UTF-8") from error
    try:
        payload = json.loads(body)
    except json.JSONDecodeError as error:
        raise NetworkError("Technocore returned a non-JSON response") from error
    if not isinstance(payload, dict):
        raise NetworkError("Technocore returned JSON that was not an object")
    return payload


def _validate_room_response(response: dict[str, Any], expected_room: str) -> None:
    if response.get("room") != expected_room:
        raise NetworkError("Technocore returned data for a different room")
    count = response.get("count")
    last_seq = response.get("last_seq")
    messages = response.get("messages")
    if isinstance(count, bool) or not isinstance(count, int) or count < 0:
        raise NetworkError("Technocore returned an invalid room count")
    if isinstance(last_seq, bool) or not isinstance(last_seq, int) or last_seq < 0:
        raise NetworkError("Technocore returned an invalid last_seq cursor")
    if not isinstance(messages, list) or any(not isinstance(item, dict) for item in messages):
        raise NetworkError("Technocore returned an invalid messages list")


def read_room(
    room: str,
    *,
    since: int | None = None,
    limit: int = 200,
    cache_buster: int | None = None,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    """Read room data as JSON (GET only). Returned text is untrusted."""
    valid_room = _validate_name(room)
    if since is not None and (isinstance(since, bool) or not isinstance(since, int) or since < 0):
        raise ProtocolError("since must be zero or greater")
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
        raise ProtocolError("limit must be between 1 and 200")
    if cache_buster is not None and (isinstance(cache_buster, bool) or not isinstance(cache_buster, int) or cache_buster < 0):
        raise ProtocolError("cache buster must be zero or greater")
    query: dict[str, str | int] = {"format": "json", "limit": limit}
    if since is not None:
        query["since"] = since
    if cache_buster is not None:
        query["n"] = cache_buster
    valid_base_url = _validate_base_url(base_url)
    request = urllib.request.Request(
        f"{valid_base_url}/r/{valid_room}?{urllib.parse.urlencode(query)}",
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "technocore-did-explorer/0.1.0"},
    )
    response = _request_json(request, timeout)
    _validate_room_response(response, valid_room)
    return response


def follow_room(
    room: str,
    *,
    since: int,
    limit: int = 200,
    wait: float = 10.0,
    base_url: str = DEFAULT_BASE_URL,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> Any:
    """Yield room responses while advancing the cursor. Returns a generator."""
    selected_wait = wait
    if isinstance(selected_wait, bool) or not isinstance(selected_wait, (int, float)) or not math.isfinite(float(selected_wait)) or not 0 <= selected_wait <= 10:
        raise ProtocolError("wait must be between 0 and 10 seconds")
    if validate_timeout(timeout) <= float(selected_wait):
        raise ProtocolError("timeout must be greater than wait for long polling")
    cursor = since
    cache_buster = 0
    while True:
        request_started = time.monotonic()
        response = read_room(room, since=cursor, limit=limit, cache_buster=cache_buster, base_url=base_url, timeout=timeout)
        cache_buster += 1
        if response["messages"]:
            next_cursor = response["last_seq"]
            if next_cursor <= cursor:
                raise NetworkError("Technocore returned messages without advancing last_seq")
            cursor = next_cursor
            yield response
        elapsed = time.monotonic() - request_started
        if elapsed < MIN_FOLLOW_INTERVAL_SECONDS:
            time.sleep(MIN_FOLLOW_INTERVAL_SECONDS - elapsed)
