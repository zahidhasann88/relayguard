"""A stand-in for the pooled httpx client.

The gateway streams upstream responses, so the double has to behave like
``AsyncClient.stream``: an async context manager yielding a status, an
``httpx.Headers`` view and an async byte iterator.
"""

from contextlib import contextmanager
from dataclasses import dataclass, field
from unittest.mock import patch

import httpx


class FakeUpstream:
    """Stands in for a streamed ``httpx.Response``."""

    def __init__(self, content=b"{}", status_code=200, headers=None, chunks=None):
        self.content = content
        self.status_code = status_code
        self.headers = httpx.Headers(headers or {})
        self.chunks = list(chunks) if chunks is not None else [content]
        self.chunks_read = 0

    async def aiter_bytes(self):
        for chunk in self.chunks:
            self.chunks_read += 1
            yield chunk


@dataclass
class SentRequest:
    method: str
    url: str
    headers: dict = field(default_factory=dict)
    content: bytes = b""


class _StreamContext:
    def __init__(self, response, error):
        self._response = response
        self._error = error

    async def __aenter__(self):
        if self._error is not None:
            raise self._error
        return self._response

    async def __aexit__(self, *exc_info):
        return False


class FakeHTTPClient:
    """Records what the gateway sent and replays a canned upstream response."""

    is_closed = False

    def __init__(self, response=None, error=None):
        self.response = response if response is not None else FakeUpstream()
        self.error = error
        self.calls: list[SentRequest] = []

    def stream(self, method, url, *, headers=None, content=None, timeout=None):
        self.calls.append(SentRequest(method, str(url), dict(headers or {}), content or b""))
        return _StreamContext(self.response, self.error)

    @property
    def last(self) -> SentRequest:
        return self.calls[-1]

    @property
    def called(self) -> bool:
        return bool(self.calls)


@contextmanager
def fake_upstream(response=None, error=None, **response_kwargs):
    """Patch the pooled client for the duration of the block."""
    if response is None and not error:
        response = FakeUpstream(**response_kwargs)
    elif response_kwargs:
        response = FakeUpstream(**response_kwargs)

    client = FakeHTTPClient(response=response, error=error)
    with patch("proxyapi.views.get_http_client", return_value=client):
        yield client
