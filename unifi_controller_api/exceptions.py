from __future__ import annotations

import json
from typing import Any, Optional


class UnifiControllerError(Exception):
    """Base exception for UnifiController errors."""

    pass


class UnifiAuthenticationError(UnifiControllerError):
    """Raised when authentication with the UniFi Controller fails."""

    pass


class UnifiAPIError(UnifiControllerError):
    """Raised when an API call to the UniFi Controller fails.

    The UniFi private API often returns useful structured JSON for failures
    (for example ``meta.msg`` and validation details).  Preserve those details
    so callers do not need to bypass the client to diagnose controller errors.
    """

    def __init__(
        self,
        message: str,
        *,
        method: Optional[str] = None,
        url: Optional[str] = None,
        status_code: Optional[int] = None,
        response_text: Optional[str] = None,
        response_json: Optional[Any] = None,
        response: Optional[Any] = None,
    ) -> None:
        self.method = method
        self.url = url
        self.status_code = status_code
        self.response_text = response_text
        self.response_json = response_json

        if response is not None:
            self.status_code = status_code if status_code is not None else getattr(
                response, "status_code", None
            )
            if self.response_text is None:
                self.response_text = getattr(response, "text", None)
            if self.response_json is None:
                try:
                    self.response_json = response.json()
                except (TypeError, ValueError, AttributeError):
                    self.response_json = None

        detail = self._extract_controller_message()
        parts = [message]
        context = self._format_context()
        if context:
            parts.append(context)
        if detail and detail not in message:
            parts.append(f"controller_message={detail}")
        elif self.response_text and self.response_json is None:
            text = self.response_text.strip()
            if text and text not in message:
                parts.append(f"response_text={text[:500]}")

        super().__init__("; ".join(parts))

    def _format_context(self) -> str:
        values = []
        if self.method:
            values.append(f"method={self.method.upper()}")
        if self.url:
            values.append(f"url={self.url}")
        if self.status_code is not None:
            values.append(f"status_code={self.status_code}")
        return ", ".join(values)

    def _extract_controller_message(self) -> Optional[str]:
        if not isinstance(self.response_json, dict):
            return None

        meta = self.response_json.get("meta")
        if isinstance(meta, dict):
            msg = meta.get("msg")
            if msg:
                return str(msg)

        # Some UniFi validation failures put details in data entries. Keep this
        # compact so exception strings remain readable while structured data is
        # still available on ``response_json`` for callers that need more.
        data = self.response_json.get("data")
        if isinstance(data, list) and data:
            first = data[0]
            if isinstance(first, dict):
                msg = first.get("msg") or first.get("validationError")
                if msg:
                    if isinstance(msg, (dict, list)):
                        return json.dumps(msg, sort_keys=True)
                    return str(msg)
        return None


class UnifiDataError(UnifiControllerError):
    """Raised when there is an error parsing data from the UniFi Controller."""

    pass


class UnifiModelError(UnifiControllerError):
    """Raised when there is an error loading or processing device models."""

    pass
