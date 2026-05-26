from typing import Any, cast

import pytest

from unifi_controller_api import UnifiController
from unifi_controller_api.exceptions import UnifiAPIError, UnifiDataError


class FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


def process(payload):
    controller = UnifiController.__new__(UnifiController)
    return controller._process_api_response(cast(Any, FakeResponse(payload)), "/api/test")


def test_process_api_response_returns_data_items():
    assert process({"meta": {"rc": "ok"}, "data": [{"name": "default"}]}) == [
        {"name": "default"}
    ]


def test_process_api_response_rejects_missing_data_key():
    with pytest.raises(UnifiDataError, match="Unexpected API response format"):
        process({"meta": {"rc": "ok"}})


def test_process_api_response_raises_api_error_for_unifi_error_payload():
    with pytest.raises(UnifiAPIError, match="api.err.Invalid"):
        process({"meta": {"rc": "error", "msg": "api.err.Invalid"}, "data": []})
