import requests
import pytest

from unifi_controller_api import UnifiController
from unifi_controller_api.exceptions import UnifiAPIError


class ErrorResponse:
    status_code = 400
    text = '{"meta":{"rc":"error","msg":"api.err.InvalidValue"},"data":[]}'

    def json(self):
        return {"meta": {"rc": "error", "msg": "api.err.InvalidValue"}, "data": []}

    def raise_for_status(self):
        raise requests.HTTPError("400 Client Error", response=self)  # type: ignore[arg-type]


class NonJsonErrorResponse:
    status_code = 502
    text = "bad gateway"

    def json(self):
        raise ValueError("not json")

    def raise_for_status(self):
        raise requests.HTTPError("502 Server Error", response=self)  # type: ignore[arg-type]


class NoResponseSession:
    cookies = {}

    def request(self, method, url, **kwargs):
        raise requests.ConnectionError("connection failed")


class ErrorSession:
    cookies = {}

    def __init__(self, response):
        self.response = response

    def request(self, method, url, **kwargs):
        return self.response


def make_controller(session):
    controller = UnifiController.__new__(UnifiController)
    controller.controller_url = "https://controller.example"
    controller.original_controller_url = "https://controller.example"
    controller.is_udm_pro = False
    controller.session = session
    controller.verify_ssl = True
    controller.auth_retry_enabled = False
    controller.auth_retry_count = 1
    controller.auth_retry_delay = 0.1  # type: ignore[assignment]
    controller.request_timeout = None
    return controller


def test_unifi_api_error_preserves_json_response_details():
    controller = make_controller(ErrorSession(ErrorResponse()))

    with pytest.raises(UnifiAPIError) as excinfo:
        controller._invoke_api_call("POST", "https://controller.example/api/test", {})

    err = excinfo.value
    assert err.method == "POST"
    assert err.url == "https://controller.example/api/test"
    assert err.status_code == 400
    assert err.response_json is not None
    assert err.response_json["meta"]["msg"] == "api.err.InvalidValue"
    assert "api.err.InvalidValue" in str(err)


def test_unifi_api_error_preserves_non_json_response_text():
    controller = make_controller(ErrorSession(NonJsonErrorResponse()))

    with pytest.raises(UnifiAPIError) as excinfo:
        controller._invoke_api_call("PUT", "https://controller.example/api/test", {})

    err = excinfo.value
    assert err.method == "PUT"
    assert err.status_code == 502
    assert err.response_text == "bad gateway"
    assert err.response_json is None
    assert "bad gateway" in str(err)


def test_unifi_api_error_handles_request_failure_without_response():
    controller = make_controller(NoResponseSession())

    with pytest.raises(UnifiAPIError) as excinfo:
        controller._invoke_api_call("DELETE", "https://controller.example/api/test")

    err = excinfo.value
    assert err.method == "DELETE"
    assert err.url == "https://controller.example/api/test"
    assert err.status_code is None
    assert err.response_json is None
    assert "connection failed" in str(err)
