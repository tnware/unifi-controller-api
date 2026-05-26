from typing import Optional

from unifi_controller_api import UnifiController


class FakeResponse:
    status_code = 200

    def __init__(self, payload=None):
        self._payload = payload or {"meta": {"rc": "ok"}}

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class RecordingSession:
    def __init__(self):
        self.post_calls = []
        self.get_calls = []
        self.request_calls = []
        self.cookies = {}

    def post(self, url, **kwargs):
        self.post_calls.append((url, kwargs))
        return FakeResponse()

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        return FakeResponse({"meta": {"rc": "ok"}, "data": []})

    def request(self, method, url, **kwargs):
        self.request_calls.append((method, url, kwargs))
        return FakeResponse()


def make_controller(request_timeout: Optional[float] = None):
    controller = UnifiController.__new__(UnifiController)
    controller.controller_url = "https://controller.example"
    controller.original_controller_url = "https://controller.example"
    controller.is_udm_pro = False
    controller.session = RecordingSession()
    controller.verify_ssl = True
    controller.auth_retry_enabled = False
    controller.auth_retry_count = 1
    controller.auth_retry_delay = 0.1
    controller.request_timeout = request_timeout
    return controller


def test_constructor_accepts_request_timeout_and_uses_it_for_authentication(monkeypatch):
    session = RecordingSession()
    monkeypatch.setattr("unifi_controller_api.api_client.requests.Session", lambda: session)

    UnifiController(
        "https://controller.example",
        "admin",
        "secret",
        request_timeout=12.5,
    )

    assert session.post_calls[0][1]["timeout"] == 12.5


def test_get_requests_use_configured_request_timeout():
    controller = make_controller(request_timeout=7.0)

    controller.invoke_get_rest_api_call("https://controller.example/api/self/sites")

    assert controller.session.get_calls[0][1]["timeout"] == 7.0


def test_mutating_requests_use_configured_request_timeout_by_default():
    controller = make_controller(request_timeout=3.0)

    controller._invoke_api_call("POST", "https://controller.example/api/s/default/cmd", json_payload={})

    assert controller.session.request_calls[0][2]["timeout"] == 3.0


def test_per_call_timeout_overrides_configured_request_timeout():
    controller = make_controller(request_timeout=3.0)

    controller._invoke_api_call(
        "POST",
        "https://controller.example/api/s/default/cmd",
        json_payload={},
        timeout=9.0,
    )

    assert controller.session.request_calls[0][2]["timeout"] == 9.0


def test_request_timeout_defaults_to_none_for_backward_compatibility(monkeypatch):
    session = RecordingSession()
    monkeypatch.setattr("unifi_controller_api.api_client.requests.Session", lambda: session)

    UnifiController("https://controller.example", "admin", "secret")

    assert session.post_calls[0][1]["timeout"] is None
