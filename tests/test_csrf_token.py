import logging

from unifi_controller_api import UnifiController


class FakeCookies:
    def __init__(self, token):
        self.token = token

    def list_domains(self):
        return ["controller.example"]

    def get(self, name, domain=None):
        if name == "TOKEN" and domain == "controller.example":
            return self.token
        return None


class FakeSession:
    def __init__(self, token):
        self.cookies = FakeCookies(token)


def make_controller_with_token(token):
    controller = UnifiController.__new__(UnifiController)
    controller.session = FakeSession(token)
    return controller


def test_invalid_jwt_structure_warning_does_not_log_token_value(caplog):
    token = "secret-invalid-token"
    controller = make_controller_with_token(token)

    with caplog.at_level(logging.WARNING, logger="unifi_controller_api.api_client"):
        assert controller._extract_csrf_token() is None

    assert "Invalid JWT structure found in TOKEN cookie" in caplog.text
    assert token not in caplog.text
