from unifi_controller_api import UnifiController, UnifiFirewallRule


class FakeResponse:
    status_code = 200
    text = ""

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload

    def raise_for_status(self):
        return None


class FirewallSession:
    cookies = {}

    def __init__(self):
        self.get_calls = []
        self.request_calls = []
        self.get_payload = {
            "meta": {"rc": "ok"},
            "data": [
                {
                    "_id": "rule-1",
                    "name": "Allow DNS",
                    "enabled": True,
                    "action": "accept",
                    "ruleset": "LAN_OUT",
                    "rule_index": 20000,
                    "protocol": "tcp_udp",
                    "dst_port": "53",
                    "undocumented_field": "preserved",
                }
            ],
        }

    def get(self, url, **kwargs):
        self.get_calls.append((url, kwargs))
        return FakeResponse(self.get_payload)

    def request(self, method, url, **kwargs):
        self.request_calls.append((method, url, kwargs))
        payload = kwargs.get("json") or {}
        return FakeResponse(
            {
                "meta": {"rc": "ok"},
                "data": [{"_id": "rule-2", **payload}],
            }
        )


def make_controller(session=None):
    controller = UnifiController.__new__(UnifiController)
    controller.controller_url = "https://controller.example/proxy/network"
    controller.original_controller_url = "https://controller.example"
    controller.is_udm_pro = False
    controller.session = session or FirewallSession()  # type: ignore[assignment]
    controller.verify_ssl = True
    controller.auth_retry_enabled = False
    controller.auth_retry_count = 1
    controller.auth_retry_delay = 0.1  # type: ignore[assignment]
    controller.request_timeout = None
    return controller


def test_get_firewall_rules_returns_raw_data_by_default():
    session = FirewallSession()
    controller = make_controller(session)

    rules = controller.get_unifi_site_firewallrule("default")

    assert isinstance(rules[0], dict)
    assert rules[0]["name"] == "Allow DNS"
    assert session.get_calls[0][0] == (
        "https://controller.example/proxy/network/api/s/default/rest/firewallrule"
    )


def test_get_firewall_rules_maps_typed_model_and_preserves_extra_fields():
    controller = make_controller(FirewallSession())

    rules = controller.get_unifi_site_firewallrule("default", raw=False)

    assert isinstance(rules[0], UnifiFirewallRule)
    assert rules[0].name == "Allow DNS"
    assert rules[0].dst_port == "53"
    assert rules[0]._extra_fields["undocumented_field"] == "preserved"


def test_get_firewall_rule_by_id_uses_rule_specific_endpoint():
    session = FirewallSession()
    controller = make_controller(session)

    controller.get_unifi_site_firewallrule("default", firewall_rule_id="rule-1")

    assert session.get_calls[0][0].endswith(
        "/api/s/default/rest/firewallrule/rule-1"
    )


def test_create_firewall_rule_posts_payload_and_maps_response():
    session = FirewallSession()
    controller = make_controller(session)

    rules = controller.create_unifi_site_firewallrule(
        "default",
        {"name": "Block SMTP", "action": "drop"},
        raw=False,
        protocol="tcp",
        dst_port="25",
    )

    method, url, kwargs = session.request_calls[0]
    assert method == "POST"
    assert url.endswith("/api/s/default/rest/firewallrule")
    assert kwargs["json"] == {
        "name": "Block SMTP",
        "action": "drop",
        "protocol": "tcp",
        "dst_port": "25",
    }
    assert isinstance(rules[0], UnifiFirewallRule)
    assert rules[0]._id == "rule-2"
    assert rules[0].dst_port == "25"


def test_update_firewall_rule_puts_payload_to_rule_endpoint():
    session = FirewallSession()
    controller = make_controller(session)

    controller.update_unifi_site_firewallrule(
        "default", "rule-1", {"enabled": False}
    )

    method, url, kwargs = session.request_calls[0]
    assert method == "PUT"
    assert url.endswith("/api/s/default/rest/firewallrule/rule-1")
    assert kwargs["json"] == {"enabled": False}


def test_delete_firewall_rule_uses_delete_method():
    session = FirewallSession()
    controller = make_controller(session)

    controller.delete_unifi_site_firewallrule("default", "rule-1")

    method, url, kwargs = session.request_calls[0]
    assert method == "DELETE"
    assert url.endswith("/api/s/default/rest/firewallrule/rule-1")
    assert "json" not in kwargs
