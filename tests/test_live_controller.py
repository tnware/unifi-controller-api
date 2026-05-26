import os
from typing import TypedDict

import pytest

from unifi_controller_api import UnifiController


class LiveControllerConfig(TypedDict):
    controller_url: str
    username: str
    password: str
    is_udm_pro: bool
    verify_ssl: bool
    request_timeout: float


REQUIRED_ENV_VARS = (
    "UNIFI_CONTROLLER_URL",
    "UNIFI_USERNAME",
    "UNIFI_PASSWORD",
)


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _require_live_controller_config() -> LiveControllerConfig:
    missing = [name for name in REQUIRED_ENV_VARS if not os.environ.get(name)]
    if missing:
        pytest.skip(
            "live UniFi controller config not provided; missing "
            + ", ".join(missing)
        )

    return {
        "controller_url": os.environ["UNIFI_CONTROLLER_URL"],
        "username": os.environ["UNIFI_USERNAME"],
        "password": os.environ["UNIFI_PASSWORD"],
        "is_udm_pro": _env_bool("UNIFI_IS_UDM_PRO", True),
        "verify_ssl": _env_bool("UNIFI_VERIFY_SSL", True),
        "request_timeout": float(os.environ.get("UNIFI_REQUEST_TIMEOUT", "15")),
    }


@pytest.mark.live
def test_live_controller_authenticates_and_lists_sites():
    """Read-only smoke test against a real UniFi controller when env vars are set."""
    controller = UnifiController(**_require_live_controller_config())

    sites = controller.get_unifi_site(include_health=False, raw=True)

    assert isinstance(sites, list)
    assert all(isinstance(site, dict) for site in sites)


@pytest.mark.live
def test_live_controller_can_fetch_devices_for_configured_site():
    """Optional read-only device smoke test for a configured site name."""
    site_name = os.environ.get("UNIFI_SITE_NAME")
    if not site_name:
        pytest.skip("UNIFI_SITE_NAME not provided")

    controller = UnifiController(**_require_live_controller_config())

    devices = controller.get_unifi_site_device(site_name=site_name, raw=True)

    assert isinstance(devices, list)
    assert all(isinstance(device, dict) for device in devices)
