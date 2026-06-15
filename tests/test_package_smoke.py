import importlib.metadata
import json
from importlib import resources

import unifi_controller_api as api
from unifi_controller_api.models import (
    UnifiDevice,
    UnifiFirewallRule,
    UnifiHealth,
    UnifiPortConf,
    UnifiSite,
)


def test_public_imports_are_available():
    assert api.UnifiController is not None
    assert api.UnifiSite is UnifiSite
    assert UnifiDevice is not None
    assert UnifiHealth is not None
    assert UnifiPortConf is not None
    assert api.UnifiFirewallRule is UnifiFirewallRule


def test_packaged_device_model_database_is_valid_json():
    model_db = resources.files('unifi_controller_api').joinpath('device-models.json')
    with model_db.open(encoding='utf-8') as handle:
        data = json.load(handle)

    assert isinstance(data, dict)
    assert data
    assert any(isinstance(entry, dict) for entry in data.values())


def test_distribution_metadata_is_accessible():
    assert importlib.metadata.version('unifi-controller-api')
