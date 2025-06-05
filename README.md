# unifi-controller-api

A Python client library for interacting with Ubiquiti UniFi Network Controllers.

[![PyPI - Downloads](https://img.shields.io/pypi/dw/unifi-controller-api)](https://pypi.org/project/unifi-controller-api/)
[![PyPI - Version](https://img.shields.io/pypi/v/unifi-controller-api)](https://pypi.org/project/unifi-controller-api/)

> **Warning:** This package is under active development and is subject to breaking changes, incomplete or incorrect documentation, etc.

## Core Features

*   **Structured Data Models:** Opitionally parses API responses into typed Python objects (e.g., `UnifiDevice`, `UnifiSite`, `UnifiClient`, `LLDPEntry`, `UnifiWlanConf`).
*   **Automatic Model Mapping:** Translates model codes (e.g., `U7PG2`) to friendly names ("UniFi® AC Pro AP") via the `model_name` attribute.
*   **Convenience Methods:** Includes helpers for data export (`export_csv`, `export_json`).
*   **Minimal Dependencies:** Requires only `requests`.
*   **Python >= 3.9**

---

## Installation

```bash
pip install unifi-controller-api
```

---

## Quick Start

```python
from unifi_controller_api import UnifiController

# 1. Initialize & Authenticate
controller = UnifiController(
    controller_url="https://<CONTROLLER_IP_OR_HOSTNAME>", # Use :8443 for UniFi OS, :443 for legacy
    username="<LOCAL_ADMIN_USER>",
    password="<PASSWORD>",
    is_udm_pro=True, # Set True for UniFi OS devices (UDM, Cloud Key Gen2+), False for legacy software/hardware controllers
    verify_ssl=False, # Or path to your CA bundle, set True if using a valid public certificate
    auto_model_mapping=True, # Optional: Attempt to map device model codes to friendly names
    model_db_path=None, # Optional: Path to a custom model database file
    auth_retry_enabled=True, # Optional: Enable automatic retries on authentication failure
    auth_retry_count=3, # Optional: Number of authentication retries
    auth_retry_delay=5 # Optional: Delay in seconds between authentication retries
)

# 2. Fetch Data (Example: Devices for the 'default' site)
site_name = "default" # Use the internal site name
try:
    devices = controller.get_unifi_site_device(site_name=site_name, detailed=True)

    # 3. Use the Typed Data
    for device in devices:
        print(f"- {device.name} ({device.model_name}): {device.ip} / {device.mac}")
        if device.lldp_info:
            print(f"  LLDP: {len(device.lldp_info)} neighbors")

except Exception as e:
    print(f"Error fetching devices for site '{site_name}': {e}")

# Other available methods:
# sites = controller.get_unifi_site()
# clients = controller.get_clients(site_name)
# wlans = controller.get_wlan_conf(site_name)
# alarms = controller.get_alarms(site_name)
# events = controller.get_events(site_name)
# rogue_aps = controller.get_rogue_aps(site_name)
# networks = controller.get_network_conf(site_name)
# report = controller.devices_report(site_names=['site1', 'site2'])

# Exporting data:
# from unifi_controller_api.export import export_csv, export_json
# if devices:
#     export_csv(devices, "devices.csv")
#     export_json(devices, "devices.json")
```

---

## Connectivity Notes

*   Requires direct network access to the controller.
*   The `controller_url` should include the scheme (https) and port (e.g., `https://192.168.1.1:443` for UniFi OS, `https://unifi.example.com:8443` for older software controllers).
*   Requires direct network access to the controller.
*   Uses **HTTPS port 443** by default for UniFi OS devices (UDM, Cloud Key Gen2+).
*   Uses **HTTPS port 8443** by default for legacy controllers (Software, Cloud Key Gen1).
*   Requires a **local controller account**, not a UniFi Cloud/SSO account.
*   Set `is_udm_pro=True` when connecting to UniFi OS based controllers (like UDM Pro, UDM SE, Cloud Key Gen2 Plus running UniFi OS). Set to `False` for software-based controllers or older Cloud Keys not running UniFi OS.
*   For `verify_ssl`: set to `False` for self-signed certificates (common in local deployments), `True` if your controller has a valid, publicly trusted SSL certificate, or provide a path to your CA bundle file.
*   `auto_model_mapping` (default `True`) automatically translates device model codes (e.g., "U7PG2") to human-readable names (e.g., "UniFi AC Pro AP").
*   `auth_retry_enabled` (default `True`) allows the client to automatically retry authentication on failure, useful for temporary network issues.

---

## Data Models

The library automatically maps JSON API responses to Python data classes located in `unifi_controller_api.models`. Key models include:

*   `UnifiSite`: Represents a controller site.
*   `UnifiDevice`: Represents a network device (AP, Switch, Gateway).
*   `LLDPEntry`: Holds LLDP neighbor details (nested within `UnifiDevice`).
*   `UnifiClient`: Represents a connected client (wired or wireless).
*   `UnifiWlanConf`: Represents a Wireless LAN configuration.
*   `UnifiNetworkConf`: Represents a Network configuration.
*   `UnifiAlarm`: Represents a controller alarm.
*   `UnifiEvent`: Represents a controller event.
*   `UnifiRogueAp`: Represents a detected rogue access point.

Use standard object attribute access (e.g., `device.ip`, `site.desc`) to work with the data.

---

## Logging

Uses standard Python `logging`. Configure the `unifi_controller_api` logger:

```python
import logging
logging.getLogger("unifi_controller_api").setLevel(logging.DEBUG)
# Ensure you have a handler configured (e.g., via logging.basicConfig)
logging.basicConfig(level=logging.INFO) # Example: Show INFO level and above
```

---

## Disclaimer

This is an unofficial library using APIs that may change without notice. Not affiliated with Ubiquiti Inc. Use at your own risk.
