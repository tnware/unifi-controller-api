# unifi-controller-api

A Python client library for interacting with Ubiquiti UniFi Network Controllers.

![PyPI - Downloads](https://img.shields.io/pypi/dw/unifi-controller-api)
![PyPI - Version](https://img.shields.io/pypi/v/unifi-controller-api)

> **Warning:** This package is under active development and is subject to breaking changes, incomplete or incorrect documentation, etc.




## Core Features

*   **Read-Only Access:** Designed for insights and reporting, so no changes can or will be made.
*   **Structured Data Models:** Parses API responses into typed Python objects (e.g., `UnifiDevice`, `UnifiSite`, `UnifiClient`, `LLDPEntry`, `UnifiWlanConf`).
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
    controller_url="https://<CONTROLLER_IP_OR_HOSTNAME>", # Use :8443 for dedicated controller
    username="<LOCAL_ADMIN_USER>",
    password="<PASSWORD>",
    is_udm_pro=True, # Set True for UniFi OS devices, False for legacy
    verify_ssl=False # Or path to CA bundle
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
*   Uses **HTTPS port 443** for UniFi OS devices (UDM, Cloud Key 2.x+, etc.).
*   Uses **HTTPS port 8443** for legacy controllers (Software, Cloud Key Gen1/Gen2 pre-2.x).
*   Requires a **local controller account**, not a UniFi Cloud/SSO account.
*   Set `is_udm_pro=True` for UniFi OS, `False` for dedicated controller.
*   Use `verify_ssl=False` or provide a CA bundle path for self-signed certificates.

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
