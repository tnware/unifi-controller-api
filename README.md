# UniFi Controller API

A Python client library for interacting with Ubiquiti UniFi Network Controllers.

## Features

- Authenticated access to UniFi Controller API endpoints
- Support for both legacy controllers and UniFi OS devices (UDM/Pro/SE)
- Data models for sites, devices, clients, events, alarms, and WLANs
- Device model mapping with friendly names
- Flexible export options for reporting

## Installation

```bash
pip install unifi-controller-api
# or
pip install -e .  # For development
```

## Quick Start

```python
from unifi_controller_api.api_client import UnifiController

# Connect to controller
controller = UnifiController(
    controller_url="https://unifi.local",
    username="admin",
    password="password",
    is_udm_pro=True  # Set to True for UDM Pro, Cloud Key Gen2, etc.
)

# Get all sites
sites = controller.get_unifi_site(include_health=True)

# Fetch devices for a site
devices = controller.get_unifi_site_device(site_name="default", detailed=True)

# Get clients connected to the network
clients = controller.get_unifi_site_client(site_name="default")

# Get WLAN configurations
wlans = controller.get_unifi_site_wlanconf(site_name="default")
```

## Acknowledgements

This library is not affiliated with or endorsed by Ubiquiti Inc.

Based on an undocumented API that is subject to change, no guarantee of success or stability.