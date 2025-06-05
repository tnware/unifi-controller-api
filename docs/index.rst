=========================================
UniFi Controller API Documentation
=========================================

A Python library for interacting with the UniFi Controller API.

.. toctree::
   :maxdepth: 2
   :caption: User Guide:

   installation
   usage
   examples

.. toctree::
   :maxdepth: 2
   :caption: API Reference:

   api/overview
   api/client
   api/models
   api/utilities
   api/export

.. toctree::
   :maxdepth: 1
   :caption: Development:

   contributing
   changelog

About
=====

The UniFi Controller API library allows you to interact with Ubiquiti's UniFi Network Controller
software. It provides a Pythonic interface to query devices, clients, and network information
from your UniFi network.

Quick Start
==========

Installation:

.. code-block:: bash

    pip install unifi-controller-api

Basic usage:

.. code-block:: python

    from unifi_controller_api import UnifiController

    # Initialize & Authenticate
    controller = UnifiController(
        controller_url="https://<CONTROLLER_IP_OR_HOSTNAME_OR_URL>", # e.g., "https://192.168.1.1:443", "https://unifi.example.com:8443"
        username="<LOCAL_ADMIN_USER>",
        password="<PASSWORD>",
        is_udm_pro=True, # Set True for UniFi OS devices (UDM, Cloud Key Gen2+), False for legacy
        verify_ssl=False, # Set to False for self-signed certs, True for valid public certs, or path to CA bundle
        auto_model_mapping=True, # Optional: Attempt to map device model codes to friendly names
        model_db_path=None, # Optional: Path to a custom model database file
        auth_retry_enabled=True, # Optional: Enable automatic retries on authentication failure
        auth_retry_count=3, # Optional: Number of authentication retries
        auth_retry_delay=5 # Optional: Delay in seconds between authentication retries
    )

    # Example: Fetch devices for the 'default' site
    try:
        site_name = "default" # Use the internal site name (often 'default')
        devices = controller.get_unifi_site_device(site_name=site_name, detailed=True)
        for device in devices:
            print(f"- {device.name} ({device.model_name}): {device.ip} / {device.mac}")
    except Exception as e:
        print(f"Error fetching devices: {e}")

    # Other common methods:
    # sites = controller.get_unifi_site()
    # clients = controller.get_clients(site_name)
    # wlans = controller.get_wlan_conf(site_name)

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`