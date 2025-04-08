================
Export Functions
================

The UniFi Controller API includes utilities for exporting data to various formats.

.. automodule:: unifi_controller_api.export
   :members:
   :undoc-members:
   :show-inheritance:

Supported Export Formats
=======================

The API supports exporting data to the following formats:

* **CSV** - Comma-separated values format for spreadsheets
* **JSON** - JSON format for machine-readable data
* **YAML** - YAML format for human-readable data

Usage Examples
=============

Exporting to CSV
---------------

.. code-block:: python

    from unifi_controller_api import UnifiController
    from unifi_controller_api.export import export_to_csv

    # Get devices
    controller = UnifiController("https://unifi.example.com", "admin", "password")
    devices = controller.get_unifi_site_device("default")

    # Export to CSV
    export_to_csv(devices, "devices.csv")

Exporting to JSON
----------------

.. code-block:: python

    from unifi_controller_api import UnifiController
    from unifi_controller_api.export import export_to_json

    # Get clients
    controller = UnifiController("https://unifi.example.com", "admin", "password")
    clients = controller.get_unifi_site_client("default")

    # Export to JSON
    export_to_json(clients, "clients.json")