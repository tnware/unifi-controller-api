=================
API Overview
=================

The UniFi Controller API package is organized into several modules:

* **API Client** - Main interface for interacting with the UniFi Controller
* **Models** - Data classes representing UniFi objects (devices, clients, etc.)
* **Export** - Functions for exporting data to various formats
* **Utilities** - Helper functions and utilities
* **Logging** - Logging configuration and utilities
* **Exceptions** - Custom exceptions for error handling

Main Components
==============

.. autosummary::
   :nosignatures:

   unifi_controller_api.UnifiController
   unifi_controller_api.models
   unifi_controller_api.export
   unifi_controller_api.exceptions
   unifi_controller_api.logging
   unifi_controller_api.utils

Getting Started
==============

The main entry point is the :class:`unifi_controller_api.UnifiController` class:

.. code-block:: python

    from unifi_controller_api import UnifiController

    # Connect to a UniFi Controller
    controller = UnifiController(
        host="https://unifi.example.com",
        username="admin",
        password="password",
        port=8443,
        site="default",
        verify_ssl=True
    )

    # Get sites managed by this controller
    sites = controller.get_unifi_site()

    # Get devices at a specific site
    devices = controller.get_unifi_site_device('default')

    # Export devices to CSV
    from unifi_controller_api.export import export_to_csv
    export_to_csv(devices, "devices.csv")