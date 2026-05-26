================
Export Functions
================

The UniFi Controller API includes utilities for exporting data to various formats.

.. automodule:: unifi_controller_api.export
   :members:
   :undoc-members:
   :show-inheritance:

Supported Export Formats
========================

The API supports exporting data to the following formats:

* **CSV** - Comma-separated values format for spreadsheets.
* **JSON** - JSON format for machine-readable data.
* **Python Dictionaries** - Convert data to Python dictionaries for custom processing.

Usage Examples
==============

The `automodule` directive above will list all available functions. Key functions include:

*   `export_csv`: Exports a list of model objects (like devices or sites) to a CSV file.
*   `export_json`: Exports a list of model objects to a JSON file.
*   `to_dict_list`: Converts a list of model objects into a list of Python dictionaries. This can be useful for custom export logic or further manipulation before exporting.

Exporting to CSV
----------------

.. code-block:: python

    from unifi_controller_api import UnifiController
    from unifi_controller_api.export import export_csv

    # Initialize controller (update with your details)
    controller = UnifiController(
        controller_url="https://<CONTROLLER_IP_OR_HOSTNAME_OR_URL>",
        username="<LOCAL_ADMIN_USER>",
        password="<PASSWORD>",
        is_udm_pro=False,
        verify_ssl=True
    )

    # Get devices (ensure you use raw=False to get model objects for export)
    try:
        devices = controller.get_unifi_site_device(site_name="default", raw=False)
        if devices:
            # Export to CSV
            export_csv(devices, "devices.csv")
            print("Devices exported to devices.csv")
        else:
            print("No devices found to export.")
    except Exception as e:
        print(f"An error occurred: {e}")

Exporting to JSON
-----------------

.. code-block:: python

    from unifi_controller_api import UnifiController
    from unifi_controller_api.export import export_json

    # Initialize controller (update with your details)
    controller = UnifiController(
        controller_url="https://<CONTROLLER_IP_OR_HOSTNAME_OR_URL>",
        username="<LOCAL_ADMIN_USER>",
        password="<PASSWORD>",
        is_udm_pro=False,
        verify_ssl=True
    )

    # Get clients (ensure you use raw=False to get model objects for export)
    try:
        clients = controller.get_unifi_site_client(site_name="default", raw=False)
        if clients:
            # Export to JSON
            export_json(clients, "clients.json")
            print("Clients exported to clients.json")
        else:
            print("No clients found to export.")
    except Exception as e:
        print(f"An error occurred: {e}")

Converting to Dictionaries
--------------------------

.. code-block:: python

    from unifi_controller_api import UnifiController
    from unifi_controller_api.export import to_dict_list

    # Initialize controller (update with your details)
    controller = UnifiController(
        controller_url="https://<CONTROLLER_IP_OR_HOSTNAME_OR_URL>",
        username="<LOCAL_ADMIN_USER>",
        password="<PASSWORD>",
        is_udm_pro=False,
        verify_ssl=True
    )

    # Get sites (ensure you use raw=False to get model objects)
    try:
        sites = controller.get_unifi_site(include_health=False, raw=False) # Assuming raw=False for model objects
        if sites:
            site_dictionaries = to_dict_list(sites)
            # Now you can work with site_dictionaries, e.g., print them or process further
            for site_dict in site_dictionaries:
                print(site_dict)
            print(f"Converted {len(site_dictionaries)} sites to dictionaries.")
        else:
            print("No sites found to convert.")
    except Exception as e:
        print(f"An error occurred: {e}")
