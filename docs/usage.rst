=====
Usage
=====

Basic Usage
-----------

To use the UniFi Controller API:

.. code-block:: python

    from unifi_controller_api import UnifiController
    from unifi_controller_api.exceptions import UnifiAuthenticationError, UnifiAPIError

    # Initialize the client with your controller's details
    # For UniFi OS (UDM, Cloud Key Gen2+), set is_udm_pro=True
    # For self-signed certificates, set verify_ssl=False or provide a CA bundle path
    try:
        controller = UnifiController(
            controller_url="https://unifi.example.com:8443", # Adjust port if needed (e.g., 443 for UDM Pro)
            username="your_local_admin_user",
            password="your_password",
            is_udm_pro=False, # Set to True if you have a UniFi OS based controller
            verify_ssl=True # Set to False or path to CA bundle for self-signed certs
        )

        # Get a list of sites (as UnifiSite objects)
        # Use raw=True to get raw dictionaries from the API instead
        sites = controller.get_unifi_site(include_health=False, raw=False)

        if not sites:
            print("No sites found.")
            exit()

        # Get site name (usually "default" for the first site if not renamed)
        # The 'name' attribute is the internal ID, 'desc' is the human-readable name
        site_name = sites[0].name
        print(f"Operating on site: {sites[0].desc or site_name}")

        # Get devices at the site (as UnifiDevice objects)
        devices = controller.get_unifi_site_device(site_name=site_name, raw=False)

        # Get clients connected to the site (as UnifiClient objects)
        clients = controller.get_unifi_site_client(site_name=site_name, raw=False)

        # Display client information (ensure raw=False was used above)
        print("\nConnected Clients:")
        for client in clients:
            # Client name might be None, fallback to hostname or MAC
            client_identifier = client.name or client.hostname or client.mac
            print(f"- {client_identifier}, MAC: {client.mac}, IP: {client.ip}")

    except UnifiAuthenticationError:
        print("Authentication failed - please check your UniFi Controller credentials and URL.")
    except UnifiAPIError as e:
        print(f"UniFi API error: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


Working with Models
-------------------

When `raw=False` is used in data fetching methods (like `get_unifi_site_device(raw=False)`),
the API returns data as model objects with attributes corresponding to the API fields.

.. code-block:: python

    # Assuming 'sites', 'devices', 'clients' are lists of model objects from the example above

    # Working with site model
    if sites:
        site = sites[0] # Example: first site
        print(f"\nSite Details: Name: {site.desc or site.name}, ID: {site.name}")

    # Working with device model
    if devices:
        device = devices[0] # Example: first device
        # Use device.model_name for a friendly model name if auto_model_mapping is enabled
        print(f"Device: {device.name or device.mac}, Model: {device.model_name or device.model}, Status: {device.state}")

    # Working with client model
    if clients:
        client = clients[0] # Example: first client
        client_identifier = client.name or client.hostname or client.mac
        print(f"Client: {client_identifier}, MAC: {client.mac}, IP: {client.ip}")

Authentication
--------------

Authentication is handled during the initialization of the `UnifiController` object.
Ensure you provide the correct `controller_url` (including protocol and port),
`username`, and `password` for a **local account** on your UniFi Controller.
UniFi Cloud/SSO accounts are not supported by this library directly.

Set `is_udm_pro=True` if your controller is a UniFi OS device (like UDM Pro, UDM SE, Cloud Key Gen2 Plus running UniFi OS).
For older software controllers or Cloud Keys not on UniFi OS, set `is_udm_pro=False`.

If your controller uses a self-signed SSL certificate (common for local deployments),
you may need to set `verify_ssl=False` or provide the path to your CA bundle file.
Disabling SSL verification is insecure for production environments connecting over untrusted networks.

Fetching Data
-------------

Most `get_*` methods in the `UnifiController` class accept a `raw` parameter:

*   `raw=True` (default for many methods if not specified): Returns the raw JSON data from the API as a list of Python dictionaries. This is useful if you need all fields, including those not explicitly defined in the models, or if you prefer to work with dictionaries.
*   `raw=False`: Attempts to parse the JSON data into typed data model objects (e.g., `UnifiDevice`, `UnifiClient`). This provides better type hinting, auto-completion in IDEs, and more Pythonic attribute access.

Example:

.. code-block:: python

    # Fetch devices as model objects
    devices_as_models = controller.get_unifi_site_device(site_name="default", raw=False)
    for device in devices_as_models:
        print(f"Device Name: {device.name}, Model: {device.model_name or device.model}")

    # Fetch devices as raw dictionaries
    devices_as_raw_dicts = controller.get_unifi_site_device(site_name="default", raw=True)
    for device_dict in devices_as_raw_dicts:
        print(f"Device Name: {device_dict.get('name')}, Model: {device_dict.get('model')}")


Exporting Data
--------------

You can export data (typically lists of model objects) to different formats.
Ensure data is fetched with `raw=False` to get model objects for export.

.. code-block:: python

    from unifi_controller_api.export import export_json, export_csv

    # Assuming 'devices' and 'clients' are lists of model objects
    # (fetched with raw=False from previous examples)

    if devices:
        # Export devices to JSON
        export_json(devices, "devices.json")
        print("\nDevices exported to devices.json")

    if clients:
        # Export clients to CSV
        export_csv(clients, "clients.csv")
        print("Clients exported to clients.csv")

Error Handling
--------------

The library defines several custom exceptions that inherit from `UnifiControllerError`.
It's good practice to handle these exceptions when interacting with the controller.

.. code-block:: python

    from unifi_controller_api import UnifiController
    from unifi_controller_api.exceptions import UnifiAuthenticationError, UnifiAPIError, UnifiDataError, UnifiModelError

    try:
        controller = UnifiController(
            controller_url="https://unifi.example.com:8443",
            username="your_local_admin_user",
            password="your_password_is_incorrect", # Intentionally incorrect for testing auth error
            is_udm_pro=False,
            verify_ssl=True
        )
        # Example: Try to fetch data that might cause other errors
        # devices = controller.get_unifi_site_device(site_name="non_existent_site", raw=False)

    except UnifiAuthenticationError:
        print("Authentication failed - please check your UniFi Controller credentials, URL, and is_udm_pro setting.")
    except UnifiAPIError as e:
        # Covers issues like network problems, controller API errors (4xx, 5xx responses)
        print(f"UniFi API error: {e}")
    except UnifiDataError as e:
        # Raised if API response is malformed or unexpected
        print(f"UniFi data processing error: {e}")
    except UnifiModelError as e:
        # Raised if there's an issue with loading the device model database
        print(f"UniFi model database error: {e}")
    except Exception as e:
        # Catch any other unexpected errors
        print(f"An unexpected error occurred: {e}")