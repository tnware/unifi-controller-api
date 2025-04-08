=====
Usage
=====

Basic Usage
-----------

To use the UniFi Controller API:

.. code-block:: python

    from unifi_controller_api import UnifiController

    # Initialize the client with your controller's details
    controller = UnifiController(
        host="unifi.example.com",
        username="admin",
        password="password",
        port=8443,
        verify_ssl=True
    )

    # Get a list of sites
    sites = controller.get_unifi_site()

    # Get site ID (usually "default")
    site_id = sites[0].name

    # Get devices at a site
    devices = controller.get_unifi_site_device(site_id)

    # Get clients connected to a site
    clients = controller.get_unifi_site_client(site_id)

    # Display client information
    for client in clients:
        print(f"Client: {client.name}, MAC: {client.mac}, IP: {client.ip}")

Working with Models
-------------------

The API returns data as model objects with properties:

.. code-block:: python

    # Working with site model
    site = sites[0]
    print(f"Site name: {site.description}, ID: {site.name}")

    # Working with device model
    device = devices[0]
    print(f"Device: {device.name}, Model: {device.model}, Status: {device.state}")

    # Working with client model
    client = clients[0]
    print(f"Client: {client.name}, MAC: {client.mac}, IP: {client.ip}")

Exporting Data
--------------

You can export data to different formats:

.. code-block:: python

    from unifi_controller_api.export import export_to_json, export_to_csv

    # Export devices to JSON
    export_to_json(devices, "devices.json")

    # Export clients to CSV
    export_to_csv(clients, "clients.csv")

Error Handling
--------------

Handle API errors:

.. code-block:: python

    from unifi_controller_api.exceptions import UnifiLoginError, UnifiConnectionError

    try:
        controller = UnifiController(
            host="unifi.example.com",
            username="admin",
            password="incorrect",
            port=8443,
            verify_ssl=True
        )
    except UnifiLoginError:
        print("Login failed - check credentials")
    except UnifiConnectionError:
        print("Connection failed - check host and port")