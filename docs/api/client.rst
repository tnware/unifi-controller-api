===================
UniFi API Client
===================

The :class:`UnifiController` class is the main interface for interacting with the UniFi Controller API.

.. automodule:: unifi_controller_api.api_client
   :members:
   :undoc-members:
   :show-inheritance:


Usage Examples
==============

Connecting to a Controller
--------------------------

.. code-block:: python

    from unifi_controller_api import UnifiController

    controller = UnifiController(
        host="https://unifi.example.com",
        username="admin",
        password="password"
    )

Getting Devices at a Site
-------------------------

.. code-block:: python

    # Get all devices at the default site
    devices = controller.get_unifi_site_device("default")

    # Get a specific device by MAC address
    device = controller.get_device_by_mac("default", "00:11:22:33:44:55")

    # Print device names
    for device in devices:
        print(f"Device: {device.name} ({device.model})")

Getting Clients
----------------

.. code-block:: python

    # Get all clients at the default site
    clients = controller.get_unifi_site_client("default")

    # Print client information
    for client in clients:
        print(f"Client: {client.name} ({client.ip})")