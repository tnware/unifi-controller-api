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
        controller_url="https://<CONTROLLER_IP_OR_HOSTNAME_OR_URL>", # e.g., "https://192.168.1.1:443", "https://unifi.example.com:8443"
        username="<LOCAL_ADMIN_USER>",
        password="<PASSWORD>",
        is_udm_pro=False,  # Set True for UniFi OS devices (UDM, Cloud Key Gen2+), False for legacy
        verify_ssl=True,  # Set to False for self-signed certs, True for valid public certs, or path to CA bundle
        auto_model_mapping=True,
        model_db_path=None, # Optional: Path to a custom model database file
        auth_retry_enabled=True,
        auth_retry_count=3,
        auth_retry_delay=1,
        request_timeout=30
    )

Getting Devices at a Site
-------------------------

.. code-block:: python

    # Get all devices at the 'default' site, mapped to UnifiDevice objects
    # Use raw=True to get raw dictionaries instead
    devices = controller.get_unifi_site_device(site_name="default", detailed=True, raw=False)

    # Get a specific device by MAC address
    # Note: MAC addresses are normalized (e.g., to lowercase with colons)
    device_mac = "00:1a:2b:3c:4d:5e"
    specific_devices = controller.get_unifi_site_device(site_name="default", mac=device_mac, raw=False)

    if specific_devices:
        device = specific_devices[0]
        print(f"Specific Device: {device.name} ({device.model_name}), IP: {device.ip}")

    # Print all device names and models
    for dev in devices:
        print(f"Device: {dev.name} ({dev.model_name}), MAC: {dev.mac}, IP: {dev.ip}")

Getting Clients
----------------

.. code-block:: python

    # Get all active clients at the 'default' site, mapped to UnifiClient objects
    # Use raw=True to get raw dictionaries instead
    clients = controller.get_unifi_site_client(site_name="default", raw=False)

    # Print client information
    for client in clients:
        print(f"Client: {client.hostname or client.name or client.mac} (IP: {client.ip}), MAC: {client.mac}")