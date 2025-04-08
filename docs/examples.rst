========
Examples
========

This page provides examples of common usage patterns for the UniFi Controller API.

Basic Connection
===============

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

Working with Sites
=================

Get all sites:

.. code-block:: python

    # List all sites
    sites = controller.get_unifi_site()

    for site in sites:
        print(f"Site Name: {site.description} (ID: {site.name})")

    # Get a specific site with health data
    sites = controller.get_unifi_site(include_health=True)

    for site in sites:
        if hasattr(site, 'health'):
            print(f"Site: {site.description}, Status: {site.health.status}")

Working with Devices
===================

Get all devices at a site:

.. code-block:: python

    # Get all devices with detailed info
    devices = controller.get_unifi_site_device("default", detailed=True)

    for device in devices:
        print(f"Device: {device.name} ({device.model})")
        print(f"  IP: {device.ip}")
        print(f"  Status: {'Online' if device.state == 1 else 'Offline'}")

    # Get a specific device by MAC
    device = controller.get_device_by_mac("default", "00:11:22:33:44:55")

    if device:
        print(f"Found device: {device.name}")

Working with Clients
==================

Get all clients at a site:

.. code-block:: python

    # Get all connected clients
    clients = controller.get_unifi_site_client("default")

    for client in clients:
        print(f"Client: {client.name} ({client.ip})")
        print(f"  MAC: {client.mac}")
        print(f"  Connected to: {client.ap_mac}")

Network Configuration
===================

Get network configurations:

.. code-block:: python

    # Get WLAN configurations
    wlanconfs = controller.get_unifi_site_wlanconf("default")

    for wlan in wlanconfs:
        print(f"WLAN: {wlan.name}")
        print(f"  SSID: {wlan.x_passphrase}")
        print(f"  Security: {wlan.security}")

    # Get network configurations
    netconfs = controller.get_unifi_site_networkconf("default")

    for net in netconfs:
        print(f"Network: {net.name}")
        print(f"  Subnet: {net.ip_subnet}")

Exporting Data
=============

Export data to various formats:

.. code-block:: python

    from unifi_controller_api.export import export_to_csv, export_to_json

    # Export devices to CSV
    devices = controller.get_unifi_site_device("default")
    export_to_csv(devices, "devices.csv")

    # Export clients to JSON
    clients = controller.get_unifi_site_client("default")
    export_to_json(clients, "clients.json")