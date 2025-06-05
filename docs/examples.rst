========
Examples
========

This page provides examples of common usage patterns for the UniFi Controller API.

Basic Connection
===============

.. code-block:: python

    from unifi_controller_api import UnifiController
    from unifi_controller_api.exceptions import UnifiAuthenticationError, UnifiAPIError

    # --- Controller Initialization ---
    # Adjust these details for your UniFi Controller setup
    CONTROLLER_URL = "https://unifi.example.com:8443"  # Or :443 for UniFi OS like UDM Pro
    USERNAME = "your_local_admin_user"
    PASSWORD = "your_password"
    IS_UDM_PRO = False  # Set to True for UniFi OS based controllers
    VERIFY_SSL = True   # Set to False or path to CA bundle for self-signed certificates

    try:
        # Connect to the UniFi Controller
        controller = UnifiController(
            controller_url=CONTROLLER_URL,
            username=USERNAME,
            password=PASSWORD,
            is_udm_pro=IS_UDM_PRO,
            verify_ssl=VERIFY_SSL
        )
        print(f"Successfully connected to UniFi Controller at {CONTROLLER_URL}")

    except UnifiAuthenticationError:
        print(f"Authentication failed. Check credentials for {CONTROLLER_URL}.")
        exit()
    except UnifiAPIError as e:
        print(f"Failed to connect to UniFi Controller: {e}")
        exit()
    except Exception as e:
        print(f"An unexpected error occurred during connection: {e}")
        exit()

    # Define a target site name (usually 'default' if not changed)
    TARGET_SITE_NAME = "default"

Working with Sites
=================

Get all sites:

.. code-block:: python

    # Assuming 'controller' is initialized as shown in the Basic Connection example

    try:
        # List all sites (as UnifiSite model objects)
        sites = controller.get_unifi_site(include_health=False, raw=False)

        if not sites:
            print("No sites found on the controller.")
        else:
            print("\nAvailable Sites:")
            for site in sites:
                # 'desc' is the human-readable name, 'name' is the internal ID
                print(f"- Name: {site.desc or site.name} (ID: {site.name})")

        # Get sites again, this time including health data
        sites_with_health = controller.get_unifi_site(include_health=True, raw=False)

        if sites_with_health:
            print("\nSites with Health Data:")
            for site in sites_with_health:
                site_identifier = site.desc or site.name
                # UnifiHealth object contains subsystems, each with a status
                # For a simple overview, you might check the status of a key subsystem like 'www' or 'wan'
                # or iterate through site.health.subsystems if needed.
                # The overall health status isn't a single field on site.health directly.
                # This example just shows one way to access a subsystem status if present.
                www_status = "N/A"
                if site.health and site.health.subsystems.get("www"):
                    www_status = site.health.subsystems["www"].status
                print(f"- Site: {site_identifier}, WWW Subsystem Status: {www_status}")
        else:
            print("No sites found when fetching with health data.")

    except UnifiAPIError as e:
        print(f"Error fetching site information: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


Working with Devices
===================

Get all devices at a site:

.. code-block:: python

    # Assuming 'controller' and 'TARGET_SITE_NAME' are initialized/defined

    try:
        # Get all devices with detailed info (as UnifiDevice model objects)
        devices = controller.get_unifi_site_device(site_name=TARGET_SITE_NAME, detailed=True, raw=False)

        if not devices:
            print(f"No devices found in site '{TARGET_SITE_NAME}'.")
        else:
            print(f"\nDevices in site '{TARGET_SITE_NAME}':")
            for device in devices:
                # device.model_name provides a friendly name if auto_model_mapping is enabled
                status = 'Online' if device.state == 1 else ('Offline' if device.state == 0 else f'Unknown ({device.state})')
                print(f"- Name: {device.name or device.mac} ({device.model_name or device.model})")
                print(f"  IP: {device.ip}, MAC: {device.mac}")
                print(f"  Status: {status}, Version: {device.version}")

        # Get a specific device by MAC address
        target_mac = "00:11:22:33:44:55" # Replace with a MAC address from your site
        specific_devices = controller.get_unifi_site_device(site_name=TARGET_SITE_NAME, mac=target_mac, raw=False)

        if specific_devices:
            device = specific_devices[0]
            print(f"\nFound specific device: {device.name or device.mac} ({device.model_name or device.model})")
        else:
            print(f"\nDevice with MAC {target_mac} not found in site '{TARGET_SITE_NAME}'.")

    except UnifiAPIError as e:
        print(f"Error fetching device information: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


Working with Clients
==================

Get all clients at a site:

.. code-block:: python

    # Assuming 'controller' and 'TARGET_SITE_NAME' are initialized/defined

    try:
        # Get all connected clients (as UnifiClient model objects)
        clients = controller.get_unifi_site_client(site_name=TARGET_SITE_NAME, raw=False)

        if not clients:
            print(f"No clients found in site '{TARGET_SITE_NAME}'.")
        else:
            print(f"\nClients in site '{TARGET_SITE_NAME}':")
            for client in clients:
                client_identifier = client.name or client.hostname or client.mac
                print(f"- Client: {client_identifier} (IP: {client.ip})")
                print(f"  MAC: {client.mac}")
                print(f"  Connected to AP MAC: {client.ap_mac or 'N/A'}, Radio: {client.radio or 'N/A'}")

    except UnifiAPIError as e:
        print(f"Error fetching client information: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")


Network Configuration
===================

Get network configurations:

.. code-block:: python

    # Assuming 'controller' and 'TARGET_SITE_NAME' are initialized/defined

    try:
        # Get WLAN configurations (as UnifiWlanConf model objects)
        wlanconfs = controller.get_unifi_site_wlanconf(site_name=TARGET_SITE_NAME, raw=False)

        if not wlanconfs:
            print(f"No WLAN configurations found in site '{TARGET_SITE_NAME}'.")
        else:
            print(f"\nWLAN Configurations in site '{TARGET_SITE_NAME}':")
            for wlan in wlanconfs:
                print(f"- WLAN Group: {wlan.name}, Enabled: {wlan.enabled}")
                # Accessing x_passphrase might be sensitive, ensure it's intended for display
                # For security, avoid printing actual passphrases in logs or production output
                if wlan.x_passphrase:
                    print(f"  SSID Passphrase: {'********' if wlan.x_passphrase else 'None'}")
                print(f"  Security: {wlan.security}, User Group ID: {wlan.usergroup_id}")

        # Get network configurations (as UnifiNetworkConf model objects)
        netconfs = controller.get_unifi_site_networkconf(site_name=TARGET_SITE_NAME, raw=False)

        if not netconfs:
            print(f"No network configurations found in site '{TARGET_SITE_NAME}'.")
        else:
            print(f"\nNetwork Configurations in site '{TARGET_SITE_NAME}':")
            for net in netconfs:
                print(f"- Network: {net.name}, Purpose: {net.purpose}")
                print(f"  Subnet: {net.ip_subnet or 'N/A'}, VLAN: {net.vlan or 'N/A'}, DHCP Enabled: {net.dhcpd_enabled}")

    except UnifiAPIError as e:
        print(f"Error fetching network configurations: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

Exporting Data
=============

Export data to various formats. Ensure data is fetched as model objects (`raw=False`).

.. code-block:: python

    # Assuming 'controller' and 'TARGET_SITE_NAME' are initialized/defined
    from unifi_controller_api.export import export_csv, export_json

    try:
        # Export devices to CSV
        # Fetch devices as model objects first
        devices_to_export = controller.get_unifi_site_device(site_name=TARGET_SITE_NAME, raw=False)
        if devices_to_export:
            export_csv(devices_to_export, "devices.csv")
            print("\nDevices exported to devices.csv")
        else:
            print("\nNo devices found to export to CSV.")

        # Export clients to JSON
        # Fetch clients as model objects first
        clients_to_export = controller.get_unifi_site_client(site_name=TARGET_SITE_NAME, raw=False)
        if clients_to_export:
            export_json(clients_to_export, "clients.json")
            print("Clients exported to clients.json")
        else:
            print("No clients found to export to JSON.")

    except UnifiAPIError as e:
        print(f"Error during data export: {e}")
    except Exception as e:
        print(f"An unexpected error occurred during export: {e}")