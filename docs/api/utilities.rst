===================
Utilities and Helpers
===================

The UniFi Controller API includes several utility modules to help with common tasks.

Logging Utilities
================

.. automodule:: unifi_controller_api.logging
   :members:
   :undoc-members:
   :show-inheritance:

Exception Handling
================

.. automodule:: unifi_controller_api.exceptions
   :members:
   :undoc-members:
   :show-inheritance:

Utility Functions
===============

.. automodule:: unifi_controller_api.utils
   :members:
   :undoc-members:
   :show-inheritance:

Common Usage Examples
===================

Setting Up Logging
----------------

.. code-block:: python

    from unifi_controller_api.logging import setup_logger

    # Set up a logger with a specific name and level
    logger = setup_logger("my_app", log_level="INFO")

    # Use the logger
    logger.info("Connected to UniFi Controller")
    logger.error("Failed to connect")

Handling Exceptions
-----------------

.. code-block:: python

    from unifi_controller_api import UnifiController
    from unifi_controller_api.exceptions import UnifiLoginError, UnifiError

    try:
        controller = UnifiController("https://unifi.example.com", "admin", "wrong_password")
    except UnifiLoginError as e:
        print(f"Login failed: {e}")
    except UnifiError as e:
        print(f"Other UniFi error: {e}")