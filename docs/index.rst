=========================================
UniFi Controller API Documentation
=========================================

A Python library for interacting with the UniFi Controller API.

.. toctree::
   :maxdepth: 2
   :caption: User Guide:

   installation
   usage
   examples

.. toctree::
   :maxdepth: 2
   :caption: API Reference:

   api/overview
   api/client
   api/models
   api/utilities
   api/export

.. toctree::
   :maxdepth: 1
   :caption: Development:

   contributing
   changelog

About
=====

The UniFi Controller API library allows you to interact with Ubiquiti's UniFi Network Controller
software. It provides a Pythonic interface to query devices, clients, and network information
from your UniFi network.

Quick Start
==========

Installation:

.. code-block:: bash

    pip install unifi-controller-api

Basic usage:

.. code-block:: python

    from unifi_controller_api import UnifiController

    controller = UnifiController('https://unifi.example.com', 'admin', 'password')
    sites = controller.get_unifi_site()
    devices = controller.get_unifi_site_device('default')

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`