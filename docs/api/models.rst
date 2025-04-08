=============
Data Models
=============

The UniFi Controller API uses data classes to represent the various objects returned by the API.

Model Organization
==================

Each model represents a specific type of data returned by the UniFi Controller API:

.. list-table::
   :header-rows: 1
   :widths: 25 75

   * - Model
     - Description
   * - :class:`~unifi_controller_api.models.UnifiDevice`
     - UniFi network devices (access points, switches, gateways)
   * - :class:`~unifi_controller_api.models.UnifiSite`
     - Sites managed by the controller
   * - :class:`~unifi_controller_api.models.UnifiClient`
     - Client devices connected to the network
   * - :class:`~unifi_controller_api.models.UnifiEvent`
     - Events recorded by the controller
   * - :class:`~unifi_controller_api.models.UnifiAlarm`
     - Alerts and alarms
   * - :class:`~unifi_controller_api.models.UnifiWlanConf`
     - WLAN configurations
   * - :class:`~unifi_controller_api.models.UnifiRogueAp`
     - Rogue access points detected
   * - :class:`~unifi_controller_api.models.UnifiNetworkConf`
     - Network configurations
   * - :class:`~unifi_controller_api.models.UnifiHealth`
     - Health metrics for sites
   * - :class:`~unifi_controller_api.models.UnifiPortConf`
     - Port configurations

Device Models
=============

.. automodule:: unifi_controller_api.models.device
   :members:
   :undoc-members:
   :show-inheritance:

Site Models
===========

.. automodule:: unifi_controller_api.models.site
   :members:
   :undoc-members:
   :show-inheritance:

Client Models
=============

.. automodule:: unifi_controller_api.models.client
   :members:
   :undoc-members:
   :show-inheritance:

Network Configuration Models
============================

.. automodule:: unifi_controller_api.models.networkconf
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: unifi_controller_api.models.wlanconf
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: unifi_controller_api.models.portconf
   :members:
   :undoc-members:
   :show-inheritance:

Health Models
==============

.. automodule:: unifi_controller_api.models.health
   :members:
   :undoc-members:
   :show-inheritance:

Event and Alert Models
======================

.. automodule:: unifi_controller_api.models.event
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: unifi_controller_api.models.alarm
   :members:
   :undoc-members:
   :show-inheritance:

.. automodule:: unifi_controller_api.models.rogueap
   :members:
   :undoc-members:
   :show-inheritance:


Common Model Behavior
=====================

All model classes inherit from a base dataclass and provide common functionality:

* JSON serialization/deserialization
* Handling of "extra" properties not defined in the dataclass
* Type conversion for known fields