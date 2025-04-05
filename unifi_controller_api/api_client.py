import json
import os

import requests
import urllib3

from typing import List, Dict, Any, Union, Optional

from .models.site import UnifiSite
from .models.device import UnifiDevice
from .models.client import UnifiClient
from .logging import get_logger
from .utils import resolve_model_names, map_api_data_to_model
from .exceptions import (
    UnifiAuthenticationError,
    UnifiAPIError,
    UnifiDataError,
    UnifiModelError,
)

logger = get_logger(__name__)

DEFAULT_REPORT_FIELDS = [
    "site_name",
    "model",
    "model_name",
    "ip",
    "mac",
    "model_in_lts",
    "model_in_eol",
    "type",
    "version",
    "adopted",
    "last_seen",
    "disconnected_at",
    "uptime",
    "disconnection_reason",
    "connect_request_ip",
]


class UnifiController:
    """
    Client for interacting with the Unifi Controller API.

    This class provides methods to authenticate, fetch data about sites and devices,
    and generate reports from a Unifi Controller.
    """

    def __init__(
        self,
        controller_url,
        username,
        password,
        is_udm_pro=False,
        disable_ssl_warnings=False,
        verify_ssl=True,
        auto_model_mapping=True,
        model_db_path=None,
    ):
        """
        Initialize the Unifi Controller client and authenticate.

        Args:
            controller_url: Base URL of the Unifi Controller.
            username: Username for authentication.
            password: Password for authentication.
            is_udm_pro: Whether the controller is a UniFi OS device. Set to True for:
                        UDM, UDM Pro, UDR, Cloud Key Gen2 (2.0.24+), UX, UDW,
                        UCG-Ultra, CK-Enterprise, and EFG. Defaults to False.
            disable_ssl_warnings: Whether to disable SSL warnings when verify_ssl is False.
                                Defaults to False.
            verify_ssl: Whether to verify SSL certificates. Can be:
                       - True: Verify SSL certificates (default, recommended)
                       - False: Disable verification (insecure, not recommended)
                       - str: Path to a CA bundle file or directory with certificates of trusted CAs
            auto_model_mapping: Whether to automatically populate model_name using the device-models.json
                              database. Defaults to True.
            model_db_path: Optional custom path to the device model database JSON file.
                         If None, uses the built-in device-models.json file. Defaults to None.
        """

        logger.debug(
            f"Initializing UnifiController with URL: {controller_url}, is_udm_pro: {is_udm_pro}"
        )
        self.controller_url = controller_url
        self.is_udm_pro = is_udm_pro
        self.session = requests.Session()
        self.verify_ssl = verify_ssl
        self.auto_model_mapping = auto_model_mapping

        if model_db_path is None:
            self.model_db_path = os.path.join(
                os.path.dirname(__file__), "device-models.json"
            )
        else:
            self.model_db_path = model_db_path

        self._device_models = None

        if disable_ssl_warnings and not verify_ssl:
            logger.warning(
                "SSL certificate verification is disabled. This is not recommended for production use."
            )
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        elif not verify_ssl:
            logger.warning(
                "SSL certificate verification is disabled but SSL warnings are enabled. You may see warning messages."
            )

        self.authenticate(username, password)

    def authenticate(self, username, password):
        """
        Authenticate with the Unifi Controller.

        For UniFi OS devices (UDM, UDM Pro, UDR, etc.), uses /api/auth/login
        followed by changing the API path to /proxy/network. For legacy controllers,
        uses /api/login directly.

        Args:
            username: Username for authentication. Must be a local account, not a cloud account.
            password: Password for authentication.

        Raises:
            UnifiAuthenticationError: If authentication fails.
        """
        if self.is_udm_pro:
            login_uri = f"{self.controller_url}/api/auth/login"
            logger.debug(f"Using UDM Pro authentication endpoint: {login_uri}")
            self.controller_url = f"{self.controller_url}/proxy/network"
        else:
            login_uri = f"{self.controller_url}/api/login"
            logger.debug(f"Using legacy authentication endpoint: {login_uri}")

        logger.debug(
            f"Attempting authentication with username: {username}")
        try:
            response = self.session.post(
                login_uri,
                json={"username": username, "password": password},
                verify=self.verify_ssl,
            )
            response.raise_for_status()
            if response.json().get("meta", {}).get("rc") == "ok":
                logger.info("Successfully connected to Unifi controller.")
                logger.debug("Authentication response meta: ok")
            else:
                error_msg = "Failed to connect: Response code not ok."
                logger.warning(error_msg)
                logger.debug(f"Authentication response: {response.json()}")
                raise UnifiAuthenticationError(error_msg)
        except requests.exceptions.RequestException as e:
            error_msg = f"Authentication failed: {e}"
            logger.error(error_msg)
            raise UnifiAuthenticationError(error_msg) from e

    def invoke_get_rest_api_call(self, url, headers=None):
        """
        Make a GET request to the UniFi Controller REST API.

        Args:
            url: The URL to send the GET request to.
            headers: Optional additional headers to include in the request.

        Returns:
            The response object on success.

        Raises:
            UnifiAPIError: If the API request fails.
        """
        try:
            if headers:
                response = self.session.get(
                    url, headers=headers, verify=self.verify_ssl
                )
            else:
                response = self.session.get(url, verify=self.verify_ssl)

            response.raise_for_status()
            logger.debug(f"API GET request to {url} successful")
            return response
        except requests.exceptions.RequestException as e:
            error_msg = f"API GET request to {url} failed: {str(e)}"
            logger.error(error_msg)
            raise UnifiAPIError(error_msg) from e

    def _process_api_response(
        self, response: Optional[requests.Response], uri: str
    ) -> List[Dict[str, Any]]:
        """
        Process API response and handle common error cases.

        Args:
            response: Response from API call
            uri: URI that was called

        Returns:
            List of data items from the response

        Raises:
            UnifiAPIError: If the API request fails
            UnifiDataError: If the API response cannot be parsed
        """
        if response is None:
            raise UnifiAPIError(f"API request to {uri} failed")

        try:
            raw_data = response.json()
            raw_results = raw_data.get("data", [])
            if "data" not in raw_data:
                error_msg = f"Unexpected API response format for {uri}"
                logger.warning(error_msg)
                raise UnifiDataError(error_msg)
            return raw_results
        except (ValueError, AttributeError) as e:
            error_msg = f"Failed to parse API response: {e}"
            logger.error(error_msg)
            raise UnifiDataError(error_msg) from e

    def get_unifi_site(
        self, include_health, raw=False
    ) -> Union[List[Dict[str, Any]], List[UnifiSite]]:
        """
        Get information about Unifi sites.

        Args:
            include_health: Whether to include health information in the response.
            raw: Whether to return raw API response. Defaults to False.

        Returns:
            list: Site information with or without health data.
                 Returns a list of UnifiSite objects unless raw=True.

        Raises:
            UnifiAPIError: If the API request fails.
            UnifiDataError: If the API response cannot be parsed.
        """
        uri = (
            f"{self.controller_url}/api/stat/sites"
            if include_health
            else f"{self.controller_url}/api/self/sites"
        )
        response = self.invoke_get_rest_api_call(uri)
        raw_results = self._process_api_response(response, uri)

        if raw:
            return raw_results

        sites = []
        for site_data in raw_results:
            model_fields, extra_fields = map_api_data_to_model(
                site_data, UnifiSite
            )
            try:
                site = UnifiSite(**model_fields)
                if hasattr(site, "_extra_fields"):
                    site._extra_fields = extra_fields
                sites.append(site)
            except Exception as e:
                logger.error(
                    f"Error creating UnifiSite model from data: {site_data}. Error: {e}")

        return sites

    def get_unifi_site_device(
        self, site_name, detailed=False, raw=False,
        mac: Optional[Union[str, List[str]]] = None
    ) -> Union[List[Dict[str, Any]], List[UnifiDevice]]:
        """
        Get information about devices on a specific Unifi site.

        Args:
            site_name: The name of the site to fetch devices from.
            detailed: Whether to fetch detailed device information.
                      True uses /stat/device, False uses /stat/device-basic.
            raw: Whether to return raw API response. Defaults to False.
            mac: Optional MAC address string or list of MAC strings to filter by.
                 Defaults to None (no filtering).

        Returns:
            list: Device information. Returns a list of UnifiDevice objects unless raw=True.

        Raises:
            UnifiAPIError: If the API request fails.
            UnifiDataError: If the API response cannot be parsed.
            UnifiModelError: If data cannot be mapped to the UnifiDevice model.
        """
        uri = (
            f"{self.controller_url}/api/s/{site_name}/stat/device"
            if detailed
            else f"{self.controller_url}/api/s/{site_name}/stat/device-basic"
        )

        if mac is not None:
            mac_list = [mac] if isinstance(mac, str) else mac
            normalized_macs = [self.normalize_mac(m) for m in mac_list]
            mac_query = ",".join(normalized_macs)
            uri += f"?mac={mac_query}"
            logger.info(f"Filtering devices by MAC(s): {mac_query}")

        logger.info(f"Fetching devices for site '{site_name}' from {uri}")
        response = self.invoke_get_rest_api_call(uri)
        raw_results = self._process_api_response(response, uri)

        if raw:
            logger.debug("Returning raw device data.")
            return raw_results

        devices = []
        for device_data in raw_results:
            model_fields, _extra_fields = map_api_data_to_model(
                device_data, UnifiDevice
            )
            try:
                device = UnifiDevice(**model_fields)
                if not hasattr(device, 'site_name') or not device.site_name:
                    device.site_name = site_name
                devices.append(device)
            except Exception as e:
                logger.error(
                    f"Error creating UnifiDevice model from data: {device_data}. Error: {e}")

        if devices and self.auto_model_mapping:
            logger.debug("Resolving model names for devices.")
            resolve_model_names(devices, self.model_db_path)

        logger.debug(f"Returning {len(devices)} mapped UnifiDevice objects.")
        return devices

    def get_unifi_site_client(
        self, site_name, raw=False
    ) -> Union[List[Dict[str, Any]], List[UnifiClient]]:
        """
        Get information about active clients (stations) on a specific Unifi site.
        Uses @dataclass for the returned objects, applying consistent model mapping.
        Endpoint changed to /stat/sta for potentially better active client data (including IP).

        Args:
            site_name: The name of the site to fetch clients from.
            raw: Whether to return raw API response. Defaults to False.

        Returns:
            list: Client information. Returns a list of UnifiClient objects unless raw=True.

        Raises:
            UnifiAPIError: If the API request fails.
            UnifiDataError: If the API response cannot be parsed.
            UnifiModelError: If data cannot be mapped to the UnifiClient model.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/sta"
        logger.info(
            f"Fetching active clients for site '{site_name}' from {uri}")
        response = self.invoke_get_rest_api_call(uri)
        raw_results = self._process_api_response(response, uri)

        if raw:
            logger.debug("Returning raw client data.")
            return raw_results

        clients = []
        for client_data in raw_results:
            try:
                model_fields, _extra_fields = map_api_data_to_model(
                    client_data, UnifiClient
                )

                client = UnifiClient(**model_fields)

                clients.append(client)

            except TypeError as e:
                logger.error(
                    f"Error instantiating UnifiClient dataclass (likely missing fields): {model_fields}. Error: {e}")
            except Exception as e:
                logger.error(
                    f"Error processing client data into dataclass: {client_data}. Error: {e}")

        logger.debug(
            f"Returning {len(clients)} mapped UnifiClient dataclass objects (using map_api_data_to_model).")
        return clients

    def normalize_mac(self, mac_address):
        """
        Normalize MAC address to colon-separated format.

        Args:
            mac_address: MAC address string in any format (with or without separators).

        Returns:
            str: MAC address with colons between each pair of characters.
        """
        mac_clean = (
            mac_address.replace(":", "").replace(
                "-", "").replace(".", "").lower()
        )

        return ":".join(mac_clean[i: i + 2] for i in range(0, len(mac_clean), 2))

    def load_device_models(self, force_reload=False):
        """
        Load the device models database from a JSON file.

        Args:
            force_reload: Whether to force reload the device models database.
                        Defaults to False.

        Returns:
            dict: The device models database.

        Raises:
            UnifiModelError: If the device models database cannot be loaded.
        """
        if self._device_models is not None and not force_reload:
            return self._device_models

        logger.debug(f"Loading device models from {self.model_db_path}")
        try:
            with open(self.model_db_path, "r", encoding="utf-8") as f:
                self._device_models = json.load(f)
            return self._device_models
        except (json.JSONDecodeError, IOError) as e:
            error_msg = f"Failed to load device models from {self.model_db_path}: {e}"
            logger.error(error_msg)
            raise UnifiModelError(error_msg) from e

    def generate_device_report(
        self, sites, output_csv_path, device_models_json_path=None, fields=None
    ):
        """
        Generate a CSV report of devices across multiple sites.

        Args:
            sites: List of sites to include in the report.
            output_csv_path: Path where the CSV report will be saved.
            device_models_json_path: Path to the JSON file with device model information.
                                   If None, uses the default path. Defaults to None.
            fields: List of fields to include in the report. If None, uses DEFAULT_REPORT_FIELDS.
                   Defaults to None.

        Raises:
            UnifiAPIError: If the API request to site devices fails.
            UnifiDataError: If the site devices data cannot be parsed.
            UnifiModelError: If the device models cannot be loaded.
        """
        devices = self.devices_report(sites, device_models_json_path)

        if not devices:
            logger.info(
                "No device data found across any sites. Creating empty CSV.")
            with open(output_csv_path, "w", newline="", encoding="utf-8") as csvfile:
                csvfile.write("")
            return

        if fields is None:
            fields = DEFAULT_REPORT_FIELDS

        report_data = []

        for device in devices:
            device_dict = {}

            for field in fields:
                attr_name = field

                if attr_name == "site_name" and (
                    not hasattr(device, attr_name) or getattr(
                        device, attr_name) is None
                ):
                    device_dict[field] = "Unknown Site"
                elif hasattr(device, attr_name):
                    device_dict[field] = getattr(device, attr_name)
                else:
                    device_dict[field] = None

            report_data.append(device_dict)

        from .export import export_csv

        export_csv(report_data, output_csv_path)

    def devices_report(
        self,
        sites: Union[List[UnifiSite], List[Dict[str, Any]]],
        device_models_json_path=None,
    ) -> List[UnifiDevice]:
        """
        Generate a detailed device report across multiple sites.

        This method provides comprehensive information about all devices across the specified sites.

        Args:
            sites: List of sites to include in the report. Can be UnifiSite objects or raw dicts.
            device_models_json_path: Path to the JSON file with device model information.
                                   If None, uses the default path. Defaults to None.

        Returns:
            list: A list of UnifiDevice objects with enhanced model information.

        Raises:
            UnifiAPIError: If the API request to site devices fails.
            UnifiDataError: If the site devices data cannot be parsed.
            UnifiModelError: If the device models cannot be loaded.
        """
        if device_models_json_path is None:
            device_models_json_path = self.model_db_path

        report_data: List[UnifiDevice] = []

        for site in sites:
            if isinstance(site, UnifiSite):
                site_name = site.desc or "Unknown Site"
                site_id = site.name
            else:
                site_name = site.get("desc", "Unknown Site")
                site_id = site.get("name")

            try:
                devices = self.get_unifi_site_device(
                    site_name=site_id, detailed=True)

                for device in devices:
                    if isinstance(device, UnifiDevice) and not device.unifi_id:
                        device.unifi_id = site_id

                if not isinstance(devices, list):
                    logger.warning(
                        f"Expected list of devices for site {site_name}, got {type(devices)}"
                    )
                    continue

                valid_devices = [
                    d for d in devices if isinstance(d, UnifiDevice)]
                if len(valid_devices) != len(devices):
                    logger.warning(
                        f"Some devices for site {site_name} were not UnifiDevice objects"
                    )
                report_data.extend(valid_devices)

            except (UnifiAPIError, UnifiDataError) as e:
                logger.error(
                    f"Error getting devices for site {site_name}: {e}")

        if report_data and self.auto_model_mapping:
            try:
                resolve_model_names(report_data, device_models_json_path)
            except Exception as e:
                error_msg = f"Error resolving model names: {e}"
                logger.error(error_msg)
                raise UnifiModelError(error_msg) from e

        return report_data
