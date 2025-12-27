import json
import os
import time
import base64
import binascii

import requests
import urllib3

from typing import List, Dict, Any, Union, Optional

from .models.site import UnifiSite
from .models.device import UnifiDevice
from .models.client import UnifiClient
from .models.event import UnifiEvent
from .models.alarm import UnifiAlarm
from .models.wlanconf import UnifiWlanConf
from .models.rogueap import UnifiRogueAp
from .models.networkconf import UnifiNetworkConf
from .models.health import UnifiHealth, UnifiSubsystemHealth
from .models.portconf import UnifiPortConf
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

    Note:
        This client interacts with the UniFi Controller's **undocumented** private API.
        Response structures and endpoint behavior may change without notice between
        controller versions. While this library attempts to provide stable methods and
        data models, users should be prepared for potential inconsistencies and check
        the `_extra_fields` attribute on returned dataclass objects for unexpected data.
    """

    def __init__(
        self,
        controller_url,
        username,
        password,
        is_udm_pro=False,
        verify_ssl=True,
        auto_model_mapping=True,
        model_db_path=None,
        auth_retry_enabled=True,
        auth_retry_count=3,
        auth_retry_delay=1,
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
            verify_ssl: Whether to verify SSL certificates. Can be:
                       - True: Verify SSL certificates (default, recommended)
                       - False: Disable verification (insecure, not recommended)
                       - str: Path to a CA bundle file or directory with certificates of trusted CAs
            auto_model_mapping: Whether to automatically populate model_name using the device-models.json
                              database. Defaults to True.
            model_db_path: Optional custom path to the device model database JSON file.
                         If None, uses the built-in device-models.json file. Defaults to None.
            auth_retry_enabled: Whether to automatically retry authentication when session expires.
                             Defaults to True.
            auth_retry_count: Maximum number of authentication retry attempts (1-10).
                           Defaults to 3.
            auth_retry_delay: Delay in seconds between retry attempts (0.1-30).
                           Defaults to 1.
        """
        if auth_retry_count < 1 or auth_retry_count > 10:
            raise ValueError("auth_retry_count must be between 1 and 10")
        if auth_retry_delay < 0.1 or auth_retry_delay > 30:
            raise ValueError("auth_retry_delay must be between 0.1 and 30")

        logger.debug(
            f"Initializing UnifiController with URL: {controller_url}, is_udm_pro: {is_udm_pro}"
        )
        self.controller_url = controller_url
        self.original_controller_url = controller_url
        self.is_udm_pro = is_udm_pro
        self.session = requests.Session()
        self.verify_ssl = verify_ssl
        self.auto_model_mapping = auto_model_mapping

        self.auth_retry_enabled = auth_retry_enabled
        self.auth_retry_count = auth_retry_count
        self.auth_retry_delay = auth_retry_delay

        if model_db_path is None:
            self.model_db_path = os.path.join(
                os.path.dirname(__file__), "device-models.json"
            )
        else:
            self.model_db_path = model_db_path

        self._device_models = None

        if not verify_ssl:
            logger.warning(
                "SSL certificate verification is disabled. This is not recommended for production use."
            )
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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
        self._username = username
        self._password = password

        if self.is_udm_pro:
            login_uri = f"{self.original_controller_url}/api/auth/login"
            logger.debug(f"Using UDM Pro authentication endpoint: {login_uri}")
            self.controller_url = f"{self.original_controller_url}/proxy/network"
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

            # Handle both legacy (meta.rc == "ok") and UniFi OS (user object) responses.
            try:
                response_data = response.json()
            except ValueError:
                error_msg = "Authentication failed: Non-JSON response received."
                logger.warning(error_msg)
                raise UnifiAuthenticationError(error_msg)

            # Explicit UniFi OS authentication error payloads (HTTP 200 with error JSON)
            # Example: {'code': 'AUTHENTICATION_FAILED_INVALID_CREDENTIALS', 'message': 'Invalid username or password', 'level': 'debug'}
            if (
                isinstance(response_data, dict)
                and ("code" in response_data and "message" in response_data)
                and not response_data.get("meta")
            ):
                error_code = response_data.get("code", "AUTHENTICATION_FAILED")
                error_message = response_data.get(
                    "message", "Authentication failed.")
                full_message = f"{error_code}: {error_message}"
                logger.warning(f"Authentication failed: {full_message}")
                raise UnifiAuthenticationError(full_message)

            is_unifi_os_response = isinstance(response_data, dict) and (
                "isSuperAdmin" in response_data or "roles" in response_data
            )
            is_legacy_response = (
                isinstance(response_data, dict)
                and response_data.get("meta", {}).get("rc") == "ok"
            )

            if is_unifi_os_response or is_legacy_response:
                logger.info("Successfully connected to Unifi controller.")
                logger.debug("Authentication response validated.")
            else:
                error_msg = "Failed to connect: Unknown authentication response format."
                logger.warning(error_msg)
                logger.debug(f"Authentication response: {response_data}")
                raise UnifiAuthenticationError(error_msg)
        except requests.exceptions.RequestException as e:
            error_msg = f"Authentication failed: {e}"
            logger.error(error_msg)
            raise UnifiAuthenticationError(error_msg) from e

    def _invoke_api_call(
        self,
        method: str,
        url: str,
        json_payload: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> requests.Response:
        """
        Make an API request with the specified method, handling potential re-authentication.

        Handles different HTTP methods (POST, PUT, DELETE, etc.), JSON payloads,
        and CSRF token injection for UniFi OS devices when necessary.

        Args:
            method: HTTP method (e.g., 'POST', 'PUT', 'DELETE').
            url: The full URL for the API endpoint.
            json_payload: Optional dictionary to send as JSON body.
            headers: Optional dictionary of additional headers.
            timeout: Optional request timeout in seconds.

        Returns:
            requests.Response: The response object from the requests library.

        Raises:
            UnifiAPIError: For general API request errors.
            UnifiAuthenticationError: If authentication or re-authentication fails.
            ValueError: If an invalid HTTP method is provided.
        """
        if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
            raise ValueError(f"Unsupported HTTP method: {method}")

        request_kwargs = {
            'verify': self.verify_ssl,
            'timeout': timeout
        }

        if headers:
            request_kwargs['headers'] = headers

        if json_payload is not None:
            request_kwargs['json'] = json_payload

        current_headers = headers.copy() if headers else {}
        if self.is_udm_pro and method.upper() != 'GET':
            csrf_token = self._extract_csrf_token()
            if csrf_token:
                current_headers['X-Csrf-Token'] = csrf_token
                request_kwargs['headers'] = current_headers
            else:
                logger.warning(
                    "UniFi OS detected, but CSRF token not found in cookies for non-GET request.")

        try:
            response = self.session.request(method, url, **request_kwargs)

            if response.status_code == 401 and self.auth_retry_enabled:
                if hasattr(self, '_username') and hasattr(self, '_password'):
                    for retry in range(self.auth_retry_count):
                        try:
                            if retry > 0 and self.auth_retry_delay > 0:
                                time.sleep(self.auth_retry_delay)

                            logger.warning(
                                f"Received 401 Unauthorized from {url}. "
                                f"Attempting re-authentication (try {retry+1}/{self.auth_retry_count})..."
                            )

                            self.authenticate(self._username, self._password)
                            logger.info(
                                "Re-authentication successful. Retrying original request.")

                            if self.is_udm_pro and method.upper() != 'GET':
                                csrf_token = self._extract_csrf_token()
                                if csrf_token:
                                    current_headers['X-Csrf-Token'] = csrf_token
                                    request_kwargs['headers'] = current_headers
                                else:
                                    logger.warning(
                                        "CSRF token not found after re-auth.")

                            response = self.session.request(
                                method, url, **request_kwargs)

                            if response.status_code != 401:
                                break

                            logger.warning(
                                f"Request still failed with 401 after re-authentication (try {retry+1}).")

                        except UnifiAuthenticationError as auth_err:
                            logger.error(
                                f"Re-authentication failed during retry {retry+1}: {auth_err}")
                            break

                    if response.status_code == 401:
                        raise UnifiAuthenticationError(
                            f"Authentication failed after {self.auth_retry_count} attempts. "
                            "Session could not be renewed."
                        )
                else:
                    logger.error(
                        "Cannot re-authenticate: credentials not available")
                    response.raise_for_status()

            response.raise_for_status()
            logger.debug(
                f"API {method} request to {url} successful (Status: {response.status_code})")
            return response

        except requests.exceptions.RequestException as e:
            if not isinstance(e, UnifiAuthenticationError):
                error_msg = f"API {method} request to {url} failed: {str(e)}"
                logger.error(error_msg)
                raise UnifiAPIError(error_msg) from e
            else:
                raise

    def _extract_csrf_token(self) -> Optional[str]:
        """Extracts the CSRF token from the session cookies if available."""
        unifi_cookie = self.session.cookies.get('TOKEN', domain=self.session.cookies.list_domains()[
                                                0] if self.session.cookies.list_domains() else None)
        if not unifi_cookie:
            logger.debug("UniFi OS 'TOKEN' cookie not found in session.")
            return None

        parts = unifi_cookie.split('.')
        if len(parts) != 3:
            logger.warning(
                f"Invalid JWT structure found in TOKEN cookie: {unifi_cookie}")
            return None

        try:
            payload_b64 = parts[1]
            payload_b64 += '=' * (-len(payload_b64) % 4)
            payload_json = base64.urlsafe_b64decode(
                payload_b64).decode('utf-8')
            payload_data = json.loads(payload_json)

            csrf_token = payload_data.get('csrfToken')
            if csrf_token:
                logger.debug("Extracted CSRF token from cookie.")
                return csrf_token
            else:
                logger.warning("CSRF token not found within JWT payload.")
                return None
        except (IndexError, binascii.Error, json.JSONDecodeError, UnicodeDecodeError) as e:
            logger.error(f"Error decoding JWT payload from TOKEN cookie: {e}")
            return None

    def invoke_get_rest_api_call(self, url, headers=None):
        """
        Make a GET request to the UniFi Controller REST API with automatic session renewal.

        When a 401 Unauthorized error is received (indicating an expired session),
        this method will automatically attempt to re-authenticate and retry the request
        according to the configured retry settings.

        Args:
            url: The URL to send the GET request to.
            headers: Optional additional headers to include in the request.

        Returns:
            The response object on success.

        Raises:
            UnifiAPIError: If the API request fails.
            UnifiAuthenticationError: If re-authentication fails.
        """
        try:
            if headers:
                response = self.session.get(
                    url, headers=headers, verify=self.verify_ssl)
            else:
                response = self.session.get(url, verify=self.verify_ssl)

            if response.status_code == 401 and self.auth_retry_enabled:
                if hasattr(self, '_username') and hasattr(self, '_password'):
                    for retry in range(self.auth_retry_count):
                        try:
                            if retry > 0 and self.auth_retry_delay > 0:
                                time.sleep(self.auth_retry_delay)

                            logger.warning(
                                f"Received 401 Unauthorized from {url}. "
                                f"Attempting re-authentication (try {retry+1}/{self.auth_retry_count})..."
                            )

                            self.authenticate(self._username, self._password)
                            logger.info(
                                "Re-authentication successful. Retrying original request.")

                            if headers:
                                response = self.session.get(
                                    url, headers=headers, verify=self.verify_ssl)
                            else:
                                response = self.session.get(
                                    url, verify=self.verify_ssl)

                            if response.status_code != 401:
                                break

                            logger.warning(
                                "Request still failed with 401 after re-authentication.")

                        except UnifiAuthenticationError as auth_err:
                            logger.error(
                                f"Re-authentication failed: {auth_err}")

                    if response.status_code == 401:
                        raise UnifiAuthenticationError(
                            f"Authentication failed after {self.auth_retry_count} attempts. "
                            "Session could not be renewed."
                        )
                else:
                    logger.error(
                        "Cannot re-authenticate: credentials not available")

            response.raise_for_status()
            logger.debug(f"API GET request to {url} successful")
            return response

        except requests.exceptions.RequestException as e:
            if not isinstance(e, UnifiAuthenticationError):
                error_msg = f"API GET request to {url} failed: {str(e)}"
                logger.error(error_msg)
                raise UnifiAPIError(error_msg) from e
            raise

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
        self, include_health, raw=True
    ) -> Union[List[Dict[str, Any]], List[UnifiSite]]:
        """
        Get information about Unifi sites.

        Fetches site data from either `/api/stat/sites` (with health) or
        `/api/self/sites` (without health) based on the `include_health` flag.
        This interacts with **undocumented** private API endpoints, and the response
        structure may vary between controller versions.

        Args:
            include_health (bool): If True, includes detailed health metrics for each site.
                                  Requires potentially more controller resources.
            raw (bool): If True (default), returns the raw API response as a list of dictionaries.
                        If False, attempts to map the response to `UnifiSite` dataclass objects.

        Returns:
            Union[List[Dict[str, Any]], List[UnifiSite]]:
                If `raw=True` (default), returns a `List[Dict[str, Any]]` representing the direct
                JSON response data from the API.
                If `raw=False`, returns a `List[UnifiSite]` where known fields from the API
                response are mapped to the dataclass attributes. Undocumented or new fields
                are captured in the `_extra_fields` attribute (a `Dict[str, Any]`) on each
                `UnifiSite` instance.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
            UnifiAuthenticationError: If authentication or re-authentication fails.

        Note:
            The specific health metrics included when `include_health=True` may vary
            between controller versions.
        """
        uri = (
            f"{self.controller_url}/api/stat/sites"
            if include_health
            else f"{self.controller_url}/api/self/sites"
        )
        response = self.invoke_get_rest_api_call(uri)
        raw_results = self._process_api_response(response, uri)

        if not raw:
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
        else:
            return raw_results

    def get_unifi_site_device(
        self, site_name: str, detailed=False, raw=True,
        mac: Optional[Union[str, List[str]]] = None
    ) -> Union[List[Dict[str, Any]], List[UnifiDevice]]:
        """
        Get information about devices on a specific Unifi site.

        Fetches device data from the controller using either
        `/api/s/{site_name}/stat/device` (detailed) or
        `/api/s/{site_name}/stat/device-basic` (basic).
        Can optionally filter by one or more MAC addresses.
        This interacts with **undocumented** private API endpoints, and the response
        structure may vary between controller versions.

        Args:
            site_name (str): The short name (ID) of the site to fetch devices from.
            detailed (bool): If True, fetches detailed device information via
                             `/api/s/{site_name}/stat/device`. If False (default),
                             fetches basic info via `/api/s/{site_name}/stat/device-basic`.
            raw (bool): If True (default), returns the raw API response as a list of dictionaries.
                        If False, attempts to map the response to `UnifiDevice` dataclass objects.
            mac (Optional[Union[str, List[str]]]): Optional MAC address string or list
                                                  of MAC strings to filter results by.
                                                  Defaults to None (no filtering).

        Returns:
            Union[List[Dict[str, Any]], List[UnifiDevice]]:
                If `raw=True` (default), returns a `List[Dict[str, Any]]` representing the direct
                JSON response data from the API.
                If `raw=False`, returns a `List[UnifiDevice]` mapping known fields.
                Undocumented or new fields from the API response are stored
                in the `_extra_fields` attribute (a `Dict[str, Any]`) on each
                `UnifiDevice` instance. The `model_name` field is auto-populated
                if `auto_model_mapping` is enabled during client initialization.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
            UnifiModelError: If `auto_model_mapping` is enabled and the device model
                            database cannot be loaded or parsed when `raw=False`.
            UnifiAuthenticationError: If authentication or re-authentication fails.

        Note:
            The structure of the returned data can vary between UniFi Controller versions
            as the underlying API is undocumented. Check raw results or `_extra_fields` if
            expecting specific data not present in the dataclass definition.
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

        if not raw:
            devices = []
            for device_data in raw_results:
                model_fields, _extra_fields = map_api_data_to_model(
                    device_data, UnifiDevice
                )
                try:
                    device = UnifiDevice(**model_fields)
                    # Add site_name if missing (common in basic view)
                    if not hasattr(device, 'site_name') or not device.site_name:
                        device.site_name = site_name
                    # Store extra fields if the attribute exists
                    if hasattr(device, '_extra_fields'):
                        device._extra_fields = _extra_fields
                    devices.append(device)
                except Exception as e:
                    logger.error(
                        f"Error creating UnifiDevice model from data: {device_data}. Error: {e}")

            if devices and self.auto_model_mapping:
                logger.debug("Resolving model names for devices.")
                resolve_model_names(devices, self.model_db_path)

            logger.debug(
                f"Returning {len(devices)} mapped UnifiDevice objects.")
            return devices
        else:
            logger.debug("Returning raw device data.")
            return raw_results

    def get_unifi_site_client(
        self, site_name: str, raw=True
    ) -> Union[List[Dict[str, Any]], List[UnifiClient]]:
        """
        Get information about active clients (stations) on a specific Unifi site.

        Uses the `/api/s/{site_name}/stat/sta` endpoint which typically provides
        data for currently connected clients, including network details like IP address.
        This interacts with an **undocumented** private API endpoint, and the response
        structure may vary between controller versions.

        Args:
            site_name (str): The short name (ID) of the site to fetch clients from.
            raw (bool): If True (default), returns the raw API response as a list of dictionaries.
                        If False, attempts to map the response to `UnifiClient` dataclass objects.

        Returns:
            Union[List[Dict[str, Any]], List[UnifiClient]]:
                If `raw=True` (default), returns a `List[Dict[str, Any]]` representing the direct
                JSON response data from the API.
                If `raw=False`, returns a `List[UnifiClient]` mapping known fields.
                Undocumented or new fields from the API response are stored
                in the `_extra_fields` attribute (a `Dict[str, Any]`) on each
                `UnifiClient` instance.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
            UnifiAuthenticationError: If authentication or re-authentication fails.

        Note:
            This endpoint primarily returns *active* clients. To get historical or offline
            clients, use methods like `get_all_clients_history` or `get_offline_clients_v2`.
            The specific fields returned can vary between controller versions.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/sta"
        logger.info(
            f"Fetching active clients for site '{site_name}' from {uri}")
        response = self.invoke_get_rest_api_call(uri)
        raw_results = self._process_api_response(response, uri)

        if not raw:
            clients = []
            for client_data in raw_results:
                try:
                    model_fields, _extra_fields = map_api_data_to_model(
                        client_data, UnifiClient
                    )
                    client = UnifiClient(**model_fields)
                    if hasattr(client, '_extra_fields'):
                        client._extra_fields = _extra_fields
                    clients.append(client)
                except TypeError as e:
                    logger.error(
                        f"Error instantiating UnifiClient dataclass (likely missing fields): {model_fields}. Error: {e}")
                except Exception as e:
                    logger.error(
                        f"Error processing client data into dataclass: {client_data}. Error: {e}")
            logger.debug(
                f"Returning {len(clients)} mapped UnifiClient dataclass objects.")
            return clients
        else:
            logger.debug("Returning raw client data.")
            return raw_results

    def get_unifi_site_event(
        self,
        site_name: str,
        history_hours: int = 720,
        start_index: int = 0,
        limit: int = 3000,
        raw: bool = True
    ) -> Union[List[Dict[str, Any]], List[UnifiEvent]]:
        """
        Get event logs for a specific Unifi site.

        Retrieves events from the `/api/s/{site_name}/stat/event` endpoint, which
        includes device connections/disconnections, configuration changes, etc.
        This interacts with an **undocumented** private API endpoint (using POST),
        and the response structure may vary between controller versions.

        Args:
            site_name (str): The short name (ID) of the site to fetch events from.
            history_hours (int): Look back duration in hours. Defaults to 720 (30 days).
            start_index (int): Offset for pagination. Defaults to 0.
            limit (int): Maximum number of events to return. Defaults to 3000.
            raw (bool): If True (default), returns the raw API response as a list of dictionaries.
                        If False, attempts to map the response to `UnifiEvent` dataclass objects.

        Returns:
            Union[List[Dict[str, Any]], List[UnifiEvent]]:
                If `raw=True` (default), returns a `List[Dict[str, Any]]` representing the direct
                JSON response data from the API.
                If `raw=False`, returns a `List[UnifiEvent]` mapping known fields.
                Undocumented or new fields from the API response are stored
                in the `_extra_fields` attribute (a `Dict[str, Any]`) on each
                `UnifiEvent` instance.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
            UnifiAuthenticationError: If authentication or re-authentication fails.

        Note:
            The API uses a POST request for this endpoint, even though it's fetching data.
            The specific event types and keys available can vary between controller versions.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/event"
        payload = {
            '_sort': '-time',  # Sort descending by time
            'within': history_hours,
            'type': None,  # Seems required but can be None for all types
            '_start': start_index,
            '_limit': limit,
        }
        logger.info(
            f"Fetching events for site '{site_name}' from {uri} with payload: {payload}")
        # This endpoint uses POST
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        if not raw:
            events = []
            for event_data in raw_results:
                try:
                    model_fields, extra_fields = map_api_data_to_model(
                        event_data, UnifiEvent
                    )
                    event = UnifiEvent(**model_fields)
                    if hasattr(event, '_extra_fields'):
                        event._extra_fields = extra_fields
                    events.append(event)
                except Exception as e:
                    logger.error(
                        f"Error creating UnifiEvent model from data: {event_data}. Error: {e}")
            logger.debug(f"Returning {len(events)} mapped UnifiEvent objects.")
            return events
        else:
            logger.debug("Returning raw event data.")
            return raw_results

    def get_unifi_site_alarm(
        self,
        site_name: str,
        archived: Optional[bool] = None,
        raw: bool = True
    ) -> Union[List[Dict[str, Any]], List[UnifiAlarm]]:
        """
        Get alarm logs for a specific Unifi site.

        Retrieves alarms (system alerts, warnings) from `/api/s/{site_name}/list/alarm`.
        Can optionally filter by archived status.
        This interacts with an **undocumented** private API endpoint, and the response
        structure may vary between controller versions.

        Args:
            site_name (str): The short name (ID) of the site to fetch alarms from.
            archived (Optional[bool]): Filter by archived status:
                                      - None (default): Return all alarms.
                                      - False: Return only active (unarchived) alarms.
                                      - True: Return only archived alarms.
            raw (bool): If True (default), returns the raw API response as a list of dictionaries.
                        If False, attempts to map the response to `UnifiAlarm` dataclass objects.

        Returns:
            Union[List[Dict[str, Any]], List[UnifiAlarm]]:
                If `raw=True` (default), returns a `List[Dict[str, Any]]` representing the direct
                JSON response data from the API.
                If `raw=False`, returns a `List[UnifiAlarm]` mapping known fields.
                Undocumented or new fields from the API response are stored
                in the `_extra_fields` attribute (a `Dict[str, Any]`) on each
                `UnifiAlarm` instance.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
            UnifiAuthenticationError: If authentication or re-authentication fails.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/list/alarm"
        payload = {}  # Payload seems optional for base list, used by PHP client though?
        if archived is not None:
            # Filtering might be done via query params or payload, test needed
            # Let's try query params first based on count_alarms
            uri += f"?archived={'true' if archived else 'false'}"
            logger.info(f"Filtering alarms by archived={archived}")
        # else: # PHP client sent empty payload for list_alarms
            # payload = {}

        logger.info(f"Fetching alarms for site '{site_name}' from {uri}")
        # PHP client used POST for list_alarms, let's try GET first as it's a 'list' endpoint
        try:
            response = self.invoke_get_rest_api_call(url=uri)
        except UnifiAPIError as e:
            logger.warning(
                f"GET request to {uri} failed ({e}), trying POST as per PHP client.")
            # If GET fails, try POST with optional payload
            response = self._invoke_api_call(
                method="POST", url=uri, json_payload=payload if archived is None else {})

        raw_results = self._process_api_response(response, uri)

        if not raw:
            alarms = []
            for alarm_data in raw_results:
                try:
                    model_fields, extra_fields = map_api_data_to_model(
                        alarm_data, UnifiAlarm
                    )
                    alarm = UnifiAlarm(**model_fields)
                    if hasattr(alarm, '_extra_fields'):
                        alarm._extra_fields = extra_fields
                    alarms.append(alarm)
                except Exception as e:
                    logger.error(
                        f"Error creating UnifiAlarm model from data: {alarm_data}. Error: {e}")
            logger.debug(f"Returning {len(alarms)} mapped UnifiAlarm objects.")
            return alarms
        else:
            logger.debug("Returning raw alarm data.")
            return raw_results

    def get_unifi_site_wlanconf(
        self, site_name: str, wlan_id: Optional[str] = None, raw: bool = True
    ) -> Union[List[Dict[str, Any]], List[UnifiWlanConf]]:
        """
        Get WLAN configurations for a specific Unifi site.

        Retrieves WLAN (Wireless Network) settings from `/api/s/{site_name}/rest/wlanconf`.
        Can optionally fetch a single WLAN configuration by its ID.
        This interacts with an **undocumented** private API endpoint, and the response
        structure may vary between controller versions.

        Args:
            site_name (str): The short name (ID) of the site to fetch WLAN configurations from.
            wlan_id (Optional[str]): The _id of a specific WLAN to fetch. If None (default),
                                     fetches all WLANs for the site.
            raw (bool): If True (default), returns the raw API response as a list of dictionaries.
                        If False, attempts to map the response to `UnifiWlanConf` dataclass objects.

        Returns:
            Union[List[Dict[str, Any]], List[UnifiWlanConf]]:
                If `raw=True` (default), returns a `List[Dict[str, Any]]` representing the direct
                JSON response data from the API.
                If `raw=False`, returns a `List[UnifiWlanConf]` mapping known fields.
                Undocumented or new fields from the API response are stored
                in the `_extra_fields` attribute (a `Dict[str, Any]`) on each
                `UnifiWlanConf` instance.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
            UnifiAuthenticationError: If authentication or re-authentication fails.
        """
        uri_suffix = f"/{wlan_id}" if wlan_id else ""
        uri = f"{self.controller_url}/api/s/{site_name}/rest/wlanconf{uri_suffix}"
        log_msg = f"Fetching WLAN configuration(s) for site '{site_name}'"
        if wlan_id:
            log_msg += f" (ID: {wlan_id})"
        log_msg += f" from {uri}"
        logger.info(log_msg)

        response = self.invoke_get_rest_api_call(uri)
        raw_results = self._process_api_response(response, uri)

        if not raw:
            wlanconfs = []
            for conf_data in raw_results:
                try:
                    model_fields, extra_fields = map_api_data_to_model(
                        conf_data, UnifiWlanConf
                    )
                    conf = UnifiWlanConf(**model_fields)
                    if hasattr(conf, '_extra_fields'):
                        conf._extra_fields = extra_fields
                    wlanconfs.append(conf)
                except Exception as e:
                    logger.error(
                        f"Error creating UnifiWlanConf model from data: {conf_data}. Error: {e}")
            logger.debug(
                f"Returning {len(wlanconfs)} mapped UnifiWlanConf objects.")
            return wlanconfs
        else:
            logger.debug("Returning raw WLAN configuration data.")
            return raw_results

    def get_unifi_site_rogueap(
        self, site_name: str, within_hours: int = 24, raw: bool = True
    ) -> Union[List[Dict[str, Any]], List[UnifiRogueAp]]:
        """
        Get neighboring APs (often termed "rogue" APs) detected by UniFi APs on a specific site.

        Retrieves data from `/api/s/{site_name}/stat/rogueap`.
        This interacts with an **undocumented** private API endpoint (using POST),
        and the response structure may vary between controller versions.

        Args:
            site_name (str): The short name (ID) of the site to fetch neighboring APs from.
            within_hours (int): Look back duration in hours for discovered APs.
                                Defaults to 24.
            raw (bool): If True (default), returns the raw API response as a list of dictionaries.
                        If False, attempts to map the response to `UnifiRogueAp` dataclass objects.

        Returns:
            Union[List[Dict[str, Any]], List[UnifiRogueAp]]:
                If `raw=True` (default), returns a `List[Dict[str, Any]]` representing the direct
                JSON response data from the API.
                If `raw=False`, returns a `List[UnifiRogueAp]` mapping known fields.
                Undocumented or new fields from the API response are stored
                in the `_extra_fields` attribute (a `Dict[str, Any]`) on each
                `UnifiRogueAp` instance.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
            UnifiAuthenticationError: If authentication or re-authentication fails.

        Note:
            The API uses a POST request for this endpoint.
            To see APs explicitly marked as 'known rogue', use `get_known_rogueaps()`.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/rogueap"
        payload = {'within': within_hours}
        logger.info(
            f"Fetching neighboring APs (within {within_hours}h) for site '{site_name}' from {uri}")
        # This endpoint uses POST
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        if not raw:
            rogueaps = []
            for ap_data in raw_results:
                try:
                    model_fields, extra_fields = map_api_data_to_model(
                        ap_data, UnifiRogueAp
                    )
                    ap = UnifiRogueAp(**model_fields)
                    if hasattr(ap, '_extra_fields'):
                        ap._extra_fields = extra_fields
                    rogueaps.append(ap)
                except Exception as e:
                    logger.error(
                        f"Error creating UnifiRogueAp model from data: {ap_data}. Error: {e}"
                    )
            logger.debug(
                f"Returning {len(rogueaps)} mapped UnifiRogueAp objects.")
            return rogueaps
        else:
            logger.debug("Returning raw neighboring AP data.")
            return raw_results

    def get_unifi_site_networkconf(
        self, site_name: str, network_id: Optional[str] = None, raw: bool = True
    ) -> Union[List[Dict[str, Any]], List[UnifiNetworkConf]]:
        """
        Get network configurations (LANs, VLANs, VPNs, etc.) for a specific Unifi site.

        Retrieves network settings from `/api/s/{site_name}/rest/networkconf`.
        Can optionally fetch a single network configuration by its ID.
        This interacts with an **undocumented** private API endpoint, and the response
        structure may vary between controller versions.

        Args:
            site_name (str): The short name (ID) of the site to fetch network configurations from.
            network_id (Optional[str]): The _id of a specific network to fetch. If None (default),
                                        fetches all networks for the site.
            raw (bool): If True (default), returns the raw API response as a list of dictionaries.
                        If False, attempts to map the response to `UnifiNetworkConf` dataclass objects.

        Returns:
            Union[List[Dict[str, Any]], List[UnifiNetworkConf]]:
                If `raw=True` (default), returns a `List[Dict[str, Any]]` representing the direct
                JSON response data from the API.
                If `raw=False`, returns a `List[UnifiNetworkConf]` mapping known fields.
                Undocumented or new fields from the API response are stored
                in the `_extra_fields` attribute (a `Dict[str, Any]`) on each
                `UnifiNetworkConf` instance.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
            UnifiAuthenticationError: If authentication or re-authentication fails.
        """
        uri_suffix = f"/{network_id}" if network_id else ""
        uri = f"{self.controller_url}/api/s/{site_name}/rest/networkconf{uri_suffix}"
        log_msg = f"Fetching network configuration(s) for site '{site_name}'"
        if network_id:
            log_msg += f" (ID: {network_id})"
        log_msg += f" from {uri}"
        logger.info(log_msg)

        response = self.invoke_get_rest_api_call(uri)
        raw_results = self._process_api_response(response, uri)

        if not raw:
            networkconfs = []
            for conf_data in raw_results:
                try:
                    model_fields, extra_fields = map_api_data_to_model(
                        conf_data, UnifiNetworkConf
                    )
                    conf = UnifiNetworkConf(**model_fields)
                    if hasattr(conf, '_extra_fields'):
                        conf._extra_fields = extra_fields
                    networkconfs.append(conf)
                except Exception as e:
                    logger.error(
                        f"Error creating UnifiNetworkConf model from data: {conf_data}. Error: {e}"
                    )
            logger.debug(
                f"Returning {len(networkconfs)} mapped UnifiNetworkConf objects."
            )
            return networkconfs
        else:
            logger.debug("Returning raw network configuration data.")
            return raw_results

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

    def get_unifi_site_health(
        self, site_name, raw=True
    ) -> Union[List[Dict[str, Any]], UnifiHealth]:
        """
        Get detailed health information for a specific UniFi site.

        Uses the `/api/s/{site_name}/stat/health` endpoint which provides
        subsystem-level health data in a more lightweight format than the full site data.
        This interacts with an **undocumented** private API endpoint, and the response
        structure may vary between controller versions.

        Args:
            site_name (str): The name of the site to fetch health data for.
            raw (bool): If True (default), returns the raw API response as a list of dictionaries.
                        If False, attempts to map the response to a `UnifiHealth` object.

        Returns:
            Union[List[Dict[str, Any]], UnifiHealth]:
                If `raw=True` (default), returns a `List[Dict[str, Any]]` representing the direct
                JSON response data from the API, where each dictionary represents a subsystem.
                If `raw=False`, returns a `UnifiHealth` object containing
                a dictionary of `UnifiSubsystemHealth` objects keyed by subsystem name.
                Undocumented or new fields from the API response are stored
                in the `_extra_fields` attribute (a `Dict[str, Any]`) on each
                `UnifiSubsystemHealth` instance within the `subsystems` dictionary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiDataError: If the API response cannot be parsed.
            UnifiAuthenticationError: If authentication or re-authentication fails.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/health"
        logger.info(f"Fetching health data for site '{site_name}' from {uri}")
        response = self.invoke_get_rest_api_call(uri)
        raw_results = self._process_api_response(response, uri)

        if not raw:
            # Create a UnifiHealth object with subsystems
            health = UnifiHealth(site_name=site_name)

            for subsystem_data in raw_results:
                if 'subsystem' not in subsystem_data:
                    logger.warning(
                        f"Skipping health entry without 'subsystem' key: {subsystem_data}")
                    continue

                subsystem_name = subsystem_data['subsystem']
                # Map API data to the UnifiSubsystemHealth model
                model_fields, extra_fields = map_api_data_to_model(
                    subsystem_data, UnifiSubsystemHealth
                )

                try:
                    subsystem = UnifiSubsystemHealth(**model_fields)
                    if hasattr(subsystem, '_extra_fields'):
                        subsystem._extra_fields = extra_fields
                    health.subsystems[subsystem_name] = subsystem
                except Exception as e:
                    logger.error(
                        f"Error creating UnifiSubsystemHealth model from data: {subsystem_data}. Error: {e}")
            return health
        else:
            logger.debug("Returning raw health data.")
            return raw_results

    def get_unifi_site_portconf(
        self, site_name, raw=True
    ) -> Union[List[Dict[str, Any]], List[UnifiPortConf]]:
        """
        Get port profile configurations for a specific UniFi site.

        Retrieves port profiles (switch port settings templates) from
        `/api/s/{site_name}/rest/portconf`. These profiles define settings like
        operation mode, PoE, VLANs, STP, LLDP, etc., that can be applied to ports.
        This interacts with an **undocumented** private API endpoint, and the response
        structure may vary between controller versions.

        Args:
            site_name (str): The short name (ID) of the site to fetch port profiles from.
            raw (bool): If True (default), returns the raw API response as a list of dictionaries.
                        If False, attempts to map the response to `UnifiPortConf` dataclass objects.

        Returns:
            Union[List[Dict[str, Any]], List[UnifiPortConf]]:
                If `raw=True` (default), returns a `List[Dict[str, Any]]` representing the direct
                JSON response data from the API.
                If `raw=False`, returns a `List[UnifiPortConf]` mapping known fields.
                Undocumented or new fields from the API response are stored
                in the `_extra_fields` attribute (a `Dict[str, Any]`) on each
                `UnifiPortConf` instance.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
            UnifiAuthenticationError: If authentication or re-authentication fails.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/portconf"
        logger.info(
            f"Fetching port profiles for site '{site_name}' from {uri}")
        response = self.invoke_get_rest_api_call(uri)
        raw_results = self._process_api_response(response, uri)

        if not raw:
            port_confs = []
            for conf_data in raw_results:
                try:
                    model_fields, extra_fields = map_api_data_to_model(
                        conf_data, UnifiPortConf
                    )
                    conf = UnifiPortConf(**model_fields)
                    if hasattr(conf, '_extra_fields'):
                        conf._extra_fields = extra_fields
                    port_confs.append(conf)
                except Exception as e:
                    logger.error(
                        f"Error creating UnifiPortConf model from data: {conf_data}. Error: {e}")
            logger.debug(
                f"Returning {len(port_confs)} mapped UnifiPortConf objects.")
            return port_confs
        else:
            logger.debug("Returning raw port profile data.")
            return raw_results

    def authorize_client_guest(
        self,
        site_name: str,
        mac: str,
        minutes: int,
        up_kbps: Optional[int] = None,
        down_kbps: Optional[int] = None,
        megabytes: Optional[int] = None,
        ap_mac: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Authorize a client device (guest) using the `/cmd/stamgr` endpoint.

        Issues a command to grant network access to a guest client for a specified duration,
        optionally with bandwidth or data usage limits. This method interacts with an
        **undocumented** private API endpoint `/api/s/{site_name}/cmd/stamgr`.

        Args:
            site_name (str): The short name (ID) of the site.
            mac (str): Client MAC address to authorize.
            minutes (int): Duration in minutes until authorization expires.
            up_kbps (Optional[int]): Optional upload speed limit in Kbps.
            down_kbps (Optional[int]): Optional download speed limit in Kbps.
            megabytes (Optional[int]): Optional data transfer limit in Megabytes (MB).
                                       The API parameter name is 'bytes', but expects MB value.
            ap_mac (Optional[str]): Optional MAC address of the AP the client is connected to.
                                   Providing this might speed up authorization propagation.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries.
                                  The structure may vary between controller versions.
                                  Typically contains details of the authorized client if successful.
                                  Check the `meta` field in the full HTTP response (not directly
                                  returned here) for definitive success/failure confirmation.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/stamgr"
        payload = {
            'cmd': 'authorize-guest',
            'mac': self.normalize_mac(mac),
            'minutes': minutes
        }
        if up_kbps is not None:
            payload['up'] = up_kbps
        if down_kbps is not None:
            payload['down'] = down_kbps
        if megabytes is not None:
            payload['bytes'] = megabytes  # API uses 'bytes' for MB limit
        if ap_mac is not None:
            payload['ap_mac'] = self.normalize_mac(ap_mac)

        logger.info(f"Authorizing guest {mac} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define a UnifiAuthorizationResult dataclass and map raw_results.
        return raw_results

    def unauthorize_client_guest(self, site_name: str, mac: str) -> List[Dict[str, Any]]:
        """
        Unauthorize a client device (guest) using the `/cmd/stamgr` endpoint.

        Revokes network access previously granted via guest authorization.
        This interacts with an **undocumented** private API endpoint `/api/s/{site_name}/cmd/stamgr`.

        Args:
            site_name (str): The short name (ID) of the site.
            mac (str): Client MAC address to unauthorize.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries.
                                  Typically an empty list on success. Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/stamgr"
        payload = {
            'cmd': 'unauthorize-guest',
            'mac': self.normalize_mac(mac)
        }
        logger.info(f"Unauthorizing guest {mac} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult dataclass or similar and map raw_results.
        return raw_results

    def reconnect_client(self, site_name: str, mac: str) -> List[Dict[str, Any]]:
        """
        Reconnect (kick) a client device using the `/cmd/stamgr` endpoint.

        Forces a wireless client to disconnect and attempt to reconnect.
        This interacts with an **undocumented** private API endpoint `/api/s/{site_name}/cmd/stamgr`.

        Args:
            site_name (str): The short name (ID) of the site.
            mac (str): Client MAC address to reconnect.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries.
                                  Typically an empty list on success. Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/stamgr"
        payload = {
            'cmd': 'kick-sta',
            'mac': self.normalize_mac(mac)
        }
        logger.info(f"Reconnecting client {mac} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult dataclass or similar and map raw_results.
        return raw_results

    def block_client(self, site_name: str, mac: str) -> List[Dict[str, Any]]:
        """
        Block a client device using the `/cmd/stamgr` endpoint.

        Prevents a client device from associating with the network on this site.
        This interacts with an **undocumented** private API endpoint `/api/s/{site_name}/cmd/stamgr`.

        Args:
            site_name (str): The short name (ID) of the site.
            mac (str): Client MAC address to block.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries.
                                  Often contains the updated client object, reflecting
                                  the blocked status. Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/stamgr"
        payload = {
            'cmd': 'block-sta',
            'mac': self.normalize_mac(mac)
        }
        logger.info(f"Blocking client {mac} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Optionally map to UnifiClient if response contains full client data.
        # TODO: Otherwise define a UnifiBlockResult dataclass or similar.
        return raw_results

    def unblock_client(self, site_name: str, mac: str) -> List[Dict[str, Any]]:
        """
        Unblock a client device using the `/cmd/stamgr` endpoint.

        Removes a block previously placed on a client device for this site.
        This interacts with an **undocumented** private API endpoint `/api/s/{site_name}/cmd/stamgr`.

        Args:
            site_name (str): The short name (ID) of the site.
            mac (str): Client MAC address to unblock.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries.
                                  Often contains the updated client object. Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/stamgr"
        payload = {
            'cmd': 'unblock-sta',
            'mac': self.normalize_mac(mac)
        }
        logger.info(f"Unblocking client {mac} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Otherwise define a UnifiUnblockResult dataclass or similar.
        return raw_results

    def forget_client(self, site_name: str, macs: Union[str, List[str]]) -> List[Dict[str, Any]]:
        """
        Forget one or more client devices using the `/cmd/stamgr` endpoint.

        This command removes historical data (like connection logs, DPI stats)
        associated with the specified client(s).
        This interacts with an **undocumented** private API endpoint `/api/s/{site_name}/cmd/stamgr`.

        Args:
            site_name (str): The short name (ID) of the site.
            macs (Union[str, List[str]]): A single MAC address string or a list of
                                         MAC address strings to forget.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries.
                                  Typically an empty list on success. Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            This action is irreversible. It may take some time to complete on controllers
            with large datasets. Introduced around controller v5.9.X.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/stamgr"
        if isinstance(macs, str):
            mac_list = [self.normalize_mac(macs)]
        else:
            mac_list = [self.normalize_mac(m) for m in macs]

        payload = {
            'cmd': 'forget-sta',
            'macs': mac_list
        }
        logger.info(
            f"Forgetting client(s) {mac_list} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult dataclass or similar and map raw_results.
        return raw_results

    def create_client_user(
        self,
        site_name: str,
        mac: str,
        user_group_id: str,
        name: Optional[str] = None,
        note: Optional[str] = None,
        is_guest: Optional[bool] = None,
        is_wired: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """
        Create a new user/client-device entry using the `/group/user` endpoint.

        This method is typically used to define properties for known clients, often
        before they connect or when they are offline. It pre-populates the client
        record.
        This interacts with an **undocumented** private API endpoint `/api/s/{site_name}/group/user`.

        Args:
            site_name (str): The short name (ID) of the site.
            mac (str): Client MAC address.
            user_group_id (str): _id of the user group the client should belong to.
                                 Obtainable via `list_user_groups()`.
            name (Optional[str]): Optional name (alias) for the client.
            note (Optional[str]): Optional note for the client.
            is_guest (Optional[bool]): Optional flag indicating if the client is a guest.
            is_wired (Optional[bool]): Optional flag indicating if the client is wired.

        Returns:
            List[Dict[str, Any]]: Raw API response as a list of dictionaries, typically
                                  containing the created client object. Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/group/user"
        new_user_data = {
            'mac': self.normalize_mac(mac),
            'usergroup_id': user_group_id
        }
        if name is not None:
            new_user_data['name'] = name
        if note is not None:
            new_user_data['note'] = note
        if is_guest is not None:
            new_user_data['is_guest'] = is_guest
        if is_wired is not None:
            new_user_data['is_wired'] = is_wired

        # This endpoint expects the data wrapped in an 'objects' list
        payload = {'objects': [{'data': new_user_data}]}

        logger.info(
            f"Creating client user {mac} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClient dataclass and map raw_results.
        return raw_results

    def set_client_note(
        self, site_name: str, client_id: str, note: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Add, modify, or remove a note for a client device using its user ID.

        Uses the `/upd/user/{client_id}` endpoint (typically via POST).
        This interacts with an **undocumented** private API endpoint.

        Args:
            site_name (str): The short name (ID) of the site.
            client_id (str): The `_id` of the client device (obtainable from client lists
                             like `get_all_known_clients` or `get_unifi_site_client`).
            note (Optional[str]): The note text. An empty string or None removes the note.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries, often
                                  containing the updated client object. Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/upd/user/{client_id}"
        payload = {'note': note if note is not None else ""}

        action = "Setting" if note else "Removing"
        logger.info(
            f"{action} note for client {client_id} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClient dataclass and map raw_results.
        return raw_results

    def set_client_name(
        self, site_name: str, client_id: str, name: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Set or remove the name (alias) for a client device using its user ID.

        Uses the `/upd/user/{client_id}` endpoint (typically via POST).
        For the REST equivalent, see `set_client_name_rest`.
        This interacts with an **undocumented** private API endpoint.

        Args:
            site_name (str): The short name (ID) of the site.
            client_id (str): The `_id` of the client device.
            name (Optional[str]): The name for the client. An empty string or None removes
                                 the name.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries, often
                                  containing the updated client object. Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/upd/user/{client_id}"
        payload = {'name': name if name is not None else ""}

        action = "Setting" if name else "Removing"
        logger.info(
            f"{action} name for client {client_id} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClient dataclass and map raw_results.
        return raw_results

    def get_client_details(self, site_name: str, mac: str) -> List[Dict[str, Any]]:
        """
        Fetch details for a single client device by MAC address.

        Uses the `/stat/user/{mac}` endpoint.
        This interacts with an **undocumented** private API endpoint.

        Args:
            site_name (str): The short name (ID) of the site.
            mac (str): Client MAC address.

        Returns:
            List[Dict[str, Any]]: Raw API response as a list of dictionaries, typically
                                  containing a single client object with details.
                                  Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/user/{self.normalize_mac(mac)}"
        logger.info(
            f"Fetching details for client {mac} on site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)  # Uses GET helper
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClient dataclass and map raw_results.
        return raw_results

    def assign_client_to_group(self, site_name: str, client_id: str, group_id: str) -> List[Dict[str, Any]]:
        """
        Assign a client device to a different user group.

        Uses the `/upd/user/{client_id}` endpoint (typically via POST).
        This interacts with an **undocumented** private API endpoint.

        Args:
            site_name (str): The short name (ID) of the site.
            client_id (str): The `_id` of the client device.
            group_id (str): The `_id` of the target user group.
                           Obtainable via `list_user_groups()`.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries, often
                                  containing the updated client object. Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/upd/user/{client_id}"
        payload = {'usergroup_id': group_id}
        logger.info(
            f"Assigning client {client_id} to group {group_id} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClient dataclass and map raw_results.
        return raw_results

    def set_client_fixed_ip(
        self,
        site_name: str,
        client_id: str,
        use_fixed_ip: bool,
        network_id: Optional[str] = None,
        fixed_ip: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Enable/disable or modify a client's fixed IP address using the REST endpoint.

        Updates client settings via `PUT /api/s/{site_name}/rest/user/{client_id}`.
        This interacts with an **undocumented** private API endpoint.

        Args:
            site_name (str): The short name (ID) of the site.
            client_id (str): The `_id` of the client device.
            use_fixed_ip (bool): True to enable and set a fixed IP, False to disable.
            network_id (Optional[str]): Required if `use_fixed_ip` is True. The `_id` of
                                        the network (subnet) for the fixed IP.
                                        Obtainable via `get_unifi_site_networkconf()`.
            fixed_ip (Optional[str]): Required if `use_fixed_ip` is True. The desired
                                     fixed IP address string (e.g., "192.168.1.100").

        Returns:
            List[Dict[str, Any]]: Raw API response as a list of dictionaries, typically
                                  containing the updated client object. Structure may vary.

        Raises:
            ValueError: If `use_fixed_ip` is True but `network_id` or `fixed_ip` is missing.
            UnifiAPIError: If the API request fails.
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/user/{client_id}"
        payload = {
            # '_id': client_id, # Usually not needed in payload for PUT to specific ID URL
            'use_fixedip': use_fixed_ip,
        }

        if use_fixed_ip:
            if not network_id or not fixed_ip:
                raise ValueError(
                    "network_id and fixed_ip are required when use_fixed_ip is True.")
            payload['network_id'] = network_id
            payload['fixed_ip'] = fixed_ip

        logger.info(
            f"Setting fixed IP status ({use_fixed_ip}) for client {client_id} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="PUT", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClient dataclass and map raw_results.
        return raw_results

    def set_client_name_rest(
        self, site_name: str, client_id: str, name: str
    ) -> List[Dict[str, Any]]:
        """
        Update a client device's name (alias) using the REST endpoint.

        Updates client settings via `PUT /api/s/{site_name}/rest/user/{client_id}`.
        Use this instead of `set_client_name` for REST-based updates.

        Args:
            site_name (str): The short name (ID) of the site.
            client_id (str): The `_id` of the client device.
            name (str): The new name for the client. Cannot be empty.

        Returns:
            List[Dict[str, Any]]: Raw API response as a list of dictionaries, typically
                                  containing the updated client object. Structure may vary.

        Raises:
            ValueError: If name is empty.
            UnifiAPIError: If the API request fails.
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.
        """
        if not name:
            raise ValueError("Client name cannot be empty.")

        uri = f"{self.controller_url}/api/s/{site_name}/rest/user/{client_id}"
        payload = {
            # '_id': client_id,
            'name': name,
        }

        logger.info(
            f"Setting REST name for client {client_id} to '{name}' on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="PUT", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClient dataclass and map raw_results.
        return raw_results

    # --- User Group Management (Raw API) ---

    def list_user_groups(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch user groups configured for the site using the `/list/usergroup` endpoint.

        User groups define bandwidth limits that can be applied to clients.
        This interacts with an **undocumented** private API endpoint `/api/s/{site_name}/list/usergroup`.
        Response structure may vary between controller versions.

        Args:
            site_name (str): The short name (ID) of the site.

        Returns:
            List[Dict[str, Any]]: Raw API response as a list of dictionaries, where each
                                  dictionary represents a user group object. Known keys include:
                                  `_id` (str), `name` (str), `site_id` (str),
                                  `qos_rate_max_down` (int, Kbps, -1=unlimited),
                                  `qos_rate_max_up` (int, Kbps, -1=unlimited).
                                  Actual structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            Consider using a dataclass like `UnifiUserGroup` to represent the returned objects
            for better type safety and clarity in future development.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/list/usergroup"
        logger.info(f"Listing user groups for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiUserGroup dataclass and map raw_results.
        return raw_results

    def create_user_group(
        self,
        site_name: str,
        name: str,
        qos_rate_max_down_kbps: int = -1,
        qos_rate_max_up_kbps: int = -1
    ) -> List[Dict[str, Any]]:
        """
        Create a new user group using the REST endpoint `/rest/usergroup`.

        User groups define bandwidth limits that can be applied to clients.
        This interacts with an **undocumented** private API endpoint `/api/s/{site_name}/rest/usergroup`.
        Response structure may vary between controller versions.

        Args:
            site_name (str): The short name (ID) of the site.
            name (str): Name for the new user group. Must be unique within the site.
            qos_rate_max_down_kbps (int): Download bandwidth limit in Kilobits per second (Kbps).
                                          Use -1 for unlimited. Defaults to -1.
            qos_rate_max_up_kbps (int): Upload bandwidth limit in Kilobits per second (Kbps).
                                        Use -1 for unlimited. Defaults to -1.

        Returns:
            List[Dict[str, Any]]: Raw API response as a list of dictionaries, typically
                                  containing the newly created user group object with its assigned `_id`.
                                  Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., name conflict, invalid params, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            Consider using a dataclass like `UnifiUserGroup` to represent the returned object
            for better type safety and clarity in future development.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/usergroup"
        payload = {
            'name': name,
            'qos_rate_max_down': qos_rate_max_down_kbps,
            'qos_rate_max_up': qos_rate_max_up_kbps,
        }
        logger.info(
            f"Creating user group '{name}' on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiUserGroup dataclass and map raw_results.
        return raw_results

    def edit_user_group(
        self,
        site_name: str,
        group_id: str,
        name: Optional[str] = None,
        qos_rate_max_down_kbps: Optional[int] = None,
        qos_rate_max_up_kbps: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Modify an existing user group using the REST endpoint `PUT /rest/usergroup/{group_id}`.

        Only provide parameters for the fields you want to change. Unspecified parameters
        will retain their current values on the controller (unless the API requires all fields
        on PUT, which might be the case).
        This interacts with an **undocumented** private API endpoint. Response structure may vary.

        Args:
            site_name (str): The short name (ID) of the site.
            group_id (str): The `_id` of the user group to modify.
            name (Optional[str]): New name for the user group. Defaults to None (no change).
                                  Must be unique within the site if provided.
            qos_rate_max_down_kbps (Optional[int]): New download bandwidth limit in Kbps.
                                                   Use -1 for unlimited. Defaults to None (no change).
            qos_rate_max_up_kbps (Optional[int]): New upload bandwidth limit in Kbps.
                                                  Use -1 for unlimited. Defaults to None (no change).

        Returns:
            List[Dict[str, Any]]: Raw API response as a list of dictionaries, typically
                                  containing the updated user group object. Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., invalid group_id, name conflict, network issue).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            Consider using a dataclass like `UnifiUserGroup` to represent the returned object
            for better type safety and clarity in future development. Behaviour when no
            optional arguments are provided is untested (might be a no-op or error).
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/usergroup/{group_id}"
        payload = {}
        if name is not None:
            payload['name'] = name
        if qos_rate_max_down_kbps is not None:
            payload['qos_rate_max_down'] = qos_rate_max_down_kbps
        if qos_rate_max_up_kbps is not None:
            payload['qos_rate_max_up'] = qos_rate_max_up_kbps

        if not payload:
            logger.warning(
                f"Edit user group called for {group_id} with no changes specified.")
            # Optionally return early or raise error if no changes are specified
            # For now, proceed with empty payload PUT (might be no-op or error on controller)

        logger.info(
            f"Editing user group {group_id} on site {site_name} with payload: {payload} via {uri}")
        response = self._invoke_api_call(
            method="PUT", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiUserGroup dataclass and map raw_results.
        return raw_results

    def delete_user_group(self, site_name: str, group_id: str) -> List[Dict[str, Any]]:
        """
        Delete a user group using the REST endpoint `DELETE /rest/usergroup/{group_id}`.

        This interacts with an **undocumented** private API endpoint. Response structure may vary.
        You cannot delete the default 'Automatic' group. Attempting to delete a group that is
        currently assigned to clients might fail or have unintended consequences.

        Args:
            site_name (str): The short name (ID) of the site.
            group_id (str): The `_id` of the user group to delete.

        Returns:
            List[Dict[str, Any]]: Raw API response as a list of dictionaries, typically
                                  an empty list on success. Structure may vary.

        Raises:
            UnifiAPIError: If the API request fails (e.g., group not found, deletion forbidden, network issue).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            Consider using a dataclass like `UnifiOperationResult` or similar to represent the
            outcome, rather than relying on the raw list structure.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/usergroup/{group_id}"
        logger.info(
            f"Deleting user group {group_id} on site {site_name} via {uri}")
        response = self._invoke_api_call(method="DELETE", url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult dataclass or similar and map raw_results.
        return raw_results

    def _get_stats(
        self,
        endpoint_suffix: str,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        attributes: Optional[List[str]] = None,
        extra_payload: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """
        Internal helper to fetch time-series statistics via POST requests.

        Constructs a request to `/api/s/{site_name}/stat/report/{endpoint_suffix}`.
        This interacts with **undocumented** private API endpoints.

        Args:
            endpoint_suffix (str): The specific stats endpoint suffix (e.g., '5minutes.site').
            site_name (str): The short name (ID) of the site.
            start_ms (Optional[int]): Optional start time (Unix timestamp in milliseconds).
            end_ms (Optional[int]): Optional end time (Unix timestamp in milliseconds).
            attributes (Optional[List[str]]): Optional list of specific attributes ('attrs')
                                             to request in the payload. 'time' is added if
                                             not present.
            extra_payload (Optional[Dict[str, Any]]): Optional additional key-value pairs
                                                     to include in the JSON payload.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries.
                                  The structure can vary between controller versions and
                                  specific endpoints.

        Raises:
            UnifiAPIError: If the API request fails.
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed or lacks 'data'.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/report/{endpoint_suffix}"
        payload: Dict[str, Any] = {
            'start': start_ms,
            'end': end_ms
        }
        if attributes:
            # Ensure 'time' is always included if specific attributes are requested
            if 'time' not in attributes:
                attributes.append('time')
            payload['attrs'] = attributes

        if extra_payload:
            payload.update(extra_payload)

        logger.info(
            f"Fetching stats from {endpoint_suffix} for site {site_name} via {uri}")
        # Stats endpoints typically use POST even for retrieval
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        return self._process_api_response(response, uri)

    def get_site_stats_5minutes(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch 5-minute interval site statistics.

        Uses the **undocumented** endpoint `/api/s/{site_name}/stat/report/5minutes.site`.
        Defaults to fetching data for the past 12 hours if start/end times are not specified.
        Response structure may vary between controller versions. Requires statistics retention
        to be enabled on the controller for the desired period.

        Args:
            site_name (str): The short name (ID) of the site.
            start_ms (Optional[int]): Optional start time (Unix timestamp in milliseconds).
                                     Defaults to 12 hours before `end_ms`.
            end_ms (Optional[int]): Optional end time (Unix timestamp in milliseconds).
                                   Defaults to the current time.
            attributes (Optional[List[str]]): Optional list of specific attributes to retrieve.
                                             If None, defaults are used (similar to PHP client):
                                             ['bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes',
                                             'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time'].
                                             'time' is always included if attributes are specified.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries, where each
                                  dictionary represents a 5-minute statistics interval.
                                  Keys correspond to the requested `attributes`.
                                  The `time` field is a Unix timestamp in milliseconds.
                                  Byte counts are typically cumulative within the interval.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            Consider creating a `UnifiSiteStats5Min` dataclass to model the response objects.
        """
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - (12 * 3600 * 1000)  # Default 12 hours

        if attributes is None:
            attributes = [
                'bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes',
                'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time'
            ]

        raw_results = self._get_stats(
            "5minutes.site", site_name, start_ms, end_ms, attributes
        )
        # TODO: Define UnifiSiteStats5Min dataclass and map raw_results.
        return raw_results

    def get_site_stats_hourly(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch hourly interval site statistics.

        Uses the **undocumented** endpoint `/api/s/{site_name}/stat/report/hourly.site`.
        Defaults to fetching data for the past 7 days if start/end times are not specified.
        Response structure may vary between controller versions. Requires statistics retention
        to be enabled on the controller for the desired period.

        Args:
            site_name (str): The short name (ID) of the site.
            start_ms (Optional[int]): Optional start time (Unix timestamp in milliseconds).
                                     Defaults to 7 days before `end_ms`.
            end_ms (Optional[int]): Optional end time (Unix timestamp in milliseconds).
                                   Defaults to the current time.
            attributes (Optional[List[str]]): Optional list of specific attributes to retrieve.
                                             If None, defaults are used (similar to PHP client):
                                             ['bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes',
                                             'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time'].
                                             'time' is always included if attributes are specified.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries, where each
                                  dictionary represents an hourly statistics interval.
                                  Keys correspond to the requested `attributes`.
                                  The `time` field is a Unix timestamp in milliseconds.
                                  Byte counts are typically cumulative within the interval.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            Consider creating a `UnifiSiteStatsHourly` dataclass to model the response objects.
        """
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - (7 * 24 * 3600 * 1000)  # Default 7 days

        if attributes is None:
            attributes = [
                'bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes',
                'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time'
            ]

        raw_results = self._get_stats(
            "hourly.site", site_name, start_ms, end_ms, attributes
        )
        # TODO: Define UnifiSiteStatsHourly dataclass and map raw_results.
        return raw_results

    def get_site_stats_daily(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch daily interval site statistics.

        Uses the **undocumented** endpoint `/api/s/{site_name}/stat/report/daily.site`.
        Defaults to fetching data for the past 52 weeks if start/end times are not specified.
        Response structure may vary between controller versions. Requires statistics retention
        to be enabled on the controller for the desired period.

        Args:
            site_name (str): The short name (ID) of the site.
            start_ms (Optional[int]): Optional start time (Unix timestamp in milliseconds).
                                     Defaults to 52 weeks before `end_ms`.
            end_ms (Optional[int]): Optional end time (Unix timestamp in milliseconds).
                                   Defaults to the start of the current hour.
            attributes (Optional[List[str]]): Optional list of specific attributes to retrieve.
                                             If None, defaults are used (similar to PHP client):
                                             ['bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes',
                                             'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time'].
                                             'time' is always included if attributes are specified.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries, where each
                                  dictionary represents a daily statistics interval.
                                  Keys correspond to the requested `attributes`.
                                  The `time` field is a Unix timestamp in milliseconds.
                                  Byte counts are typically cumulative within the interval.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            Consider creating a `UnifiSiteStatsDaily` dataclass to model the response objects.
            Default `end_ms` is the start of the current hour, not current time.
        """
        if end_ms is None:
            # Default to start of current hour for daily/monthly stats
            end_ms = int((time.time() // 3600) * 3600 * 1000)
        if start_ms is None:
            start_ms = end_ms - (52 * 7 * 24 * 3600 * 1000)

        if attributes is None:
            attributes = [
                'bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes',
                'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time'
            ]

        raw_results = self._get_stats(
            "daily.site", site_name, start_ms, end_ms, attributes
        )
        # TODO: Define UnifiSiteStatsDaily dataclass and map raw_results.
        return raw_results

    def get_site_stats_monthly(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch monthly interval site statistics.

        Uses the **undocumented** endpoint `/api/s/{site_name}/stat/report/monthly.site`.
        Defaults to fetching data for the past 52 weeks if start/end times are not specified.
        Response structure may vary between controller versions. Requires statistics retention
        to be enabled on the controller for the desired period.

        Args:
            site_name (str): The short name (ID) of the site.
            start_ms (Optional[int]): Optional start time (Unix timestamp in milliseconds).
                                     Defaults to 52 weeks before `end_ms`.
            end_ms (Optional[int]): Optional end time (Unix timestamp in milliseconds).
                                   Defaults to the start of the current hour.
            attributes (Optional[List[str]]): Optional list of specific attributes to retrieve.
                                             If None, defaults are used (similar to PHP client):
                                             ['bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes',
                                             'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time'].
                                             'time' is always included if attributes are specified.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries, where each
                                  dictionary represents a monthly statistics interval.
                                  Keys correspond to the requested `attributes`.
                                  The `time` field is a Unix timestamp in milliseconds.
                                  Byte counts are typically cumulative within the interval.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            Consider creating a `UnifiSiteStatsMonthly` dataclass to model the response objects.
            Default `end_ms` is the start of the current hour, not current time.
            The default time range (52 weeks) might overlap with the daily stats default.
        """
        # Same default range as daily in PHP lib
        if end_ms is None:
            end_ms = int((time.time() // 3600) * 3600 * 1000)
        if start_ms is None:
            start_ms = end_ms - (52 * 7 * 24 * 3600 * 1000)

        if attributes is None:
            attributes = [
                'bytes', 'wan-tx_bytes', 'wan-rx_bytes', 'wlan_bytes',
                'num_sta', 'lan-num_sta', 'wlan-num_sta', 'time'
            ]

        raw_results = self._get_stats(
            "monthly.site", site_name, start_ms, end_ms, attributes
        )
        # TODO: Define UnifiSiteStatsMonthly dataclass and map raw_results.
        return raw_results

    def get_aps_stats_5minutes(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        mac: Optional[str] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch 5-minute stats for one or all access points.

        Uses the **undocumented** endpoint `/api/s/{site_name}/stat/report/5minutes.ap`.
        Defaults to fetching data for the past 12 hours if start/end times are not specified.
        Response structure may vary between controller versions. Requires statistics retention
        to be enabled on the controller for the desired period.

        Args:
            site_name (str): The short name (ID) of the site.
            start_ms (Optional[int]): Optional start time (Unix timestamp in milliseconds).
                                     Defaults to 12 hours before `end_ms`.
            end_ms (Optional[int]): Optional end time (Unix timestamp in milliseconds).
                                   Defaults to the current time.
            mac (Optional[str]): Optional AP MAC address to filter results by. If None,
                                 fetches stats for all APs on the site.
            attributes (Optional[List[str]]): Optional list of specific attributes to retrieve.
                                             If None, defaults to ['bytes', 'num_sta', 'time'].
                                             'time' is always included if attributes are specified.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries, where each
                                  dictionary represents a 5-minute AP statistics interval.
                                  Keys include the requested `attributes` and usually `mac`.
                                  The `time` field is a Unix timestamp in milliseconds.
                                  Byte/client counts are typically cumulative within the interval.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            Consider creating a `UnifiApStats5Min` dataclass to model the response objects.
        """
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - (12 * 3600 * 1000)

        if attributes is None:
            attributes = ['bytes', 'num_sta', 'time']

        extra_payload = {}
        if mac:
            extra_payload['mac'] = self.normalize_mac(mac)

        raw_results = self._get_stats(
            "5minutes.ap", site_name, start_ms, end_ms, attributes, extra_payload
        )
        # TODO: Define UnifiApStats5Min dataclass and map raw_results.
        return raw_results

    def get_aps_stats_hourly(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        mac: Optional[str] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch hourly stats for one or all access points.

        Uses the **undocumented** endpoint `/api/s/{site_name}/stat/report/hourly.ap`.
        Defaults to fetching data for the past 7 days if start/end times are not specified.
        Response structure may vary between controller versions. Requires statistics retention
        to be enabled on the controller for the desired period.

        Args:
            site_name (str): The short name (ID) of the site.
            start_ms (Optional[int]): Optional start time (Unix timestamp in milliseconds).
                                     Defaults to 7 days before `end_ms`.
            end_ms (Optional[int]): Optional end time (Unix timestamp in milliseconds).
                                   Defaults to the current time.
            mac (Optional[str]): Optional AP MAC address to filter results by. If None,
                                 fetches stats for all APs on the site.
            attributes (Optional[List[str]]): Optional list of specific attributes to retrieve.
                                             If None, defaults to ['bytes', 'num_sta', 'time'].
                                             'time' is always included if attributes are specified.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries, where each
                                  dictionary represents an hourly AP statistics interval.
                                  Keys include the requested `attributes` and usually `mac`.
                                  The `time` field is a Unix timestamp in milliseconds.
                                  Byte/client counts are typically cumulative within the interval.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            Consider creating a `UnifiApStatsHourly` dataclass to model the response objects.
        """
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - (7 * 24 * 3600 * 1000)

        if attributes is None:
            attributes = ['bytes', 'num_sta', 'time']

        extra_payload = {}
        if mac:
            extra_payload['mac'] = self.normalize_mac(mac)

        raw_results = self._get_stats(
            "hourly.ap", site_name, start_ms, end_ms, attributes, extra_payload
        )
        # TODO: Define UnifiApStatsHourly dataclass and map raw_results.
        return raw_results

    def get_aps_stats_daily(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        mac: Optional[str] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch daily stats for one or all access points.

        Uses the **undocumented** endpoint `/api/s/{site_name}/stat/report/daily.ap`.
        Defaults to fetching data for the past 52 weeks if start/end times are not specified.
        Response structure may vary between controller versions. Requires statistics retention
        to be enabled on the controller for the desired period.

        Args:
            site_name (str): The short name (ID) of the site.
            start_ms (Optional[int]): Optional start time (Unix timestamp in milliseconds).
                                     Defaults to 52 weeks before `end_ms`.
            end_ms (Optional[int]): Optional end time (Unix timestamp in milliseconds).
                                   Defaults to the start of the current hour.
            mac (Optional[str]): Optional AP MAC address to filter results by. If None,
                                 fetches stats for all APs on the site.
            attributes (Optional[List[str]]): Optional list of specific attributes to retrieve.
                                             If None, defaults to ['bytes', 'num_sta', 'time'].
                                             'time' is always included if attributes are specified.

        Returns:
            List[Dict[str, Any]]: Raw API response data as a list of dictionaries, where each
                                  dictionary represents a daily AP statistics interval.
                                  Keys include the requested `attributes` and usually `mac`.
                                  The `time` field is a Unix timestamp in milliseconds.
                                  Byte/client counts are typically cumulative within the interval.

        Raises:
            UnifiAPIError: If the API request fails (e.g., network issue, 4xx/5xx error).
            UnifiAuthenticationError: If authentication or re-authentication fails.
            UnifiDataError: If the API response cannot be parsed as valid JSON or lacks
                           the expected 'data' field.

        Note:
            Consider creating a `UnifiApStatsDaily` dataclass to model the response objects.
            Default `end_ms` is the start of the current hour.
            The PHP library comment indicated default time range was 7 days, but the code used 52 weeks;
            this implementation follows the 52-week default for daily AP stats, matching site daily stats.
        """
        # Matches PHP lib default range
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - (52 * 7 * 24 * 3600 * 1000)

        if attributes is None:
            attributes = ['rx_bytes', 'tx_bytes', 'time']

        extra_payload = {}
        if mac:
            extra_payload['mac'] = self.normalize_mac(mac)

        raw_results = self._get_stats(
            "hourly.user", site_name, start_ms, end_ms, attributes, extra_payload
        )
        # TODO: Define UnifiClientStatsHourly dataclass and map raw_results.
        return raw_results

    def get_client_stats_daily(
        self,
        site_name: str,
        mac: Optional[str] = None,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch daily stats for a specific client device (or potentially all if mac is None).
        Defaults to the past 7 days if start/end are not specified (matching PHP lib).
        Requires enabling "Clients Historical Data" in controller settings.

        Args:
            site_name: The short name (ID) of the site.
            mac: Optional client MAC address.
            start_ms: Optional start time (Unix timestamp in milliseconds).
            end_ms: Optional end time (Unix timestamp in milliseconds).
            attributes: Optional list of specific attributes. Defaults: ['rx_bytes', 'tx_bytes', 'time'].

        Returns:
            Raw API response: A list of daily client stat objects.
        """
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - (7 * 24 * 3600 * 1000)

        if attributes is None:
            attributes = ['rx_bytes', 'tx_bytes', 'time']

        extra_payload = {}
        if mac:
            extra_payload['mac'] = self.normalize_mac(mac)

        raw_results = self._get_stats(
            "daily.user", site_name, start_ms, end_ms, attributes, extra_payload
        )
        # TODO: Define UnifiClientStatsDaily dataclass and map raw_results.
        return raw_results

    def get_client_stats_monthly(
        self,
        site_name: str,
        mac: Optional[str] = None,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch monthly stats for a specific client device (or potentially all if mac is None).
        Defaults to the past 13 weeks if start/end are not specified.
        Requires enabling "Clients Historical Data" in controller settings.

        Args:
            site_name: The short name (ID) of the site.
            mac: Optional client MAC address.
            start_ms: Optional start time (Unix timestamp in milliseconds).
            end_ms: Optional end time (Unix timestamp in milliseconds).
            attributes: Optional list of specific attributes. Defaults: ['rx_bytes', 'tx_bytes', 'time'].

        Returns:
            Raw API response: A list of monthly client stat objects.
        """
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - (13 * 7 * 24 * 3600 * 1000)  # Default 13 weeks

        if attributes is None:
            attributes = ['rx_bytes', 'tx_bytes', 'time']

        extra_payload = {}
        if mac:
            extra_payload['mac'] = self.normalize_mac(mac)

        raw_results = self._get_stats(
            "monthly.user", site_name, start_ms, end_ms, attributes, extra_payload
        )
        # TODO: Define UnifiClientStatsMonthly dataclass and map raw_results.
        return raw_results

    def get_gateway_stats_5minutes(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch 5-minute interval gateway statistics.
        Requires a UniFi gateway device on the site.
        Defaults to the past 12 hours if start/end are not specified.

        Args:
            site_name: The short name (ID) of the site.
            start_ms: Optional start time (Unix timestamp in milliseconds).
            end_ms: Optional end time (Unix timestamp in milliseconds).
            attributes: Optional list of specific attributes.
                        Defaults: ['time', 'mem', 'cpu', 'loadavg_5'].

        Returns:
            Raw API response: A list of 5-minute gateway stat objects.
        """
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - (12 * 3600 * 1000)

        if attributes is None:
            attributes = ['time', 'mem', 'cpu', 'loadavg_5']

        raw_results = self._get_stats(
            "5minutes.gw", site_name, start_ms, end_ms, attributes
        )
        # TODO: Define UnifiGatewayStats5Min dataclass and map raw_results.
        return raw_results

    def get_gateway_stats_hourly(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch hourly interval gateway statistics.
        Requires a UniFi gateway device on the site.
        Defaults to the past 7 days if start/end are not specified.

        Args:
            site_name: The short name (ID) of the site.
            start_ms: Optional start time (Unix timestamp in milliseconds).
            end_ms: Optional end time (Unix timestamp in milliseconds).
            attributes: Optional list of specific attributes.
                        Defaults: ['time', 'mem', 'cpu', 'loadavg_5'].

        Returns:
            Raw API response: A list of hourly gateway stat objects.
        """
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - (7 * 24 * 3600 * 1000)

        if attributes is None:
            attributes = ['time', 'mem', 'cpu', 'loadavg_5']

        raw_results = self._get_stats(
            "hourly.gw", site_name, start_ms, end_ms, attributes
        )
        # TODO: Define UnifiGatewayStatsHourly dataclass and map raw_results.
        return raw_results

    def get_gateway_stats_daily(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch daily interval gateway statistics.
        Requires a UniFi gateway device on the site.
        Defaults to the past 52 weeks if start/end are not specified.

        Args:
            site_name: The short name (ID) of the site.
            start_ms: Optional start time (Unix timestamp in milliseconds).
            end_ms: Optional end time (Unix timestamp in milliseconds).
            attributes: Optional list of specific attributes.
                        Defaults: ['time', 'mem', 'cpu', 'loadavg_5'].

        Returns:
            Raw API response: A list of daily gateway stat objects.
        """
        if end_ms is None:
            end_ms = int((time.time() // 3600) * 3600 * 1000)
        if start_ms is None:
            start_ms = end_ms - (52 * 7 * 24 * 3600 * 1000)

        if attributes is None:
            attributes = ['time', 'mem', 'cpu', 'loadavg_5']

        raw_results = self._get_stats(
            "daily.gw", site_name, start_ms, end_ms, attributes
        )
        # TODO: Define UnifiGatewayStatsDaily dataclass and map raw_results.
        return raw_results

    def get_gateway_stats_monthly(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        attributes: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch monthly interval gateway statistics.
        Requires a UniFi gateway device on the site.
        Defaults to the past 52 weeks if start/end are not specified.

        Args:
            site_name: The short name (ID) of the site.
            start_ms: Optional start time (Unix timestamp in milliseconds).
            end_ms: Optional end time (Unix timestamp in milliseconds).
            attributes: Optional list of specific attributes.
                        Defaults: ['time', 'mem', 'cpu', 'loadavg_5'].

        Returns:
            Raw API response: A list of monthly gateway stat objects.
        """
        if end_ms is None:
            end_ms = int((time.time() // 3600) * 3600 * 1000)
        if start_ms is None:
            start_ms = end_ms - (52 * 7 * 24 * 3600 * 1000)

        if attributes is None:
            attributes = ['time', 'mem', 'cpu', 'loadavg_5']

        raw_results = self._get_stats(
            "monthly.gw", site_name, start_ms, end_ms, attributes
        )
        # TODO: Define UnifiGatewayStatsMonthly dataclass and map raw_results.
        return raw_results

    def get_speedtest_results(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch speed test results.
        Requires a UniFi gateway device on the site.
        Defaults to the past 24 hours if start/end are not specified.

        Args:
            site_name: The short name (ID) of the site.
            start_ms: Optional start time (Unix timestamp in milliseconds).
            end_ms: Optional end time (Unix timestamp in milliseconds).

        Returns:
            Raw API response: A list of speed test result objects.
        """
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - (24 * 3600 * 1000)

        # Attributes are fixed for this endpoint according to PHP lib
        attributes = ['xput_download', 'xput_upload', 'latency', 'time']

        raw_results = self._get_stats(
            "archive.speedtest", site_name, start_ms, end_ms, attributes
        )
        # TODO: Define UnifiSpeedTestResult dataclass and map raw_results.
        return raw_results

    def get_ips_events(
        self,
        site_name: str,
        start_ms: Optional[int] = None,
        end_ms: Optional[int] = None,
        limit: int = 10000
    ) -> List[Dict[str, Any]]:
        """
        Fetch IPS/IDS threat events.
        Requires a UniFi gateway device with IPS/IDS enabled.
        Defaults to the past 24 hours if start/end are not specified.

        Args:
            site_name: The short name (ID) of the site.
            start_ms: Optional start time (Unix timestamp in milliseconds).
            end_ms: Optional end time (Unix timestamp in milliseconds).
            limit: Maximum number of events to return (default 10000).

        Returns:
            Raw API response: A list of IPS event objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/ips/event"
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - (24 * 3600 * 1000)

        payload = {
            'start': start_ms,
            'end': end_ms,
            '_limit': limit
        }

        logger.info(f"Fetching IPS events for site {site_name} via {uri}")
        # Uses POST according to PHP lib
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiIpsEvent dataclass and map raw_results.
        return raw_results

    def get_client_sessions(
        self,
        site_name: str,
        start_s: Optional[int] = None,
        end_s: Optional[int] = None,
        mac: Optional[str] = None,
        client_type: str = 'all'  # 'all', 'guest', 'user'
    ) -> List[Dict[str, Any]]:
        """
        Fetch client login sessions.
        Defaults to the past 7 days if start/end are not specified.

        Args:
            site_name: The short name (ID) of the site.
            start_s: Optional start time (Unix timestamp in seconds).
            end_s: Optional end time (Unix timestamp in seconds).
            mac: Optional client MAC address to filter by.
            client_type: Type of client ('all', 'guest', 'user'). Default 'all'.

        Returns:
            Raw API response: A list of session objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/session"
        if client_type not in ['all', 'guest', 'user']:
            raise ValueError("client_type must be 'all', 'guest', or 'user'")

        if end_s is None:
            end_s = int(time.time())
        if start_s is None:
            start_s = end_s - (7 * 24 * 3600)  # Default 7 days

        payload = {
            'type': client_type,
            'start': start_s,
            'end': end_s
        }
        if mac:
            payload['mac'] = self.normalize_mac(mac)

        logger.info(
            f"Fetching client sessions ({client_type}) for site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClientSession dataclass and map raw_results.
        return raw_results

    def get_client_sessions_latest(
        self,
        site_name: str,
        mac: str,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Fetch the latest 'n' login sessions for a specific client device.

        Args:
            site_name: The short name (ID) of the site.
            mac: Client MAC address (required).
            limit: Maximum number of sessions to retrieve (default 5).

        Returns:
            Raw API response: A list of the latest session objects for the client.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/session"
        payload = {
            'mac': self.normalize_mac(mac),
            '_limit': limit,
            '_sort': '-assoc_time'  # Sort descending by association time
        }
        logger.info(
            f"Fetching latest {limit} sessions for client {mac} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClientSession dataclass and map raw_results.
        return raw_results

    def get_authorizations(
        self,
        site_name: str,
        start_s: Optional[int] = None,
        end_s: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch client authorizations (e.g., guest portal logins).
        Defaults to the past 7 days if start/end are not specified.

        Args:
            site_name: The short name (ID) of the site.
            start_s: Optional start time (Unix timestamp in seconds).
            end_s: Optional end time (Unix timestamp in seconds).

        Returns:
            Raw API response: A list of authorization objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/authorization"
        if end_s is None:
            end_s = int(time.time())
        if start_s is None:
            start_s = end_s - (7 * 24 * 3600)  # Default 7 days

        payload = {
            'start': start_s,
            'end': end_s
        }
        logger.info(f"Fetching authorizations for site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClientAuthorization dataclass and map raw_results.
        return raw_results

    def get_all_clients_history(
        self,
        site_name: str,
        history_hours: int = 8760  # Default 1 year
    ) -> List[Dict[str, Any]]:
        """
        Fetch client devices that connected within a given timeframe (all users).
        Note: Return stats per client are all-time totals, not just for the timeframe.

        Args:
            site_name: The short name (ID) of the site.
            history_hours: Hours to look back for client connections (default 8760).

        Returns:
            Raw API response: A list of client objects connected within the timeframe.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/alluser"
        payload = {
            'type': 'all',
            'conn': 'all',
            'within': history_hours
        }
        logger.info(
            f"Fetching all client history ({history_hours}h) for site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClient dataclass and map raw_results.
        return raw_results

    def get_guests(
        self,
        site_name: str,
        within_hours: int = 8760  # Default 1 year
    ) -> List[Dict[str, Any]]:
        """
        Fetch guest devices with valid access within a given timeframe.

        Args:
            site_name: The short name (ID) of the site.
            within_hours: Timeframe in hours to list guests with valid access (default 8760).

        Returns:
            Raw API response: A list of guest client objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/guest"
        payload = {'within': within_hours}
        logger.info(
            f"Fetching guests ({within_hours}h) for site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClient (or specific UnifiGuest) dataclass and map raw_results.
        return raw_results

    def get_active_clients_v2(
        self,
        site_name: str,
        include_traffic_usage: bool = True,
        include_unifi_devices: bool = True
    ) -> List[Dict[str, Any]]:  # Return type might differ for V2 API
        """
        Fetch active client devices using the V2 API.

        Args:
            site_name: The short name (ID) of the site.
            include_traffic_usage: Whether to include traffic usage data.
            include_unifi_devices: Whether to include UniFi devices in the response.

        Returns:
            Raw API response from the V2 endpoint.
        """
        # Note the V2 API path structure
        uri = f"{self.controller_url}/v2/api/site/{site_name}/clients/active"
        params = {
            'include_traffic_usage': include_traffic_usage,
            'include_unifi_devices': include_unifi_devices,
        }
        # V2 API endpoints seem to often use GET with query params
        full_uri = uri + "?" + requests.compat.urlencode(params)

        logger.info(
            f"Fetching active clients (V2) for site {site_name} via {full_uri}")
        response = self.invoke_get_rest_api_call(url=full_uri)

        # V2 API responses might not have the standard 'data'/'meta' structure.
        # Adjust processing if needed. For now, attempt standard processing.
        try:
            # V2 might return data directly, not nested under 'data'
            # Check common direct list or object returns
            raw_results = response.json()
            if not isinstance(raw_results, list):
                # If it's a dict, maybe the list is inside? Or it's a single obj?
                # For now, wrap dicts in a list for consistency if not a list.
                raw_results = [raw_results]
        except (ValueError, AttributeError) as e:
            error_msg = f"Failed to parse V2 API response for {uri}: {e}. Response: {response.text[:200]}"
            logger.error(error_msg)
            raise UnifiDataError(error_msg) from e

        # TODO: Define UnifiClientV2 dataclass and map raw_results.
        return raw_results

    def get_offline_clients_v2(
        self,
        site_name: str,
        only_non_blocked: bool = True,
        include_unifi_devices: bool = True,
        within_hours: int = 0  # 0 means no limit
    ) -> List[Dict[str, Any]]:  # Return type might differ for V2 API
        """
        Fetch historical (offline) client devices using the V2 API.

        Args:
            site_name: The short name (ID) of the site.
            only_non_blocked: If True, only include non-blocked clients.
            include_unifi_devices: Whether to include UniFi devices.
            within_hours: Only include devices offline within this many hours (0 = no limit).

        Returns:
            Raw API response from the V2 endpoint.
        """
        uri = f"{self.controller_url}/v2/api/site/{site_name}/clients/history"
        params = {
            'only_non_blocked': only_non_blocked,
            'include_unifi_devices': include_unifi_devices,
            'within_hours': within_hours,
        }
        full_uri = uri + "?" + requests.compat.urlencode(params)

        logger.info(
            f"Fetching offline clients (V2) for site {site_name} via {full_uri}")
        response = self.invoke_get_rest_api_call(url=full_uri)

        try:
            raw_results = response.json()
            if not isinstance(raw_results, list):
                raw_results = [raw_results]
        except (ValueError, AttributeError) as e:
            error_msg = f"Failed to parse V2 API response for {uri}: {e}. Response: {response.text[:200]}"
            logger.error(error_msg)
            raise UnifiDataError(error_msg) from e

        # TODO: Define UnifiClientHistoryV2 dataclass and map raw_results.
        return raw_results

    def get_dashboard_metrics(
        self,
        site_name: str,
        use_5min_intervals: bool = False
    ) -> List[Dict[str, Any]]:
        """
        Fetch dashboard metrics.

        Args:
            site_name: The short name (ID) of the site.
            use_5min_intervals: If True, request 5-minute interval data (requires controller v5.5+).
                                Defaults to hourly intervals.

        Returns:
            Raw API response: A list containing dashboard metric objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/dashboard"
        if use_5min_intervals:
            uri += "?scale=5minutes"

        logger.info(
            f"Fetching dashboard metrics for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiDashboardMetrics dataclass and map raw_results.
        return raw_results

    def get_sysinfo(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch system information for the site.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list containing system info objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/sysinfo"
        logger.info(f"Fetching sysinfo for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSysInfo dataclass and map raw_results.
        return raw_results

    def get_controller_status(self) -> Dict[str, Any]:
        """
        Check the basic status of the controller.
        Does not require login for non-UniFi OS controllers.
        For UniFi OS, login might be required depending on configuration.

        Returns:
            Raw status dictionary from the /status endpoint.

        Raises:
            UnifiAPIError: If the status endpoint cannot be reached or returns an error.
        """
        # Use the original URL before potential proxy path is added
        original_url = self.controller_url.replace("/proxy/network", "")
        status_uri = f"{original_url}/status"

        logger.info(f"Checking controller status via {status_uri}")
        try:
            # Attempt without authentication first for non-UniFi OS
            # For UniFi OS, if this fails with 401, the _invoke_api_call will handle retry
            response = self._invoke_api_call(method="GET", url=status_uri)
            return response.json()
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to get controller status from {status_uri}: {e}"
            logger.error(error_msg)
            raise UnifiAPIError(error_msg) from e
        except json.JSONDecodeError as e:
            error_msg = f"Failed to decode controller status response: {e}. Response: {getattr(response, 'text', '')[:200]}"
            logger.error(error_msg)
            raise UnifiDataError(error_msg) from e

    def get_self(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch information about the currently authenticated user/session.

        Args:
            site_name: The short name (ID) of the site (required for path context).

        Returns:
            Raw API response: A list containing the self/session info object.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/self"
        logger.info(f"Fetching self info for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSelfInfo dataclass and map raw_results.
        return raw_results

    def get_site_settings(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch all site settings.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list containing various site setting objects/sections.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/get/setting"
        logger.info(f"Fetching settings for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: This returns multiple setting sections. Consider defining
        #       individual dataclasses (UnifiSettingGuestAccess, UnifiSettingMgmt, etc.)
        #       or a single large UnifiSiteSettings container.
        return raw_results

    def get_port_forward_stats(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch port forwarding statistics (e.g., packet/byte counts for rules).

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of port forward stat objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/portforward"
        logger.info(
            f"Fetching port forward stats for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiPortForwardStats dataclass and map raw_results.
        return raw_results

    def get_dpi_stats(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch overall Deep Packet Inspection (DPI) statistics for the site.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of DPI stat objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/dpi"
        logger.info(f"Fetching DPI stats for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiDpiStats dataclass and map raw_results.
        return raw_results

    def get_dpi_stats_filtered(
        self,
        site_name: str,
        by: str = 'by_cat',  # 'by_cat' or 'by_app'
        category_ids: Optional[List[int]] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch DPI statistics, optionally filtered by application or category.

        Args:
            site_name: The short name (ID) of the site.
            by: Grouping type: 'by_cat' (default) or 'by_app'.
            category_ids: If by='by_app', list of numeric category IDs to filter applications by.

        Returns:
            Raw API response: A list of filtered DPI stat objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/sitedpi"
        if by not in ['by_cat', 'by_app']:
            raise ValueError("'by' must be 'by_cat' or 'by_app'")

        payload = {'type': by}
        if by == 'by_app' and category_ids is not None:
            payload['cats'] = category_ids
        elif by == 'by_cat' and category_ids is not None:
            logger.warning("category_ids filter ignored when by='by_cat'")

        logger.info(
            f"Fetching filtered DPI stats ({by}) for site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiFilteredDpiStats dataclass and map raw_results.
        return raw_results

    def count_alarms(
        self,
        site_name: str,
        # None=all, False=active, True=archived
        archived: Optional[bool] = None
    ) -> List[Dict[str, Any]]:  # Returns [{'count': N}] usually
        """
        Count alarms.

        Args:
            site_name: The short name (ID) of the site.
            archived: Filter by archived status: None (all), False (active), True (archived only).

        Returns:
            Raw API response: Usually a list containing a dictionary like [{'count': N}].
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cnt/alarm"
        if archived is False:
            uri += "?archived=false"
        # Note: PHP lib didn't explicitly handle archived=True filter, assuming default counts all if param omitted.
        # Check if ?archived=true works if needed.

        log_filter = "all" if archived is None else (
            "active" if archived is False else "archived")
        logger.info(
            f"Counting {log_filter} alarms for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiAlarmCount dataclass or just return the count directly.
        return raw_results

    def get_fingerprint_devices_v2(
        self,
        site_name: str,  # Site needed for context, even if path doesn't use it?
        fingerprint_source: int = 0
    ) -> List[Dict[str, Any]]:  # Return type might differ for V2 API
        """
        Fetch fingerprints for client devices using the V2 API.

        Args:
            site_name: The short name (ID) of the site (used for API context).
            fingerprint_source: The ID of the fingerprint source (default 0).

        Returns:
            Raw API response from the V2 endpoint.
        """
        # V2 path doesn't include site_name, but uses base controller URL
        uri = (f"{self.controller_url.replace(f'/api/s/{site_name}', '')}"
               f"/v2/api/fingerprint_devices/{fingerprint_source}")

        logger.info(
            f"Fetching fingerprint devices (V2) source {fingerprint_source} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)

        try:
            # Assuming V2 returns data directly
            raw_results = response.json()
            if not isinstance(raw_results, list):
                raw_results = [raw_results]
        except (ValueError, AttributeError) as e:
            error_msg = f"Failed to parse V2 API response for {uri}: {e}. Response: {response.text[:200]}"
            logger.error(error_msg)
            raise UnifiDataError(error_msg) from e

        # TODO: Define UnifiFingerprintDeviceV2 dataclass and map raw_results.
        return raw_results

    def get_controller_full_status(self) -> Dict[str, Any]:
        """
        Fetch the full status object from the controller's /status endpoint.
        Handles potential differences in login requirements.

        Returns:
            Raw status dictionary from the /status endpoint.

        Raises:
            UnifiAPIError: If the status endpoint cannot be reached or returns an error.
            UnifiDataError: If the response cannot be parsed as JSON.
        """
        # Reuse the logic from get_controller_status
        logger.info("Fetching full controller status object.")
        # get_controller_status already returns the parsed JSON dict
        return self.get_controller_status()

    def get_device_name_mappings(self) -> List[Dict[str, Any]]:
        """
        Fetch device name/model mappings, typically from bundles.json.
        Does not usually require login.

        Returns:
            Raw API response: List of device mapping objects.

        Raises:
            UnifiAPIError: If the endpoint cannot be reached or returns an error.
            UnifiDataError: If the response cannot be parsed as JSON.
        """
        # Use the original URL before potential proxy path is added
        original_url = self.controller_url.replace("/proxy/network", "")
        bundles_uri = f"{original_url}/dl/firmware/bundles.json"

        logger.info(f"Fetching device name mappings via {bundles_uri}")
        try:
            # Attempt without authentication first
            response = self._invoke_api_call(method="GET", url=bundles_uri)
            return response.json()
        except requests.exceptions.RequestException as e:
            error_msg = f"Failed to get device name mappings from {bundles_uri}: {e}"
            logger.error(error_msg)
            raise UnifiAPIError(error_msg) from e
        except json.JSONDecodeError as e:
            error_msg = f"Failed to decode device name mappings response: {e}. Response: {getattr(response, 'text', '')[:200]}"
            logger.error(error_msg)
            raise UnifiDataError(error_msg) from e

    def get_vouchers(
        self,
        site_name: str,
        create_time_s: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch hotspot voucher information.

        Args:
            site_name: The short name (ID) of the site.
            create_time_s: Optional Unix timestamp (seconds) to filter vouchers by creation time.

        Returns:
            Raw API response: A list of voucher objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/voucher"
        payload = {}
        if create_time_s is not None:
            payload['create_time'] = create_time_s

        logger.info(f"Fetching vouchers for site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiVoucher dataclass and map raw_results.
        return raw_results

    def get_payments(
        self,
        site_name: str,
        within_hours: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Fetch hotspot payment information.

        Args:
            site_name: The short name (ID) of the site.
            within_hours: Optional number of hours to look back for payments.

        Returns:
            Raw API response: A list of payment objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/payment"
        if within_hours is not None:
            uri += f"?within={within_hours}"  # Uses query param

        logger.info(f"Fetching payments for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiPayment dataclass and map raw_results.
        return raw_results

    def get_current_channels(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch currently allowed channels for the site (based on country code, etc.).

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of channel information objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/current-channel"
        logger.info(
            f"Fetching current channels for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiChannelInfo dataclass and map raw_results.
        return raw_results

    def get_country_codes(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch available country codes (ISO 3166-1 numeric).

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of country code objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/ccode"
        logger.info(f"Fetching country codes for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiCountryCode dataclass and map raw_results.
        return raw_results

    def get_port_forwarding_rules(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch port forwarding rule configurations.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of port forwarding rule objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/list/portforward"
        logger.info(
            f"Fetching port forwarding rules for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiPortForwardRule dataclass and map raw_results.
        return raw_results

    def get_voip_extensions(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch configured VoIP extensions.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of VoIP extension objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/list/extension"
        logger.info(f"Fetching VoIP extensions for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiVoipExtension dataclass and map raw_results.
        return raw_results

    def get_all_known_clients(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch all known client devices (including offline) for the site.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of all known client objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/list/user"
        logger.info(
            f"Fetching all known clients for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiClient dataclass and map raw_results.
        return raw_results

    def get_device_tags(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch device tags configured for the site (REST endpoint).
        Requires controller v5.5+.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of device tag objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/tag"
        logger.info(f"Fetching device tags for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiDeviceTag dataclass and map raw_results.
        return raw_results

    def get_auto_backups(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch list of available automatic controller backups.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of backup file objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/backup"
        payload = {'cmd': 'list-backups'}
        logger.info(
            f"Fetching auto backups list for site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiBackupFile dataclass and map raw_results.
        return raw_results

    def get_site_admins(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch administrators with access to the specified site.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of admin objects for the site.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/sitemgr"
        payload = {'cmd': 'get-admins'}
        logger.info(f"Fetching site admins for site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiAdmin dataclass and map raw_results.
        return raw_results

    def get_all_admins(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch all administrator accounts on the controller.
        Requires appropriate permissions.

        Args:
            site_name: The short name (ID) of a site for API context (path construction).

        Returns:
            Raw API response: A list of all admin objects.
        """
        # This endpoint is outside the site context but needs a valid path base
        base_api_path = self.controller_url.replace(f'/s/{site_name}', '')
        uri = f"{base_api_path}/api/stat/admin"
        logger.info(f"Fetching all admins via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiAdmin dataclass and map raw_results.
        return raw_results

    def get_wlan_groups(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch WLAN groups for the site.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of WLAN group objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/list/wlangroup"
        logger.info(f"Fetching WLAN groups for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiWlanGroup dataclass and map raw_results.
        return raw_results

    def get_hotspot_operators(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch hotspot operators for the site (REST endpoint).

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of hotspot operator objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/hotspotop"
        logger.info(
            f"Fetching hotspot operators for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiHotspotOperator dataclass and map raw_results.
        return raw_results

    def get_radius_profiles(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch RADIUS profiles for the site (REST endpoint).
        Requires controller v5.5.19+.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of RADIUS profile objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/radiusprofile"
        logger.info(f"Fetching RADIUS profiles for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiRadiusProfile dataclass and map raw_results.
        return raw_results

    def get_radius_accounts(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch RADIUS user accounts for the site (REST endpoint).
        Requires controller v5.5.19+.

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of RADIUS account objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/account"
        logger.info(f"Fetching RADIUS accounts for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiRadiusAccount dataclass and map raw_results.
        return raw_results

    def get_firewall_groups(self, site_name: str, group_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch firewall groups for the site (REST endpoint).

        Args:
            site_name: The short name (ID) of the site.
            group_id: Optional _id of a specific group to fetch.

        Returns:
            Raw API response: A list containing firewall group objects.
                          If group_id is provided, the list contains only that group.
        """
        uri_suffix = f"/{group_id}" if group_id else ""
        uri = f"{self.controller_url}/api/s/{site_name}/rest/firewallgroup{uri_suffix}"
        logger.info(
            f"Fetching firewall group(s) for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiFirewallGroup dataclass and map raw_results.
        return raw_results

    def get_firewall_rules(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch firewall rules for the site (REST endpoint).

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list of firewall rule objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/firewallrule"
        logger.info(f"Fetching firewall rules for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiFirewallRule dataclass and map raw_results.
        return raw_results

    def get_static_routes(self, site_name: str, route_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch static routing configurations for the site (REST endpoint).

        Args:
            site_name: The short name (ID) of the site.
            route_id: Optional _id of a specific static route to fetch.

        Returns:
            Raw API response: A list containing static route objects.
                          If route_id is provided, the list contains only that route.
        """
        uri_suffix = f"/{route_id}" if route_id else ""
        uri = f"{self.controller_url}/api/s/{site_name}/rest/routing{uri_suffix}"
        logger.info(f"Fetching static route(s) for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiStaticRoute dataclass and map raw_results.
        return raw_results

    def get_dynamic_dns_config(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Fetch dynamic DNS configurations for the site (REST endpoint).

        Args:
            site_name: The short name (ID) of the site.

        Returns:
            Raw API response: A list containing dynamic DNS configuration objects.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/dynamicdns"
        logger.info(
            f"Fetching dynamic DNS config for site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiDynamicDnsConfig dataclass and map raw_results.
        return raw_results

    # --- Device Actions (Raw API) ---

    def adopt_device(self, site_name: str, macs: Union[str, List[str]]) -> List[Dict[str, Any]]:
        """
        Adopt one or more devices to the current site using the `/cmd/devmgr` endpoint.

        Args:
            site_name: The short name (ID) of the site.
            macs: A single device MAC address string or a list of MAC addresses.

        Returns:
            Raw API response, typically an empty list on success.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/devmgr"
        if isinstance(macs, str):
            mac_list = [self.normalize_mac(macs)]
        else:
            mac_list = [self.normalize_mac(m) for m in macs]

        payload = {
            'cmd': 'adopt',
            'macs': mac_list
        }
        logger.info(
            f"Adopting device(s) {mac_list} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def adopt_device_advanced(
        self,
        site_name: str,
        mac: str,
        device_ip: str,
        ssh_username: str,
        ssh_password: str,
        inform_url: str,
        ssh_port: int = 22,
        ssh_key_verify: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Adopt a device using custom SSH credentials and inform URL.

        Args:
            site_name: The short name (ID) of the site.
            mac: Device MAC address.
            device_ip: IP address of the device for SSH connection.
            ssh_username: SSH username for the device.
            ssh_password: SSH password for the device.
            inform_url: URL the device should use to inform the controller.
            ssh_port: SSH port (default 22).
            ssh_key_verify: Whether to verify the device's SSH key (default True).

        Returns:
            Raw API response.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/devmgr"
        payload = {
            'cmd': 'adv-adopt',
            'mac': self.normalize_mac(mac),
            'ip': device_ip,
            'username': ssh_username,
            'password': ssh_password,
            'url': inform_url,
            'port': ssh_port,
            'sshKeyVerify': ssh_key_verify,
        }
        logger.info(
            f"Advanced adopting device {mac} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def migrate_device(
        self, site_name: str, macs: Union[str, List[str]], inform_url: str
    ) -> List[Dict[str, Any]]:
        """
        Initiate migration for one or more devices to a new inform URL.

        Args:
            site_name: The short name (ID) of the site.
            macs: A single device MAC address string or a list of MAC addresses.
            inform_url: The new inform URL for the devices.

        Returns:
            Raw API response.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/devmgr"
        if isinstance(macs, str):
            mac_list = [self.normalize_mac(macs)]
        else:
            mac_list = [self.normalize_mac(m) for m in macs]

        payload = {
            'cmd': 'migrate',
            'inform_url': inform_url,
            'macs': mac_list
        }
        logger.info(
            f"Migrating device(s) {mac_list} to {inform_url} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def cancel_migrate_device(
        self, site_name: str, macs: Union[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """
        Cancel an ongoing migration for one or more devices.

        Args:
            site_name: The short name (ID) of the site.
            macs: A single device MAC address string or a list of MAC addresses.

        Returns:
            Raw API response.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/devmgr"
        if isinstance(macs, str):
            mac_list = [self.normalize_mac(macs)]
        else:
            mac_list = [self.normalize_mac(m) for m in macs]

        payload = {
            'cmd': 'cancel-migrate',
            'macs': mac_list
        }
        logger.info(
            f"Canceling migration for device(s) {mac_list} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def restart_device(
        # 'soft' or 'hard'
        self, site_name: str, macs: Union[str, List[str]], reboot_type: str = 'soft'
    ) -> List[Dict[str, Any]]:
        """
        Reboot one or more devices.

        Args:
            site_name: The short name (ID) of the site.
            macs: A single device MAC address string or a list of MAC addresses.
            reboot_type: 'soft' (default) requests a device restart.
                         'hard' requests a PoE power cycle (for capable switch ports).

        Returns:
            Raw API response.

        Raises:
            ValueError: If reboot_type is invalid.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/devmgr"
        if reboot_type not in ['soft', 'hard']:
            raise ValueError("reboot_type must be 'soft' or 'hard'")

        if isinstance(macs, str):
            mac_list = [self.normalize_mac(macs)]
        else:
            mac_list = [self.normalize_mac(m) for m in macs]

        payload = {
            'cmd': 'restart',
            'macs': mac_list,
            'reboot_type': reboot_type.lower()
        }
        logger.info(
            f"Restarting ({reboot_type}) device(s) {mac_list} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def force_provision_device(
        self, site_name: str, macs: Union[str, List[str]]
    ) -> List[Dict[str, Any]]:
        """
        Force provision one or more devices.

        Args:
            site_name: The short name (ID) of the site.
            macs: A single device MAC address string or a list of MAC addresses.

        Returns:
            Raw API response.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/devmgr/"
        if isinstance(macs, str):
            mac_list = [self.normalize_mac(macs)]
        else:
            mac_list = [self.normalize_mac(m) for m in macs]

        payload = {
            'cmd': 'force-provision',
            'macs': mac_list
        }
        logger.info(
            f"Force provisioning device(s) {mac_list} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def reboot_cloudkey(self, site_name: str) -> List[Dict[str, Any]]:
        """
        Reboot the UniFi Controller (effective only on Cloud Key / UniFi OS devices).

        Args:
            site_name: The short name (ID) of the site (needed for context).

        Returns:
            Raw API response.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/system"
        payload = {'cmd': 'reboot'}
        logger.info(f"Requesting controller reboot via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def disable_device(
        self, site_name: str, device_id: str, disable: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Disable or enable a device using the REST endpoint.
        A disabled device is excluded from dashboard counts, LED/WLANs are off.
        Appears most effective for APs.

        Args:
            site_name: The short name (ID) of the site.
            device_id: The _id of the device.
            disable: True to disable the device, False to enable (default True).

        Returns:
            Raw API response, often the updated device object.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/device/{device_id}"
        payload = {'disabled': disable}
        action = "Disabling" if disable else "Enabling"
        logger.info(
            f"{action} device {device_id} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="PUT", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiDevice dataclass and map raw_results.
        return raw_results

    def set_device_led_override(
        self, site_name: str, device_id: str, mode: str  # 'on', 'off', 'default'
    ) -> List[Dict[str, Any]]:
        """
        Override the LED mode for a specific device using the REST endpoint.

        Args:
            site_name: The short name (ID) of the site.
            device_id: The _id of the device.
            mode: LED mode - 'on', 'off', or 'default' (site setting).

        Returns:
            Raw API response, often the updated device object.

        Raises:
            ValueError: If mode is invalid.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/device/{device_id}"
        if mode not in ['on', 'off', 'default']:
            raise ValueError("LED mode must be 'on', 'off', or 'default'")

        payload = {'led_override': mode}
        logger.info(
            f"Setting LED override to '{mode}' for device {device_id} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="PUT", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiDevice dataclass and map raw_results.
        return raw_results

    def locate_device(
        self, site_name: str, mac: str, enable: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Enable or disable the flashing locate LED on a device.

        Args:
            site_name: The short name (ID) of the site.
            mac: Device MAC address.
            enable: True to start flashing, False to stop (default True).

        Returns:
            Raw API response.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/devmgr"
        cmd = 'set-locate' if enable else 'unset-locate'
        payload = {
            'cmd': cmd,
            'mac': self.normalize_mac(mac)
        }
        action = "Enabling" if enable else "Disabling"
        logger.info(
            f"{action} locate LED for device {mac} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def set_device_radio_settings(
        self,
        site_name: str,
        device_id: str,
        radio: str,  # e.g., 'ng', 'na'
        channel: int,
        ht: int,  # Channel width (e.g., 20, 40, 80)
        tx_power_mode: str,  # 'low', 'medium', 'high', 'auto'?
        tx_power: int
    ) -> List[Dict[str, Any]]:
        """
        Update radio settings for a specific device (likely AP) using the /upd/ endpoint.
        Note: May be deprecated or behave differently on newer controllers.

        Args:
            site_name: The short name (ID) of the site.
            device_id: The _id of the device.
            radio: The radio band to modify ('ng', 'na').
            channel: Radio channel.
            ht: Channel width (HT/VHT value like 20, 40, 80).
            tx_power_mode: Transmit power mode ('low', 'medium', 'high', 'auto').
            tx_power: Specific transmit power level (integer dBm).

        Returns:
            Raw API response, potentially the updated device object.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/upd/device/{device_id}"
        payload = {
            'radio_table': [
                {
                    'radio': radio,
                    'channel': channel,
                    'ht': ht,
                    'tx_power_mode': tx_power_mode,
                    'tx_power': tx_power,
                }
                # Note: This assumes replacing the entire radio_table.
                # Check API behavior if multiple radios exist or if merging is needed.
            ]
        }
        logger.info(
            f"Setting radio ({radio}) settings for device {device_id} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiDevice dataclass and map raw_results.
        return raw_results

    def set_device_wlan_group(
        self, site_name: str, device_id: str, radio_type: str, group_id: str
    ) -> List[Dict[str, Any]]:
        """
        Assign a device's radio to a specific WLAN group using the /upd/ endpoint.

        Args:
            site_name: The short name (ID) of the site.
            device_id: The _id of the device (typically an AP).
            radio_type: Radio band ('ng' for 2.4GHz, 'na' for 5GHz).
            group_id: The _id of the WLAN group to assign.

        Returns:
            Raw API response, potentially the updated device object.

        Raises:
            ValueError: If radio_type is invalid.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/upd/device/{device_id}"
        if radio_type not in ['ng', 'na']:
            raise ValueError("radio_type must be 'ng' or 'na'")

        # Payload structure based on PHP example, clears overrides
        payload = {
            'wlan_overrides': [],
            f'wlangroup_id_{radio_type}': group_id,
        }
        logger.info(
            f"Assigning WLAN group {group_id} to radio {radio_type} for device {device_id} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiDevice dataclass and map raw_results.
        return raw_results

    def set_device_name(
        self, site_name: str, device_id: str, name: str
    ) -> List[Dict[str, Any]]:
        """
        Rename a device using the /upd/device/ endpoint.

        Args:
            site_name: The short name (ID) of the site.
            device_id: The _id of the device.
            name: The new name for the device.

        Returns:
            Raw API response, potentially the updated device object.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/upd/device/{device_id}"
        payload = {'name': name}
        logger.info(
            f"Setting name to '{name}' for device {device_id} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiDevice dataclass and map raw_results.
        return raw_results

    def move_device_to_site(
        self, current_site: str, mac: str, target_site_id: str
    ) -> List[Dict[str, Any]]:
        """
        Move a device to a different site using the `/cmd/sitemgr` endpoint.

        Args:
            current_site: The short name (ID) of the site the device is currently in.
            mac: MAC address of the device to move.
            target_site_id: The _id (string, not name) of the destination site.

        Returns:
            Raw API response.
        """
        uri = f"{self.controller_url}/api/s/{current_site}/cmd/sitemgr"
        payload = {
            'cmd': 'move-device',
            'site': target_site_id,
            'mac': self.normalize_mac(mac)
        }
        logger.info(
            f"Moving device {mac} from site {current_site} to site {target_site_id} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def delete_device(self, site_name: str, mac: str) -> List[Dict[str, Any]]:
        """
        Delete/remove a device from the specified site using the `/cmd/sitemgr` endpoint.
        This typically forgets the device.

        Args:
            site_name: The short name (ID) of the site.
            mac: MAC address of the device to delete.

        Returns:
            Raw API response.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/sitemgr"
        payload = {
            'cmd': 'delete-device',
            'mac': self.normalize_mac(mac)
        }
        logger.info(f"Deleting device {mac} from site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def power_cycle_switch_port(
        self, site_name: str, switch_mac: str, port_index: int
    ) -> List[Dict[str, Any]]:
        """
        Power-cycle a PoE port on a UniFi switch.

        Args:
            site_name: The short name (ID) of the site.
            switch_mac: MAC address of the switch.
            port_index: The index (number) of the port to cycle.

        Returns:
            Raw API response.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/devmgr"
        payload = {
            'cmd': 'power-cycle',
            'mac': self.normalize_mac(switch_mac),
            'port_idx': port_index
        }
        logger.info(
            f"Power cycling port {port_index} on switch {switch_mac} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def start_spectrum_scan(self, site_name: str, ap_mac: str) -> List[Dict[str, Any]]:
        """
        Trigger an RF spectrum scan on a specific access point.

        Args:
            site_name: The short name (ID) of the site.
            ap_mac: MAC address of the access point.

        Returns:
            Raw API response.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/cmd/devmgr"
        payload = {
            'cmd': 'spectrum-scan',
            'mac': self.normalize_mac(ap_mac)
        }
        logger.info(
            f"Starting spectrum scan on AP {ap_mac} on site {site_name} via {uri}")
        response = self._invoke_api_call(
            method="POST", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSimpleResult or similar.
        return raw_results

    def get_spectrum_scan_state(self, site_name: str, ap_mac: str) -> List[Dict[str, Any]]:
        """
        Check the state and results of an RF spectrum scan on an access point.

        Args:
            site_name: The short name (ID) of the site.
            ap_mac: MAC address of the access point.

        Returns:
            Raw API response containing scan state and potentially results.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/stat/spectrum-scan/{self.normalize_mac(ap_mac)}"
        logger.info(
            f"Getting spectrum scan state for AP {ap_mac} on site {site_name} via {uri}")
        response = self.invoke_get_rest_api_call(url=uri)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiSpectrumScanState dataclass and map raw_results.
        return raw_results

    def set_device_settings_base(
        self, site_name: str, device_id: str, settings_payload: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Update arbitrary device settings using the REST endpoint.
        Use with caution: payload must match the structure expected by the API
        for the specific device and settings being changed.

        Args:
            site_name: The short name (ID) of the site.
            device_id: The _id of the device.
            settings_payload: A dictionary containing the settings to update.
                             Structure should match parts of the device object from get_unifi_site_device.

        Returns:
            Raw API response, potentially the updated device object.
        """
        uri = f"{self.controller_url}/api/s/{site_name}/rest/device/{device_id}"
        logger.info(
            f"Setting base device settings for {device_id} on site {site_name} via {uri}")
        # Ensure essential fields like _id are not accidentally included if not needed by PUT body
        payload = settings_payload.copy()
        # payload.pop('_id', None) # Might be needed depending on controller version

        response = self._invoke_api_call(
            method="PUT", url=uri, json_payload=payload)
        raw_results = self._process_api_response(response, uri)

        # TODO: Define UnifiDevice dataclass and map raw_results.
        return raw_results
