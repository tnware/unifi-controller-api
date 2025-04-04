"""
Utility functions for the UniFi Controller API package.
"""

import inspect
import json
import os
import dataclasses
from typing import Any, Dict, List, Type, Optional, Tuple

from .models.device import UnifiDevice
from .logging import get_logger
from .exceptions import UnifiModelError

logger = get_logger(__name__)


def get_api_field_mapping(model_class: Type) -> Dict[str, str]:
    """
    Create a mapping between API field names and model attribute names.

    Examines dataclass fields with metadata to find mappings between
    API field names (like 'user-num_sta') and Python attribute names (like 'user_num_sta').

    Args:
        model_class: The dataclass model to examine for field mappings

    Returns:
        Dictionary mapping UniFi API field names to Python model attribute names
    """
    if not dataclasses.is_dataclass(model_class):
        return {}

    field_mapping = {}

    for field in dataclasses.fields(model_class):
        if hasattr(field, "metadata") and "unifi_api_field" in field.metadata:
            api_field_name = field.metadata["unifi_api_field"]
            field_mapping[api_field_name] = field.name

    return field_mapping


def filter_valid_fields(data: Dict[str, Any], model_class: Type) -> Dict[str, Any]:
    """
    Filter a dictionary to only include fields that are valid for the model class.

    Args:
        data: Input dictionary with potentially invalid fields
        model_class: The model class to filter fields for

    Returns:
        Dictionary containing only fields that are valid parameters for the model class
    """
    signature = inspect.signature(model_class.__init__)
    valid_params = set(signature.parameters.keys())

    valid_params.discard("self")

    field_map = get_api_field_mapping(model_class)

    result = {}
    for k, v in data.items():
        if k in valid_params:
            result[k] = v
        elif k in field_map and field_map[k] in valid_params:
            mapped_key = field_map[k]
            result[mapped_key] = v

    return result


def extract_extra_fields(data: Dict[str, Any], model_class: Type) -> Dict[str, Any]:
    """
    Extract fields from a dictionary that are not valid for the model class.

    Args:
        data: Input dictionary with potentially invalid fields
        model_class: The model class to check fields against

    Returns:
        Dictionary containing only fields that are NOT valid parameters for the model class
    """
    signature = inspect.signature(model_class.__init__)
    valid_params = set(signature.parameters.keys())

    valid_params.discard("self")
    field_map = get_api_field_mapping(model_class)
    all_valid_keys = valid_params.union(field_map.keys())

    return {k: v for k, v in data.items() if k not in all_valid_keys}


def map_api_data_to_model(
    data: Dict[str, Any], model_class: Type
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Maps API data to model fields, handling special field names and separating model fields from extra fields.

    This function handles:
    - Direct field matches
    - Fields with api_key metadata mapping
    - Nested data structures
    - Extra fields preservation

    Args:
        data: Input dictionary from API response
        model_class: The dataclass model to map data to

    Returns:
        Tuple containing (model_fields, extra_fields) where:
            - model_fields: Dictionary of fields that map to the model's attributes
            - extra_fields: Dictionary of extra fields that don't directly map to the model
    """
    signature = inspect.signature(model_class.__init__)
    valid_params = set(signature.parameters.keys())
    valid_params.discard("self")

    field_map = get_api_field_mapping(model_class)
    reverse_field_map = {v: k for k, v in field_map.items()}

    model_fields = {}
    extra_fields = {}

    for api_key, value in data.items():
        mapped_key = None

        if api_key in valid_params:
            mapped_key = api_key

        elif api_key in field_map and field_map[api_key] in valid_params:
            mapped_key = field_map[api_key]
            logger.debug(f"Mapped field {api_key} to {mapped_key}")

        if mapped_key is not None:
            model_fields[mapped_key] = value
        else:
            extra_fields[api_key] = value

    return model_fields, extra_fields


def resolve_model_names(
    devices: List[UnifiDevice], model_db_path: Optional[str] = None
) -> None:
    """
    Centralized function to resolve model names for a list of UnifiDevice objects.

    This function is used to populate the model_name field based on the device model code,
    using the device-models.json database.

    Args:
        devices: List of UnifiDevice objects to resolve model names for
        model_db_path: Path to the device model database JSON file. If None,
                      uses the built-in device-models.json file.

    This function modifies the devices in-place, setting their model_name attribute.
    It only sets model_name if it's not already set, preserving existing values.

    Raises:
        UnifiModelError: If the device model database cannot be loaded.
    """
    if not devices:
        return

    if model_db_path is None:
        model_db_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "unifi_controller_api",
            "device-models.json",
        )

    try:
        with open(model_db_path, "r", encoding="utf-8") as file:
            device_models = json.load(file)
    except (json.JSONDecodeError, IOError, FileNotFoundError) as e:
        error_msg = f"Failed to load device models from {model_db_path}: {e}"
        logger.error(error_msg)
        raise UnifiModelError(error_msg) from e

    for device in devices:
        if device.model_name is not None or not device.model:
            continue

        model_details = device_models.get(device.model, {})
        model_name = model_details.get("names", {}).get("fullName", None)

        if model_name:
            device.model_name = model_name
        else:
            device.model_name = device.model
