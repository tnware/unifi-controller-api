"""
Functions for exporting UniFi device information to various formats.

This module provides simple export utilities for UniFi device data,
allowing export to CSV, JSON, and Python dictionaries without external dependencies.
"""

import csv
import json
from typing import Any, Dict, List, Optional, TypeVar

from .models.device import UnifiDevice
from .models.site import UnifiSite
from .logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T", UnifiDevice, UnifiSite)


class UnifiEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
            return obj.to_dict()
        try:
            return super().default(obj)
        except TypeError:
            return str(obj)


def to_dict_list(items: List[T]) -> List[Dict[str, Any]]:
    """
    Convert a list of UniFi model objects to a list of dictionaries.

    This is useful for further processing or serialization.

    Args:
        items: List of UniFi model objects (UnifiDevice or UnifiSite)

    Returns:
        List of dictionaries with standardized structure
    """
    result = []

    for item in items:
        if hasattr(item, "to_dict") and callable(getattr(item, "to_dict")):
            result.append(item.to_dict())
        elif isinstance(item, dict):
            result.append(item)

    return result


def _flatten_dict(
    d: Dict[str, Any], parent_key: str = "", sep: str = "_"
) -> Dict[str, Any]:
    """
    Flatten nested dictionaries using a separator.

    Args:
        d: Dictionary to flatten
        parent_key: Key of the parent dictionary (used in recursion)
        sep: Separator to use between keys (default: '_')

    Returns:
        Flattened dictionary with no nested structures
    """
    items = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten_dict(v, new_key, sep=sep).items())
        elif isinstance(v, list):
            if v and all(isinstance(i, dict) for i in v):
                for i, item in enumerate(v):
                    items.extend(_flatten_dict(item, f"{new_key}_{i}", sep=sep).items())
            else:
                items.append((new_key, ", ".join(str(i) for i in v)))
        else:
            items.append((new_key, v))

    return dict(items)


def export_csv(
    items: List[T],
    path: str,
    fields: Optional[List[str]] = None,
    flatten_nested: bool = False,
) -> None:
    """
    Export UniFi objects to a CSV file.

    Args:
        items: List of UniFi model objects (UnifiDevice or UnifiSite)
        path: Path where the CSV file will be saved
        fields: Optional list of specific fields to include in the export.
                If not provided, all fields will be exported.
        flatten_nested: Whether to flatten nested structures using dot notation (default: False)
                        For example, uplink.type becomes uplink_type
    """
    item_dicts = to_dict_list(items)

    if not item_dicts:
        with open(path, "w", newline="", encoding="utf-8") as csvfile:
            csvfile.write("")
        return

    if flatten_nested:
        item_dicts = [_flatten_dict(item) for item in item_dicts]
        item_dicts = [d for d in item_dicts if d]
        if not item_dicts:
            with open(path, "w", newline="", encoding="utf-8") as csvfile:
                csvfile.write("")
            return

    if fields:
        final_fields = fields
    else:
        final_fields = list(item_dicts[0].keys())

    with open(path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=final_fields, extrasaction="ignore")
        writer.writeheader()

        writer.writerows(item_dicts)


def export_json(items: List[T], path: str, indent: int = 2) -> None:
    """
    Export UniFi objects to a JSON file.

    Args:
        items: List of UniFi model objects (UnifiDevice or UnifiSite)
        path: Path where the JSON file will be saved
        indent: Number of spaces for indentation in the JSON file (default: 2)
    """
    item_dicts = to_dict_list(items)

    with open(path, "w", encoding="utf-8") as jsonfile:
        json.dump(item_dicts, jsonfile, indent=indent, cls=UnifiEncoder)
