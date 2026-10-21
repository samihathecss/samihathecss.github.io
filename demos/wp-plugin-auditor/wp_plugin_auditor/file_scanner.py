"""
File scanning helper for WP Plugin Risk & Hardening Auditor.

This module provides a safe function to scan a single PHP file for risky patterns.
"""

from __future__ import annotations

import os
import pathlib
from typing import List, Union
from .scanner import scan_php_text


def scan_php_file(file_path: Union[str, pathlib.Path], max_bytes: int = 1_000_000) -> List:
    """
    Scan a single PHP file for risky function patterns.

    Parameters
    ----------
    file_path : str or pathlib.Path
        The path to the PHP file to scan.
    max_bytes : int, optional
        The maximum number of bytes to read, by default 1_000_000 (1MB).

    Returns
    -------
    List[Finding]
        List of findings from scanning the file.

    Raises
    ------
    TypeError
        If `file_path` is not a string or Path object, or if `max_bytes` is not an integer.
    ValueError
        If `max_bytes` is not positive, if the file does not have a .php suffix,
        if the file does not exist, is a directory, is a symlink, exceeds max_bytes,
        or is not valid UTF-8.
    """
    # Validate file_path type
    if not isinstance(file_path, (str, pathlib.Path)):
        raise TypeError("file_path must be a string or pathlib.Path")

    # Convert to Path object for easier handling
    path = pathlib.Path(file_path)

    # Validate max_bytes type (reject booleans because bool is a subclass of int)
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int):
        raise TypeError("max_bytes must be an integer")

    if max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")

    # Check if the file exists
    if not path.exists():
        raise ValueError(f"File does not exist: {path}")

    # Check if it's a symbolic link
    if path.is_symlink():
        raise ValueError(f"File is a symbolic link: {path}")

    # Check if it's a regular file (not a directory, etc.)
    if not path.is_file():
        raise ValueError(f"Not a regular file: {path}")

    # Check the suffix (case-insensitive)
    if path.suffix.lower() != ".php":
        raise ValueError(f"File must have a .php suffix: {path}")

    # Check file size
    file_size = path.stat().st_size
    if file_size > max_bytes:
        raise ValueError(
            f"File size ({file_size} bytes) exceeds max_bytes ({max_bytes}): {path}"
        )

    # Read the file as UTF-8
    try:
        content = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"File is not valid UTF-8: {path}") from e

    # Use the existing scanner, passing the string path as file_path
    return scan_php_text(content, file_path=str(path))