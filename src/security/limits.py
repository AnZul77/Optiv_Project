"""
Security Limits and Resource Guardrails
Person 1: Lead Architect (with Person 4: Security Policy)
Enforces file size, decompression ratio, zip bomb detection, XML entity guards, and memory safety.
"""

from __future__ import annotations
import os
import zipfile
import re
from dataclasses import dataclass
from typing import Tuple, List, Optional


@dataclass
class SecurityLimitsConfig:
    """Security thresholds and limits for incoming documents."""
    max_file_size_bytes: int = 100 * 1024 * 1024  # 100 MB max input file size
    max_uncompressed_bytes: int = 350 * 1024 * 1024  # 350 MB max uncompressed archive size
    max_compression_ratio: float = 100.0  # Max expansion ratio (uncompressed/compressed)
    max_zip_entries: int = 10000  # Max number of entries inside zip
    max_pages: int = 500  # Max pages / slides
    max_single_image_bytes: int = 50 * 1024 * 1024  # 50 MB max single image
    block_external_entities: bool = True  # Block XML XXE / Billion laughs


class SecurityLimitExceededError(ValueError):
    """Raised when an uploaded document violates security boundaries."""
    pass


class MalformedFileError(ValueError):
    """Raised when a file is corrupted, malformed, or hostile."""
    pass


def check_file_size(file_path: str, config: Optional[SecurityLimitsConfig] = None) -> int:
    """
    Validate that the file size is within acceptable bounds.
    
    Args:
        file_path: Path to the target file.
        config: Security limits configuration.
        
    Returns:
        The verified file size in bytes.
        
    Raises:
        FileNotFoundError: If file does not exist.
        SecurityLimitExceededError: If file exceeds maximum allowed size.
    """
    cfg = config or SecurityLimitsConfig()
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    file_size = os.path.getsize(file_path)
    if file_size <= 0:
        raise MalformedFileError(f"File is empty (0 bytes): {file_path}")
    if file_size > cfg.max_file_size_bytes:
        raise SecurityLimitExceededError(
            f"File size ({file_size / (1024*1024):.2f} MB) exceeds maximum allowed limit "
            f"({cfg.max_file_size_bytes / (1024*1024):.2f} MB)"
        )
    return file_size


def inspect_archive_safety(
    file_path: str,
    config: Optional[SecurityLimitsConfig] = None
) -> Tuple[bool, List[str]]:
    """
    Inspect a zip-based archive (DOCX, PPTX) for zip bombs, path traversals, and decompression safety.
    
    Args:
        file_path: Path to the archive.
        config: Security limits configuration.
        
    Returns:
        Tuple of (is_safe, list_of_warnings_or_errors)
        
    Raises:
        SecurityLimitExceededError: If zip bomb or archive overflow detected.
        MalformedFileError: If archive is corrupted or contains dangerous relative paths.
    """
    cfg = config or SecurityLimitsConfig()
    file_size = os.path.getsize(file_path)
    
    if not zipfile.is_zipfile(file_path):
        raise MalformedFileError(f"File is not a valid zip archive: {file_path}")
    
    warnings = []
    total_uncompressed_bytes = 0
    entry_count = 0
    
    try:
        with zipfile.ZipFile(file_path, 'r') as zf:
            infolist = zf.infolist()
            entry_count = len(infolist)
            
            if entry_count > cfg.max_zip_entries:
                raise SecurityLimitExceededError(
                    f"Archive contains {entry_count} entries, exceeding limit of {cfg.max_zip_entries}"
                )
            
            for info in infolist:
                # Path traversal check
                if ".." in info.filename or info.filename.startswith(("/", "\\")):
                    raise MalformedFileError(
                        f"Zip entry contains suspicious path traversal pattern: {info.filename}"
                    )
                
                total_uncompressed_bytes += info.file_size
                
                # Check individual file size
                if info.file_size > cfg.max_uncompressed_bytes:
                    raise SecurityLimitExceededError(
                        f"Single archive entry '{info.filename}' exceeds uncompressed size limit"
                    )
            
            if total_uncompressed_bytes > cfg.max_uncompressed_bytes:
                raise SecurityLimitExceededError(
                    f"Total uncompressed archive size ({total_uncompressed_bytes / (1024*1024):.2f} MB) "
                    f"exceeds limit ({cfg.max_uncompressed_bytes / (1024*1024):.2f} MB)"
                )
            
            if file_size > 0:
                compression_ratio = total_uncompressed_bytes / file_size
                if compression_ratio > cfg.max_compression_ratio:
                    raise SecurityLimitExceededError(
                        f"Detected zip bomb! Compression expansion ratio {compression_ratio:.1f}:1 "
                        f"exceeds safety threshold {cfg.max_compression_ratio:.1f}:1"
                    )
                    
    except zipfile.BadZipFile as e:
        raise MalformedFileError(f"Corrupted or invalid zip container: {e}")
        
    return True, warnings


def inspect_xml_content_safety(xml_bytes: bytes) -> bool:
    """
    Inspect XML content for XML entity expansion / XXE attacks.
    DOCX and PPTX parts contain XML that must not contain external entities.
    """
    # Check for DOCTYPE and ENTITY declarations
    text_snippet = xml_bytes[:4096].decode("utf-8", errors="ignore").lower()
    if "<!doctype" in text_snippet and ("<!entity" in text_snippet or "system" in text_snippet):
        raise SecurityLimitExceededError("Dangerous XML entity declaration (XXE attempt) detected in package part")
    return True
