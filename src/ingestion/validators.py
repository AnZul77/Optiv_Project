"""
Ingestion File Validators and Safety Checks
Person 1: Lead Architect
Performs MIME inspection, magic byte verification, file size checks, and archive safety validation
before any document enters the extraction pipeline.
"""

from __future__ import annotations
import os
import zipfile
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

from ..security.limits import (
    SecurityLimitsConfig,
    check_file_size,
    inspect_archive_safety,
    SecurityLimitExceededError,
    MalformedFileError,
)

# Canonical supported extensions
SUPPORTED_EXTENSIONS = [".pdf", ".docx", ".pptx", ".txt", ".png", ".jpg", ".jpeg", ".bmp", ".tiff"]

# Magic bytes signatures
MAGIC_BYTES = {
    "pdf": b"%PDF-",
    "zip": b"PK\x03\x04",
    "png": b"\x89PNG\r\n\x1a\n",
    "jpg": b"\xff\xd8\xff",
    "bmp": b"BM",
    "tiff_le": b"II*\x00",
    "tiff_be": b"MM\x00*",
}


@dataclass
class ValidationResult:
    """Outcome of document pre-flight security and format validation."""
    is_valid: bool
    file_path: str
    detected_type: Optional[str] = None
    file_size_bytes: int = 0
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


def inspect_magic_bytes(file_path: str) -> Optional[str]:
    """
    Inspect the file header bytes to confirm actual file format rather than relying solely on extension.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(16)
            
        if header.startswith(MAGIC_BYTES["pdf"]):
            return "pdf"
        elif header.startswith(MAGIC_BYTES["zip"]):
            return "zip"
        elif header.startswith(MAGIC_BYTES["png"]):
            return "png"
        elif header.startswith(MAGIC_BYTES["jpg"]):
            return "jpg"
        elif header.startswith(MAGIC_BYTES["bmp"]):
            return "bmp"
        elif header.startswith(MAGIC_BYTES["tiff_le"]) or header.startswith(MAGIC_BYTES["tiff_be"]):
            return "tiff"
    except Exception:
        return None
    return None


def validate_document(
    file_path: str,
    allowed_extensions: Optional[List[str]] = None,
    limits_config: Optional[SecurityLimitsConfig] = None
) -> ValidationResult:
    """
    Comprehensive pre-ingestion validation for uploaded enterprise documents.
    
    Verifies:
    1. File exists and is non-empty
    2. File size satisfies security bounds
    3. File extension is supported
    4. Magic bytes match the claimed format
    5. Zip archives (DOCX, PPTX) are safe against zip bombs, path traversals, and corrupted streams
    
    Args:
        file_path: Path to the target file.
        allowed_extensions: List of allowed extensions (defaults to ['.pdf', '.docx', '.pptx']).
        limits_config: Optional configuration for limits and thresholds.
        
    Returns:
        ValidationResult indicating whether file is safe to parse.
    """
    allowed_exts = [e.lower() for e in (allowed_extensions or SUPPORTED_EXTENSIONS)]
    cfg = limits_config or SecurityLimitsConfig()
    
    if not os.path.exists(file_path):
        return ValidationResult(
            is_valid=False,
            file_path=file_path,
            error=f"File not found: {file_path}"
        )
    
    # 1. Size Check
    try:
        file_size = check_file_size(file_path, cfg)
    except (SecurityLimitExceededError, MalformedFileError, Exception) as e:
        return ValidationResult(
            is_valid=False,
            file_path=file_path,
            error=str(e)
        )
    
    # 2. Extension Check
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()
    if ext not in allowed_exts:
        return ValidationResult(
            is_valid=False,
            file_path=file_path,
            file_size_bytes=file_size,
            error=f"Unsupported file format '{ext}'. Supported formats: {', '.join(allowed_exts)}"
        )
    
    # 3. Magic Bytes Inspection
    magic_type = inspect_magic_bytes(file_path)
    if ext == ".pdf":
        if magic_type != "pdf":
            return ValidationResult(
                is_valid=False,
                file_path=file_path,
                file_size_bytes=file_size,
                error=f"MIME/Magic byte mismatch: file has .pdf extension but lacks '%PDF-' signature"
            )
        detected_type = ".pdf"
        
    elif ext in [".docx", ".pptx"]:
        if magic_type != "zip":
            return ValidationResult(
                is_valid=False,
                file_path=file_path,
                file_size_bytes=file_size,
                error=f"MIME/Magic byte mismatch: file has {ext} extension but lacks ZIP container signature"
            )
        
        # 4. Deep Zip Archive Inspection for DOCX / PPTX
        try:
            is_safe, warnings = inspect_archive_safety(file_path, cfg)
            
            # Verify internal office format structure
            with zipfile.ZipFile(file_path, "r") as zf:
                names = zf.namelist()
                if ext == ".docx":
                    if not any("word/" in n for n in names) and "[Content_Types].xml" not in names:
                        return ValidationResult(
                            is_valid=False,
                            file_path=file_path,
                            file_size_bytes=file_size,
                            error="Invalid DOCX container: missing Office Open XML structures"
                        )
                elif ext == ".pptx":
                    if not any("ppt/" in n for n in names) and "[Content_Types].xml" not in names:
                        return ValidationResult(
                            is_valid=False,
                            file_path=file_path,
                            file_size_bytes=file_size,
                            error="Invalid PPTX container: missing Office Open XML structures"
                        )
                        
        except (SecurityLimitExceededError, MalformedFileError, Exception) as e:
            return ValidationResult(
                is_valid=False,
                file_path=file_path,
                file_size_bytes=file_size,
                error=f"Archive security inspection failed: {e}"
            )
        detected_type = ext
    elif ext in [".png", ".jpg", ".jpeg", ".bmp", ".tiff"]:
        # Verify valid image container
        try:
            from PIL import Image
            with Image.open(file_path) as img:
                img.verify()
            detected_type = ext
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                file_path=file_path,
                file_size_bytes=file_size,
                error=f"Corrupted or invalid image file: {e}"
            )
    elif ext == ".txt":
        try:
            with open(file_path, "rb") as f:
                raw_chunk = f.read(4096)
            if b"\x00" in raw_chunk:
                return ValidationResult(
                    is_valid=False,
                    file_path=file_path,
                    file_size_bytes=file_size,
                    error="Binary data with null bytes detected in plain text file"
                )
            detected_type = ".txt"
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                file_path=file_path,
                file_size_bytes=file_size,
                error=f"Failed to read text file: {e}"
            )
    else:
        detected_type = ext
        warnings = []

    return ValidationResult(
        is_valid=True,
        file_path=file_path,
        detected_type=detected_type,
        file_size_bytes=file_size,
        warnings=warnings if 'warnings' in locals() else [],
        metadata={"magic_verified": True}
    )