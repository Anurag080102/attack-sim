"""
Input Validation Module

This module provides input validation utilities for API endpoints.
"""

import re
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse

# Import centralized error handling
from app.errors import ValidationError


def validate_required(data: Dict[str, Any], required_fields: List[str]) -> None:
    """
    Validate that required fields are present and not empty.
    
    Args:
        data: Dictionary to validate
        required_fields: List of required field names
        
    Raises:
        ValidationError: If a required field is missing or empty
    """
    for field in required_fields:
        if field not in data:
            raise ValidationError(f"'{field}' is required", field)
        
        value = data[field]
        if value is None or (isinstance(value, str) and not value.strip()):
            raise ValidationError(f"'{field}' cannot be empty", field)


def validate_url(url: str, field_name: str = "url") -> str:
    """
    Validate and normalize a URL.
    
    Args:
        url: URL string to validate
        field_name: Name of the field (for error messages)
        
    Returns:
        Normalized URL
        
    Raises:
        ValidationError: If URL is invalid
    """
    if not url or not isinstance(url, str):
        raise ValidationError(f"'{field_name}' must be a non-empty string", field_name)
    
    url = url.strip()
    
    # Add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = f"http://{url}"
    
    try:
        parsed = urlparse(url)
        
        if not parsed.netloc:
            raise ValidationError(f"'{field_name}' is not a valid URL", field_name)
        
        # Basic hostname validation
        hostname = parsed.netloc.split(":")[0]
        if not hostname:
            raise ValidationError(f"'{field_name}' must have a valid hostname", field_name)
        
        # Check for localhost or IP addresses (valid for security testing)
        ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        
        if hostname == "localhost":
            pass  # localhost is valid
        elif re.match(ip_pattern, hostname):
            # Validate IP octets
            octets = [int(x) for x in hostname.split(".")]
            if not all(0 <= o <= 255 for o in octets):
                raise ValidationError(f"'{field_name}' has invalid IP address", field_name)
        elif not re.match(hostname_pattern, hostname):
            raise ValidationError(f"'{field_name}' has invalid hostname", field_name)
        
        return url
        
    except Exception as e:
        if isinstance(e, ValidationError):
            raise
        raise ValidationError(f"'{field_name}' is not a valid URL: {str(e)}", field_name)


def validate_string(value: Any, field_name: str, min_length: int = 0, 
                   max_length: int = None, pattern: str = None) -> str:
    """
    Validate a string value.
    
    Args:
        value: Value to validate
        field_name: Name of the field
        min_length: Minimum string length
        max_length: Maximum string length
        pattern: Regex pattern to match
        
    Returns:
        Validated and trimmed string
        
    Raises:
        ValidationError: If validation fails
    """
    if not isinstance(value, str):
        raise ValidationError(f"'{field_name}' must be a string", field_name)
    
    value = value.strip()
    
    if len(value) < min_length:
        raise ValidationError(
            f"'{field_name}' must be at least {min_length} characters", 
            field_name
        )
    
    if max_length is not None and len(value) > max_length:
        raise ValidationError(
            f"'{field_name}' must be at most {max_length} characters", 
            field_name
        )
    
    if pattern and not re.match(pattern, value):
        raise ValidationError(f"'{field_name}' has invalid format", field_name)
    
    return value


def validate_integer(value: Any, field_name: str, min_value: int = None, 
                    max_value: int = None) -> int:
    """
    Validate an integer value.
    
    Args:
        value: Value to validate
        field_name: Name of the field
        min_value: Minimum allowed value
        max_value: Maximum allowed value
        
    Returns:
        Validated integer
        
    Raises:
        ValidationError: If validation fails
    """
    try:
        int_value = int(value)
    except (TypeError, ValueError):
        raise ValidationError(f"'{field_name}' must be an integer", field_name)
    
    if min_value is not None and int_value < min_value:
        raise ValidationError(
            f"'{field_name}' must be at least {min_value}", 
            field_name
        )
    
    if max_value is not None and int_value > max_value:
        raise ValidationError(
            f"'{field_name}' must be at most {max_value}", 
            field_name
        )
    
    return int_value


def validate_attack_config(config: Dict[str, Any], 
                          config_options: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate attack configuration against its schema.
    
    Args:
        config: Configuration to validate
        config_options: Attack's configuration options schema
        
    Returns:
        Validated configuration
        
    Raises:
        ValidationError: If validation fails
    """
    if config is None:
        return {}
    
    if not isinstance(config, dict):
        raise ValidationError("config must be an object", "config")
    
    validated = {}
    
    for key, value in config.items():
        if key not in config_options:
            # Unknown options are passed through but logged
            validated[key] = value
            continue
        
        option = config_options[key]
        option_type = option.get("type", "string")
        
        try:
            if option_type == "string":
                validated[key] = validate_string(value, key)
            elif option_type == "integer":
                validated[key] = validate_integer(
                    value, key,
                    min_value=option.get("min"),
                    max_value=option.get("max")
                )
            elif option_type == "boolean":
                if isinstance(value, bool):
                    validated[key] = value
                elif isinstance(value, str):
                    validated[key] = value.lower() in ("true", "1", "yes")
                else:
                    validated[key] = bool(value)
            elif option_type == "float":
                try:
                    validated[key] = float(value)
                except (TypeError, ValueError):
                    raise ValidationError(f"'{key}' must be a number", key)
            elif option_type == "select":
                options_list = option.get("options", [])
                if value not in options_list:
                    raise ValidationError(
                        f"'{key}' must be one of: {', '.join(options_list)}", 
                        key
                    )
                validated[key] = value
            elif option_type == "array":
                if not isinstance(value, list):
                    raise ValidationError(f"'{key}' must be an array", key)
                validated[key] = value
            elif option_type == "file":
                validated[key] = validate_string(value, key)
            else:
                validated[key] = value
                
        except ValidationError:
            raise
        except Exception as e:
            raise ValidationError(f"Invalid value for '{key}': {str(e)}", key)
    
    # Check for required options that are missing
    for key, option in config_options.items():
        if option.get("required") and key not in validated:
            if "default" not in option:
                raise ValidationError(f"'{key}' is required", key)
    
    return validated


def validate_job_id(job_id: str) -> str:
    """
    Validate a job ID format.
    
    Args:
        job_id: Job ID to validate
        
    Returns:
        Validated job ID
        
    Raises:
        ValidationError: If validation fails
    """
    if not job_id or not isinstance(job_id, str):
        raise ValidationError("job_id must be a non-empty string", "job_id")
    
    # UUID format validation
    uuid_pattern = r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
    if not re.match(uuid_pattern, job_id.lower()):
        raise ValidationError("job_id must be a valid UUID", "job_id")
    
    return job_id


def validate_report_id(report_id: str) -> str:
    """
    Validate a report ID format.
    
    Args:
        report_id: Report ID to validate
        
    Returns:
        Validated report ID
        
    Raises:
        ValidationError: If validation fails
    """
    if not report_id or not isinstance(report_id, str):
        raise ValidationError("report_id must be a non-empty string", "report_id")
    
    # Report ID format: YYYYMMDD_HHMMSS
    report_pattern = r'^\d{8}_\d{6}$'
    if not re.match(report_pattern, report_id):
        raise ValidationError("report_id has invalid format", "report_id")
    
    return report_id


def sanitize_html(text: str) -> str:
    """
    Sanitize text to prevent XSS in HTML output.
    
    Args:
        text: Text to sanitize
        
    Returns:
        Sanitized text
    """
    if not isinstance(text, str):
        return str(text)
    
    replacements = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
    }
    
    for char, replacement in replacements.items():
        text = text.replace(char, replacement)
    
    return text

