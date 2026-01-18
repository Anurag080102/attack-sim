"""
Centralized Error Handling for Attack-Sim Application

This module provides custom exception classes and error handlers
for consistent error responses across the application.
"""

import logging
from functools import wraps
from typing import Any, Dict, Optional, Tuple

from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

# Set up logging
logger = logging.getLogger(__name__)


class AppError(Exception):
    """Base exception class for application errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 500,
        error_code: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        """
        Initialize application error.

        Args:
            message: Human-readable error message
            status_code: HTTP status code
            error_code: Machine-readable error code for client handling
            details: Additional error details
        """
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code or self._generate_error_code()
        self.details = details or {}

    def _generate_error_code(self) -> str:
        """Generate error code from class name."""
        name = self.__class__.__name__
        # Convert CamelCase to UPPER_SNAKE_CASE
        result = []
        for i, char in enumerate(name):
            if char.isupper() and i > 0:
                result.append("_")
            result.append(char.upper())
        return "".join(result)

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to dictionary for JSON response."""
        response = {
            "success": False,
            "error": {"code": self.error_code, "message": self.message},
        }
        if self.details:
            response["error"]["details"] = self.details
        return response


class ValidationError(AppError):
    """Raised when input validation fails."""

    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        details = details or {}
        if field:
            details["field"] = field
        super().__init__(
            message=message,
            status_code=400,
            error_code="VALIDATION_ERROR",
            details=details,
        )


class NotFoundError(AppError):
    """Raised when a requested resource is not found."""

    def __init__(
        self,
        resource_type: str,
        resource_id: Optional[str] = None,
        message: Optional[str] = None,
    ):
        if message is None:
            if resource_id:
                message = f"{resource_type} '{resource_id}' not found"
            else:
                message = f"{resource_type} not found"
        super().__init__(
            message=message,
            status_code=404,
            error_code="NOT_FOUND",
            details={"resource_type": resource_type, "resource_id": resource_id},
        )


class AuthenticationError(AppError):
    """Raised when authentication fails."""

    def __init__(
        self,
        message: str = "Authentication required",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message,
            status_code=401,
            error_code="AUTHENTICATION_REQUIRED",
            details=details,
        )


class AuthorizationError(AppError):
    """Raised when user lacks permission for an action."""

    def __init__(
        self,
        message: str = "Permission denied",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message,
            status_code=403,
            error_code="PERMISSION_DENIED",
            details=details,
        )


class ConflictError(AppError):
    """Raised when there's a conflict with existing resource."""

    def __init__(
        self,
        message: str,
        resource_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        details = details or {}
        if resource_type:
            details["resource_type"] = resource_type
        super().__init__(message=message, status_code=409, error_code="CONFLICT", details=details)


class RateLimitError(AppError):
    """Raised when rate limit is exceeded."""

    def __init__(
        self,
        message: str = "Rate limit exceeded",
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        details = details or {}
        if retry_after:
            details["retry_after"] = retry_after
        super().__init__(
            message=message,
            status_code=429,
            error_code="RATE_LIMIT_EXCEEDED",
            details=details,
        )


class ServiceUnavailableError(AppError):
    """Raised when a service is temporarily unavailable."""

    def __init__(
        self,
        message: str = "Service temporarily unavailable",
        retry_after: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        details = details or {}
        if retry_after:
            details["retry_after"] = retry_after
        super().__init__(
            message=message,
            status_code=503,
            error_code="SERVICE_UNAVAILABLE",
            details=details,
        )


class AttackError(AppError):
    """Raised when an attack execution fails."""

    def __init__(
        self,
        message: str,
        attack_id: Optional[str] = None,
        job_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        details = details or {}
        if attack_id:
            details["attack_id"] = attack_id
        if job_id:
            details["job_id"] = job_id
        super().__init__(message=message, status_code=500, error_code="ATTACK_ERROR", details=details)


class ReportError(AppError):
    """Raised when report generation or retrieval fails."""

    def __init__(
        self,
        message: str,
        report_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        details = details or {}
        if report_id:
            details["report_id"] = report_id
        super().__init__(message=message, status_code=500, error_code="REPORT_ERROR", details=details)


class ConfigurationError(AppError):
    """Raised when there's a configuration error."""

    def __init__(
        self,
        message: str,
        config_key: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ):
        details = details or {}
        if config_key:
            details["config_key"] = config_key
        super().__init__(
            message=message,
            status_code=500,
            error_code="CONFIGURATION_ERROR",
            details=details,
        )


def register_error_handlers(app: Flask) -> None:
    """
    Register error handlers with the Flask application.

    Args:
        app: Flask application instance
    """

    @app.errorhandler(AppError)
    def handle_app_error(error: AppError) -> Tuple[Dict[str, Any], int]:
        """Handle custom application errors."""
        logger.error(
            f"Application error: {error.error_code} - {error.message}",
            extra={"details": error.details},
        )
        return jsonify(error.to_dict()), error.status_code

    @app.errorhandler(HTTPException)
    def handle_http_exception(error: HTTPException) -> Tuple[Dict[str, Any], int]:
        """Handle Werkzeug HTTP exceptions."""
        response = {
            "success": False,
            "error": {
                "code": error.name.upper().replace(" ", "_"),
                "message": error.description,
            },
        }
        logger.warning(
            f"HTTP error: {error.code} - {error.name}",
            extra={"path": request.path, "method": request.method},
        )
        return jsonify(response), error.code

    @app.errorhandler(404)
    def handle_not_found(error: HTTPException) -> Tuple[Dict[str, Any], int]:
        """Handle 404 Not Found errors."""
        response = {
            "success": False,
            "error": {
                "code": "NOT_FOUND",
                "message": f"The requested URL '{request.path}' was not found",
            },
        }
        return jsonify(response), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(error: HTTPException) -> Tuple[Dict[str, Any], int]:
        """Handle 405 Method Not Allowed errors."""
        response = {
            "success": False,
            "error": {
                "code": "METHOD_NOT_ALLOWED",
                "message": f"Method '{request.method}' is not allowed for URL '{request.path}'",
            },
        }
        return jsonify(response), 405

    @app.errorhandler(415)
    def handle_unsupported_media_type(
        error: HTTPException,
    ) -> Tuple[Dict[str, Any], int]:
        """Handle 415 Unsupported Media Type errors."""
        response = {
            "success": False,
            "error": {
                "code": "UNSUPPORTED_MEDIA_TYPE",
                "message": "Request must have Content-Type: application/json",
            },
        }
        return jsonify(response), 415

    @app.errorhandler(500)
    def handle_internal_error(error: Exception) -> Tuple[Dict[str, Any], int]:
        """Handle 500 Internal Server Error."""
        logger.exception("Internal server error")
        response = {
            "success": False,
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An internal server error occurred",
            },
        }
        # In debug mode, include the error message
        if app.debug:
            response["error"]["debug_message"] = str(error)
        return jsonify(response), 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception) -> Tuple[Dict[str, Any], int]:
        """Handle any unexpected exceptions."""
        logger.exception(f"Unexpected error: {error}")
        response = {
            "success": False,
            "error": {
                "code": "UNEXPECTED_ERROR",
                "message": "An unexpected error occurred",
            },
        }
        # In debug mode, include the error details
        if app.debug:
            response["error"]["debug_message"] = str(error)
            response["error"]["type"] = type(error).__name__
        return jsonify(response), 500


def safe_execute(func):
    """
    Decorator for safe execution of functions with proper error handling.

    Catches exceptions and converts them to appropriate AppError instances.
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except AppError:
            # Re-raise application errors as-is
            raise
        except ValueError as e:
            raise ValidationError(str(e))
        except FileNotFoundError as e:
            raise NotFoundError("File", details={"error": str(e)})
        except PermissionError as e:
            raise AuthorizationError(f"Permission denied: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error in {func.__name__}")
            raise AppError(
                message=f"Operation failed: {e}",
                status_code=500,
                details={"function": func.__name__},
            )

    return wrapper


# Export all error classes
__all__ = [
    "AppError",
    "ValidationError",
    "NotFoundError",
    "AuthenticationError",
    "AuthorizationError",
    "ConflictError",
    "RateLimitError",
    "ServiceUnavailableError",
    "AttackError",
    "ReportError",
    "ConfigurationError",
    "register_error_handlers",
    "safe_execute",
]
