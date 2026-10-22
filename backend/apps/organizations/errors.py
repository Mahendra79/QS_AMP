"""Consistent JSON error envelope: {"success": false, "error": {"code", "message"}}."""
from django.core.exceptions import PermissionDenied
from django.http import Http404
from rest_framework import status
from rest_framework.exceptions import APIException, ValidationError
from rest_framework.views import exception_handler


class ServiceError(APIException):
    """Raised by services for expected, user-facing failures."""
    status_code = status.HTTP_400_BAD_REQUEST
    default_code = "bad_request"

    def __init__(self, code, message, status_code=None, details=None):
        super().__init__(message, code)
        self.code = code
        self.message = message
        self.details = details
        if status_code:
            self.status_code = status_code


CODES = {
    401: "authentication_failed",
    403: "permission_denied",
    404: "not_found",
    405: "method_not_allowed",
    429: "throttled",
}


def _first_message(data):
    if isinstance(data, dict):
        for k, v in data.items():
            msg = _first_message(v)
            return msg if k in ("detail", "non_field_errors") else f"{k}: {msg}"
    if isinstance(data, (list, tuple)) and data:
        return _first_message(data[0])
    return str(data)


def api_exception_handler(exc, context):
    if isinstance(exc, Http404):
        exc = APIException("Resource not found.")
        exc.status_code = 404
    elif isinstance(exc, PermissionDenied):
        exc = APIException("You do not have permission to perform this action.")
        exc.status_code = 403
    response = exception_handler(exc, context)
    if response is None:
        return None
    details = None
    if isinstance(exc, ServiceError):
        code, message, details = exc.code, exc.message, exc.details
    elif isinstance(exc, ValidationError):
        code, message, details = "validation_error", _first_message(response.data), response.data
    else:
        code = CODES.get(response.status_code, getattr(exc, "default_code", "error"))
        message = _first_message(response.data)
    body = {"success": False, "error": {"code": code, "message": message}}
    if details:
        body["error"]["details"] = details
    response.data = body
    return response
