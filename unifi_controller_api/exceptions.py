class UnifiControllerError(Exception):
    """Base exception for UnifiController errors."""

    pass


class UnifiAuthenticationError(UnifiControllerError):
    """Raised when authentication with the UniFi Controller fails."""

    pass


class UnifiAPIError(UnifiControllerError):
    """Raised when an API call to the UniFi Controller fails."""

    pass


class UnifiDataError(UnifiControllerError):
    """Raised when there is an error parsing data from the UniFi Controller."""

    pass


class UnifiModelError(UnifiControllerError):
    """Raised when there is an error loading or processing device models."""

    pass
