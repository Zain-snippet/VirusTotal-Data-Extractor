class ConnectorError(Exception):
    pass


class InvalidAPIKeyError(ConnectorError):
    pass


class RateLimitExceededError(ConnectorError):
    pass


class IOCNotFoundError(ConnectorError):
    pass


class NetworkError(ConnectorError):
    pass