import logging
import re
import sys


_SECRET_PATTERNS = [
    re.compile(
        r"(?i)(api[-_]?key|secret[-_]?key|password|passwd|token|authorization)"
        r"(\s*[:=]\s*)[^\s,;]+"
    ),
    re.compile(
        r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"
    ),
    re.compile(
        r"(?i)(postgres(?:ql)?(?:\+asyncpg)?://[^:\s]+:)[^@\s]+(@)"
    ),
]


def _redact_message(message: str) -> str:
    """Remove secrets and credentials from log messages."""
    result = message

    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(
            lambda match: (
                f"{match.group(1)}[REDACTED]"
                + (
                    match.group(2)
                    if match.lastindex and match.lastindex >= 2
                    else ""
                )
            ),
            result,
        )

    return result


class SecretMaskingFormatter(logging.Formatter):
    """Logging formatter that removes secrets from formatted messages."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        return _redact_message(message)


def setup_logging(debug: bool = False) -> None:
    """Configure application-wide logging."""

    handler = logging.StreamHandler(sys.stdout)

    handler.setFormatter(
        SecretMaskingFormatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )

    root_logger = logging.getLogger()

    root_logger.handlers.clear()
    root_logger.addHandler(handler)

    # DEBUG mode enables verbose application logging.
    root_logger.setLevel(
        logging.DEBUG if debug else logging.INFO
    )

    # Keep SQLAlchemy engine logging clean unless warnings or errors occur.
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


# Backwards-compatible alias.
configure_logging = setup_logging


def get_logger(name: str) -> logging.Logger:
    """Return a named application logger."""
    return logging.getLogger(name)


# Module-level logger used by application services.
logger = get_logger("cyber-home-shield")