"""Logging filter module."""

import logging


class LoggingFilter(logging.Filter):
    """Filter instances to perform level filtering on LogRecords."""

    def __init__(self, highest_log_level: int) -> None:
        """Initialize logging level filter.

        Args:
            highest_log_level (int): Logging highest level.
        """

        super().__init__()

        self._highest_log_level = highest_log_level

    def filter(self, log_record: logging.LogRecord) -> bool:
        """Determine if the specified record should be logged.

        Args:
            log_record (logging.LogRecord): Logging log record.

        Returns:
            bool: The log record can be printed to the console.
        """

        return log_record.levelno <= self._highest_log_level
