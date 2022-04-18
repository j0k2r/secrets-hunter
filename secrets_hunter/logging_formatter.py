"""Logging formatter module."""

from typing import Dict

import logging


class LoggingFormatter(logging.Formatter):
    """Formatter instance to convert a LogRecord to text."""

    def __init__(self, enable_ansi: bool = True) -> None:
        """Initialize the logging formatter with ANSI flag.

        Args:
            enable_ansi (bool, optional): Enable ANSI output. Defaults to True.
        """

        super().__init__(
            fmt="%(levelno)d: %(msg)s", datefmt="%d-%m-%Y %H:%M:%S", style="%"
        )

        # Define the ANSI color codes
        if enable_ansi:
            self.colors = {
                "RED": "\033[91m",
                "GREEN": "\033[92m",
                "YELLOW": "\033[93m",
                "BLUE": "\033[94m",
                "PURPLE": "\033[95m",
                "CYAN": "\033[96m",
                "GRAY": "\033[97m",
                "BOLD": "\033[1m",
                "ENDC": "\033[0m",
            }
        else:
            self.colors = {
                "RED": "",
                "GREEN": "",
                "YELLOW": "",
                "BLUE": "",
                "PURPLE": "",
                "CYAN": "",
                "GRAY": "",
                "BOLD": "",
                "ENDC": "",
            }

        # Define the log output separator
        self.separator = "  "

    @staticmethod
    def _log_format(
        record_name: str,
        record_level: int,
        colors: Dict[str, str],
        separator: str,
    ) -> str:
        """Log record format for logs.

        Args:
            record_name (str): Log record name.
            record_level (int): Log record level.
            colors (Dict[str, str]): Log colors mapping.
            separator (str): Log separator.

        Returns:
            str: Log format.
        """

        if record_level == logging.DEBUG:
            return (
                colors["BOLD"]
                + colors["GRAY"]
                + "[%(asctime)s]"
                + separator
                + colors["PURPLE"]
                + "[{:25}]".format(record_name)
                + separator
                + colors["BLUE"]
                + "[%(levelname)-8s]"
                + separator
                + colors["ENDC"]
                + "%(message)s"
            )

        if record_level == logging.INFO:
            return (
                colors["BOLD"]
                + colors["GRAY"]
                + "[%(asctime)s]"
                + separator
                + colors["PURPLE"]
                + "[{:25}]".format(record_name)
                + separator
                + colors["GREEN"]
                + "[%(levelname)-8s]"
                + separator
                + colors["ENDC"]
                + "%(message)s"
            )

        if record_level == logging.WARNING:
            return (
                colors["BOLD"]
                + colors["GRAY"]
                + "[%(asctime)s]"
                + separator
                + colors["PURPLE"]
                + "[{:25}]".format(record_name)
                + separator
                + colors["YELLOW"]
                + "[%(levelname)-8s]"
                + separator
                + colors["ENDC"]
                + "%(message)s"
            )

        if record_level == logging.ERROR:
            return (
                colors["BOLD"]
                + colors["GRAY"]
                + "[%(asctime)s]"
                + separator
                + colors["PURPLE"]
                + "[{:25}]".format(record_name)
                + separator
                + colors["RED"]
                + "[%(levelname)-8s]"
                + separator
                + colors["ENDC"]
                + colors["RED"]
                + "%(message)s"
                + colors["ENDC"]
            )

        # if record_level == logging.CRITICAL:
        return (
            colors["BOLD"]
            + colors["GRAY"]
            + "[%(asctime)s]"
            + separator
            + colors["PURPLE"]
            + "[{:25}]".format(record_name)
            + separator
            + colors["RED"]
            + "[%(levelname)-8s]"
            + separator
            + colors["ENDC"]
            + colors["RED"]
            + colors["BOLD"]
            + "%(message)s"
            + colors["ENDC"]
        )

    def format(self, record: logging.LogRecord) -> str:
        """Format the logging log record as text.

        Args:
            record (logging.LogRecord): Log record.

        Returns:
            str: Log line.
        """

        # Save the original format configured by the user
        # when the logger formatter was instantiated
        format_orig = self._style._fmt

        # Logger name must not exceed 25 char
        formated_name = record.name
        if len(record.name) > 25:
            formated_name = "...{0}".format(record.name[-22:])

        # Create a logging format
        self._style._fmt = self._log_format(
            formated_name, record.levelno, self.colors, self.separator
        )

        # Call the original formatter class to do the grunt work
        result = logging.Formatter.format(self, record)

        # Restore the original format configured by the user
        self._style._fmt = format_orig

        return result
