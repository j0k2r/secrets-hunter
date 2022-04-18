"""Secrets hunter program entry point."""

import logging
import os
import sys
import traceback

import secrets_hunter
from secrets_hunter import argument_parser
from secrets_hunter import core
from secrets_hunter.logging_filter import LoggingFilter
from secrets_hunter.logging_formatter import LoggingFormatter


def app(
    target: str,
    verbosity_level: int,
    is_ansi_enabled: bool,
    threads_nb: int,
    rules_path: str,
    output_format: str,
    output_path: str,
) -> int:
    """Secrets hunter main function.

    Args:
        target (str): Target directory absolute path.
        verbosity_level (int): Logging verbosity level.
        is_ansi_enabled (bool): Enable ANSI outputs.
        threads_nb (int): Program threads number.
        rules_path (str): Scan rules file absolute path.
        output_format (str): Scan discoveries output format.
        output_path (str): Scan discoveries output path.

    Returns:
        int: Secrets hunter return code
    """

    # Initialize logging library
    try:
        __setup_logger(verbosity_level, is_ansi_enabled)
    except Exception as e:
        sys.stderr.write(
            "An error occurred while initializing logger: {0}\n".format(str(e))
        )
        raise

    # Run the core module
    try:
        return core.run(
            target, rules_path, threads_nb, output_format, output_path
        )
    except Exception:
        raise


def __setup_logger(verbosity_level: int, is_ansi_enabled: bool = True) -> None:
    """Setup the program logging library.

    Args:
        verbosity_level (int): Logging verbosity level.
        is_ansi_enabled (bool, optional): Enable ANSI outputs.
            Defaults to True.
    """

    # Get logging level filtering from command line argument
    arg_log_level_map = {
        0: logging.ERROR,
        1: logging.WARNING,
        2: logging.INFO,
        3: logging.DEBUG,
    }

    if verbosity_level in arg_log_level_map.keys():
        log_level = arg_log_level_map[verbosity_level]
    elif verbosity_level > max(arg_log_level_map.keys()):
        log_level = logging.DEBUG
    else:
        log_level = logging.INFO

    # Get the logging formatter
    logging_formatter = LoggingFormatter(is_ansi_enabled)

    # A handler for low level logs that should be sent to STDOUT
    main_info_handler = logging.StreamHandler(sys.stdout)
    main_info_handler.setLevel(log_level)
    warn_logging_filter = LoggingFilter(logging.WARNING)
    main_info_handler.addFilter(warn_logging_filter)
    main_info_handler.setFormatter(logging_formatter)

    # A handler for high level logs that should be sent to STDERR
    main_error_handler = logging.StreamHandler(sys.stderr)
    main_error_handler.setLevel(logging.ERROR)
    main_error_handler.setFormatter(logging_formatter)

    # Main Thread logs
    main_log = logging.getLogger(secrets_hunter.__pretty_name__)

    # Setup logger
    main_log.addHandler(main_info_handler)
    main_log.addHandler(main_error_handler)
    main_log.setLevel(log_level)


if __name__ == "__main__":
    """Program top-level environment."""

    return_code = 0

    # Parse the program arguments
    try:
        args = argument_parser.parse(sys.argv[1:])
    except Exception as e:
        sys.stderr.write(
            "Error: Unable to parse the program arguments ({0})"
            ", terminating !\n".format(str(e))
        )
        sys.exit(1)

    # Run the program
    try:
        return_code = app(
            args[0],  # target
            args[1],  # verbosity_level
            args[2],  # is_ansi_enabled
            args[3],  # threads_nb
            args[4],  # rules_path
            args[5],  # output_format,
            args[6],  # output_path,
        )
    except KeyboardInterrupt:
        sys.stdout.write("KeyboardInterrupt: Terminating !\n")
        os._exit(0)
    except SystemExit as e:
        sys.stdout.write("SystemExit: Terminating !\n")
        return_code = e.code
    except Exception as e:
        sys.stderr.write(traceback.format_exc())
        sys.stderr.write(
            "An exception occurred while running: {0}\n".format(str(e))
        )
        return_code = -1
    finally:
        sys.exit(return_code)
