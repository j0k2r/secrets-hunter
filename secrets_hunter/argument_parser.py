"""Parse the secrets hunter arguments."""

from typing import List
from typing import Tuple

import argparse
import os

import secrets_hunter


def parse(argv: List[str]) -> Tuple[str, int, bool, int, str, str, str]:
    """Parse the secrets hunter command line arguments.

    Args:
        argv (List[str]): Command line arguments.

    Raises:
        TypeError: Arguments list type error.

    Returns:
        Tuple[str, int, bool, int, str, str, str]: Parsed and validated
            arguments.
    """

    if not isinstance(argv, list):
        raise TypeError("Arguments must be a list")

    parser = argparse.ArgumentParser(
        description=secrets_hunter.__description__
    )

    # Print program version
    parser.add_argument(
        "--version",
        action="version",
        version=secrets_hunter.__pretty_name__
        + " "
        + secrets_hunter.__version__,
    )

    # Disable ANSI colors
    parser.add_argument(
        "--no-ansi",
        action="store_true",
        default=False,
        help="disable ANSI output (default: False)",
    )

    # Verbosity values: 1 (Warning), 2 (Info), 3 (Debug)
    parser.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="increase output verbosity (default: Error)",
    )

    # Thread number
    parser.add_argument(
        "--threads",
        "-t",
        type=int,
        default=5,
        help="threads number (default: 5)",
    )

    # Output path
    parser.add_argument(
        "--output",
        "-o",
        type=__check_writable_file,
        default="",
        help="output path (default: STDOUT)",
    )

    # Output format
    parser.add_argument(
        "--format",
        "-f",
        type=str,
        choices=["json"],
        default="json",
        help="output format (default: json)",
    )

    # Rules file
    parser.add_argument(
        "--rules",
        "-r",
        required=True,
        type=__check_readable_file,
        help="rules file path",
    )

    # Set the scan target
    parser.add_argument(
        "target",
        type=__check_readable_directory,
        metavar="SCAN_TARGET",
        help="Project source directory",
    )

    try:
        args = parser.parse_args(argv)

        target: str = args.target
        verbosity_level: int = args.verbose
        is_ansi_enabled: bool = not bool(args.no_ansi)  # type: ignore[misc]
        threads_nb: int = args.threads
        rules_path: str = str(args.rules)  # type: ignore[misc]
        output_format: str = args.format
        output_path: str = args.output

        return (
            target,
            verbosity_level,
            is_ansi_enabled,
            threads_nb,
            rules_path,
            output_format,
            output_path,
        )
    except Exception:
        raise


def __check_readable_directory(dir_path: str) -> str:
    """Scan target directory validator.

    Args:
        dir_path (str): Target directory path.

    Raises:
        argparse.ArgumentTypeError: Target directory validation error.

    Returns:
        str: Target directory absolute path.
    """

    if not isinstance(dir_path, str):
        raise argparse.ArgumentTypeError("Argument must be a string")

    if not os.path.isdir(dir_path):
        raise argparse.ArgumentTypeError(
            "Directory {0} not found".format(dir_path)
        )

    if not os.access(dir_path, os.R_OK):
        raise argparse.ArgumentTypeError(
            "Directory {0} is not readable".format(dir_path)
        )

    return os.path.abspath(dir_path)


def __check_readable_file(file_path: str) -> str:
    """Scan rules file validator.

    Args:
        file_path (str): Scan rules file path.

    Raises:
        argparse.ArgumentTypeError: Scan rules file validation error.

    Returns:
        str: Scan rules file absolute path.
    """

    if not isinstance(file_path, str):
        raise argparse.ArgumentTypeError("Argument must be a string")

    if not os.path.isfile(file_path):
        raise argparse.ArgumentTypeError(
            "File {0} not found".format(file_path)
        )

    if not os.access(file_path, os.R_OK):
        raise argparse.ArgumentTypeError(
            "File {0} is not readable".format(file_path)
        )

    return file_path


def __check_writable_file(file_path: str) -> str:
    """Output file validator.

    Args:
        file_path (str): Output file path.

    Raises:
        argparse.ArgumentTypeError: Output file validation error.

    Returns:
        str: Output file absolute path.
    """

    if not isinstance(file_path, str):
        raise argparse.ArgumentTypeError("Argument must be a string")

    if file_path == "":
        return ""

    abs_file_path = os.path.abspath(file_path)

    if not os.access(os.path.dirname(abs_file_path), os.W_OK):
        raise argparse.ArgumentTypeError(
            "Output directory {0} is not writable".format(
                os.path.dirname(abs_file_path)
            )
        )

    return abs_file_path
