"""JSON output formatter module."""

from typing import TextIO
from typing import Tuple

import json
import sys
from queue import Queue


def dump(
    discoveries_queue: Queue[Tuple[str, int, str, str, str, str]],
    fd: TextIO = sys.stdout,
) -> None:
    """Dump the discoveries into the `fd` file descriptor.

    Args:
        discoveries_queue (Queue[Tuple[str, int, str, str, str, str]]): Disco-
            vered secrets.
        fd (TextIO, optional): Output file descriptor. Defaults to sys.stdout.
    """

    output = []

    while not discoveries_queue.empty():
        discovery = discoveries_queue.get()

        # discovery[0]: File path
        # discovery[1]: Line number
        # discovery[2]: Match content
        # discovery[3]: Rule name
        # discovery[4]: Rule description
        # discovery[5]: Severity

        output.append(
            {
                "file_path": discovery[0],
                "line_number": discovery[1],
                "snippet": discovery[2],
                "rule_name": discovery[3],
                "rule_description": discovery[4],
                "severity": discovery[5],
            }
        )

    json.dump(output, fd, indent=2)
    fd.flush()
