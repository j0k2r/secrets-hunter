"""Secrets hunter program controller module.

Control and schedule the scanners execution.
"""

from typing import Tuple

import logging
import sys
import threading
import time
from queue import Queue

from secrets_hunter import json_formatter
from secrets_hunter.gitignore_parser import GitignoreParser
from secrets_hunter.indexer import Indexer
from secrets_hunter.rules_parser import RulesParser
from secrets_hunter.scanner import Scanner


def run(
    target: str,
    rules_path: str,
    threads_nb: int = 5,
    output_format: str = "json",
    output_path: str = "",
) -> int:
    """Index and scan the target directory to detect secrets.

    Args:
        target (str): Target directory absolute path.
        rules_path (str): Scan rules file absolute path.
        threads_nb (int, optional): Program threads number. Defaults to 5.
        output_format (str, optional): Scan discoveries output format.
            Defaults to "json".
        output_path (str, optional): Scan discoveries output path.
            Defaults to "".

    Returns:
        int: Secrets hunter return code
    """

    start_time = int(time.time())

    _logger = logging.getLogger("secrets-hunter")

    # Initialize the scan rules
    rules = RulesParser(rules_path)

    # Initialize the .gitignore skip rules
    gitignore_parser = GitignoreParser(target)

    # Target sub directories queue (directories to index)
    directories_queue: Queue[str] = Queue()
    directories_queue.put(target)

    # Target sub files queue (indexed files ready for scanning)
    files_queue: Queue[str] = Queue()

    # Scan discoveries queue
    discoveries_queue: Queue[Tuple[str, int, str, str, str, str]] = Queue()

    # Index the target directory files and skip the excluded ones

    indexer_stop_event = threading.Event()
    indexer_threads = []

    # Initialize and run the indexer threads
    for i in range(threads_nb):
        indexer = Indexer(
            directories_queue,
            files_queue,
            rules,
            gitignore_parser,
            indexer_stop_event,
        )
        indexer.setDaemon(True)
        indexer.start()

        indexer_threads.append(indexer)

    # Wait until the indexer threads has finished working
    while True:
        if not directories_queue.empty():
            time.sleep(0.5)
            continue

        processing_flag = False
        for thread in indexer_threads:
            if thread.is_processing:
                processing_flag = True
                break

        if not processing_flag:
            break

        time.sleep(0.5)

    indexer_stop_event.set()
    for indexer_thread in indexer_threads:
        indexer_thread.join()

    _logger.info(
        "Indexed {0} file(s) under `{1}`".format(files_queue.qsize(), target)
    )

    # Scan the indexed files for secrets

    scanner_stop_event = threading.Event()
    scanner_threads = []

    # Initialize and run the scanner threads
    for i in range(threads_nb):
        scanner = Scanner(
            files_queue, rules, discoveries_queue, scanner_stop_event
        )
        scanner.setDaemon(True)
        scanner.start()

        scanner_threads.append(scanner)

    # Wait until the scanners threads has finished working
    for scanner_thread in scanner_threads:
        scanner_thread.join()

    issues_nb = discoveries_queue.qsize()
    _logger.info("Found {0} issue(s)".format(issues_nb))

    # Dump the discoveries data
    dump_discoveries(discoveries_queue, output_format, output_path)

    _logger.info(
        "The secrets hunt took {0}s".format(int(time.time()) - start_time)
    )

    if issues_nb > 0:
        return 99

    return 0


def dump_discoveries(
    discoveries_queue: Queue[Tuple[str, int, str, str, str, str]],
    output_format: str,
    output_path: str,
) -> None:
    """Secrets discoveries dump helper.

    Args:
        discoveries_queue (Queue[Tuple[str, int, str, str, str, str]]): Secrets
            discoveries queue.
        output_format (str): Dump format.
        output_path (str): Dump output path.

    Raises:
        NotImplementedError: Unknown dump format.
    """

    output_fd = sys.stdout

    if output_path != "":
        try:
            output_fd = open(output_path, "w")
        except Exception:
            raise

    try:
        if output_format == "json":
            json_formatter.dump(discoveries_queue, output_fd)
        else:
            raise NotImplementedError(
                "Unknown `{0}` output format".format(output_format)
            )
    except Exception:
        raise
    finally:
        if output_fd != sys.stdout:
            output_fd.close()
