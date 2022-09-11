from typing import Tuple

import logging
import threading
import time
from queue import Queue

import secrets_hunter.indexer
import secrets_hunter.scanner
from secrets_hunter.gitignore_parser import GitignoreParser
from secrets_hunter.rules_parser import RulesParser


class Worker(threading.Thread):
    def __init__(
        self,
        work_queue: "Queue[Tuple[str, str]]",
        rules: RulesParser,
        gitignore_parser: GitignoreParser,
        discoveries_queue: "Queue[Tuple[str, int, str, str, str, str]]",
        stop_event: threading.Event,
    ) -> None:

        self.work_queue: "Queue[Tuple[str, str]]" = work_queue
        self.rules = rules
        self.gitignore_parser = gitignore_parser
        self.discoveries_queue = discoveries_queue
        self.stop_event = stop_event

        self._logger = logging.getLogger("secrets-hunter.worker")
        self._indexer_logger = logging.getLogger("secrets-hunter.indexer")
        self._scanner_logger = logging.getLogger("secrets-hunter.scanner")

        # Flag to check if the worker is running or waiting for a job
        self.is_processing = False

        super().__init__()

    def run(self) -> None:
        try:
            while True:
                if self.stop_event.is_set():
                    return

                if self.work_queue.empty():
                    time.sleep(0.2)
                    continue

                self.is_processing = True

                payload, category = self.work_queue.get()

                if category == "indexer":
                    secrets_hunter.indexer.process_directory(
                        payload,
                        self._indexer_logger,
                        self.rules,
                        self.gitignore_parser,
                        self.work_queue,
                    )
                elif category == "scanner":
                    secrets_hunter.scanner.process_file(
                        payload,
                        self._scanner_logger,
                        self.rules,
                        self.discoveries_queue,
                    )
                else:
                    raise ValueError(
                        "Unknown payload category, "
                        "must be: `indexer` or `scanner`"
                    )

                self.work_queue.task_done()
                self.is_processing = False
        except Exception:
            self.is_processing = False
            raise
