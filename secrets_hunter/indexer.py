"""A multi-threaded files indexer."""

import logging
import os
import threading
import time
from queue import Queue

from secrets_hunter.gitignore_parser import GitignoreParser
from secrets_hunter.rules_parser import RulesParser


class Indexer(threading.Thread):
    """Index files and ignore exceptions from the directory target."""

    def __init__(
        self,
        directories_queue: Queue[str],
        files_queue: Queue[str],
        rules: RulesParser,
        gitignore_parser: GitignoreParser,
        stop_event: threading.Event,
    ) -> None:
        """Initialize the indexer worker thread.

        Args:
            directories_queue (Queue[str]): Shared directories/sub-directories
                paths to index.
            files_queue (Queue[str]): Shared indexed files paths.
            rules (RulesParser): Scan rules object.
            gitignore_parser (GitignoreParser): Gitignore exclusion object.
            stop_event (threading.Event): Thread stop event.
        """

        self.directories_queue: Queue[str] = directories_queue
        self.files_queue: Queue[str] = files_queue
        self.rules = rules
        self.gitignore_parser = gitignore_parser
        self.stop_event = stop_event

        self._logger = logging.getLogger("secrets-hunter.indexer")

        # Flag to check if the indexer is running or waiting for a job
        self.is_processing = False

        super().__init__()

    def run(self) -> None:
        """Run the thread.

        Get a directory from the queue, process it, and put the discoverd
        sub-directories and sub-files on the queues.
        """

        try:
            while True:
                if self.stop_event.is_set():
                    return

                if self.directories_queue.empty():
                    time.sleep(0.2)
                    continue

                self.is_processing = True
                self.__process_directory(self.directories_queue.get())
                self.directories_queue.task_done()
                self.is_processing = False
        except Exception:
            self.is_processing = False
            raise

    def __process_directory(self, dir_path: str) -> None:
        """List and classify files and directories under `dir_path`.

        Args:
            dir_path (str): Parent directory path.
        """

        if not os.path.isdir(dir_path):
            return

        for name in os.listdir(dir_path):
            full_path = os.path.join(dir_path, name)

            # Handle sub-files
            if os.path.isfile(full_path):
                # Check for excluded file names
                if name in self.rules.excluded_files:
                    self._logger.debug(
                        (
                            "File `{0}` excluded by the "
                            "rule `exclusions.files`"
                        ).format(full_path)
                    )

                    continue

                # Check for excluded file size
                if os.path.getsize(full_path) > self.rules.excluded_file_size:
                    self._logger.debug(
                        (
                            "File `{0}` excluded by the "
                            "rule `exclusions.file_size`"
                        ).format(full_path)
                    )

                    continue

                # Check for excluded file extensions
                if (
                    os.path.splitext(full_path)[1]
                    in self.rules.excluded_extensions
                ):
                    self._logger.debug(
                        (
                            "File `{0}` excluded by the "
                            "rule `exclusions.extensions`"
                        ).format(full_path)
                    )

                    continue

                # Check for gitignore exclusions
                if self.gitignore_parser.match(full_path):
                    self._logger.debug(
                        (
                            "File `{0}` excluded by the `.gitignore` file"
                        ).format(full_path)
                    )

                    continue

                # Add the sub-file to the files queue
                self.files_queue.put(full_path)
                continue

            # Handle sub-directories

            # Check for excluded directories names
            if name in self.rules.excluded_directories:
                self._logger.debug(
                    (
                        "Directory `{0}` excluded by the "
                        "rule `exclusions.directories`"
                    ).format(full_path)
                )

                continue

            # Check for gitignore exclusions
            if self.gitignore_parser.match(full_path):
                self._logger.debug(
                    (
                        "Directory `{0}` excluded by the `.gitignore` file"
                    ).format(full_path)
                )

                continue

            # Add the sub-directory to the directories queue
            self.directories_queue.put(full_path)
            continue
