"""A multi-threaded files scanner."""

from typing import BinaryIO
from typing import Generator
from typing import Optional
from typing import Pattern
from typing import Tuple

import logging
import os
import re
import threading
from queue import Queue

from secrets_hunter.rules_parser import RulesParser


class Scanner(threading.Thread):
    """Scan files and ignore exceptions patterns."""

    def __init__(
        self,
        files_queue: "Queue[str]",
        rules: RulesParser,
        discoveries_queue: "Queue[Tuple[str, int, str, str, str, str]]",
        stop_event: threading.Event,
    ) -> None:
        """Initialize the scanner worker thread.

        Args:
            files_queue (Queue[str]): Shared indexed files paths to scan.
            rules (RulesParser): Scan rules object.
            discoveries_queue (Queue[Tuple[str, int, str, str, str, str]]): Di-
                scovered secrets.
            stop_event (threading.Event): Thread stop event.
        """

        self.files_queue: "Queue[str]" = files_queue
        self.rules = rules
        self.stop_event = stop_event
        self.discoveries_queue = discoveries_queue

        self._logger = logging.getLogger("secrets-hunter.scanner")

        self.empty_regex = re.compile("")

        super().__init__()

    def run(self) -> None:
        """Run the thread.

        For each file in the `files_queue`, check for secrets based on the
        rules object.
        """

        while not self.files_queue.empty():
            if self.stop_event.is_set():
                return

            self.__process_file(self.files_queue.get())
            self.files_queue.task_done()

    def __process_file(self, file_path: str) -> None:
        """Detect secrets based on the file path.

        Args:
            file_path (str): Target file path for secrets detection.
        """

        file_extension = os.path.splitext(file_path)[1]
        file_name = os.path.basename(file_path)

        # Check for extension match
        matched_rule = self.__scan_file_extension(file_extension)
        if matched_rule is not None:
            self.__add_discovery(file_path, 0, file_extension, matched_rule)

            if matched_rule[5] == "error":
                # Extension matched with error level
                # no need to check for other rules
                return

        # Check for file name match
        matched_rule = self.__scan_file_name(file_name)
        if matched_rule is not None:
            self.__add_discovery(file_path, 0, file_name, matched_rule)

            if matched_rule[5] == "error":
                # File name matched with error level
                # no need to check for other rules
                return

        # Check for file path match
        matched_rule = self.__scan_file_path(file_path)
        if matched_rule is not None:
            self.__add_discovery(file_path, 0, file_path, matched_rule)

            if matched_rule[5] == "error":
                # File path matched with error level
                # no need to check for other rules
                return

        # Check for file content match
        try:
            file_fd = open(file_path, "rb")
        except Exception:
            self._logger.exception("Failed to open {0} file".format(file_path))
            return

        try:
            for match_data, line_nb, matched_rule in self.__scan_file_content(
                file_fd
            ):
                self.__add_discovery(
                    file_path, line_nb, match_data, matched_rule
                )
        except Exception:
            self._logger.exception("Failed to read {0} file".format(file_path))
        finally:
            file_fd.close()

    def __add_discovery(
        self,
        file_path: str,
        line_number: int,
        match_data: str,
        rule: Tuple[str, str, str, Pattern[str], str, str],
    ) -> None:
        """Add the discovered secret to the `discoveries_queue`.

        The excluded patterns will be ignored.

        Args:
            file_path (str): Concerned file path.
            line_number (int): Concerned line number.
            match_data (str): Concerned line data.
            rule (Tuple[str, str, str, Pattern[str], str, str]): Matched rule.
        """

        if line_number == 0:
            # No need to check for excluded patterns

            self._logger.info(
                "Found matching pattern `{0}` while scanning `{1}`".format(
                    rule[0], file_path
                )
            )

            self.discoveries_queue.put(
                (file_path, line_number, match_data, rule[0], rule[1], rule[5])
            )

            return

        # Check for excluded patterns
        for excluded_pattern in self.rules.excluded_patterns:
            if excluded_pattern in match_data:

                self._logger.debug(
                    (
                        "Match pattern `{0}` ignored by the "
                        "rule `exclusions.patterns` for the file `{1}`"
                    ).format(rule[0], file_path)
                )

                return

        self._logger.info(
            "Found matching pattern `{0}` while scanning `{1}`".format(
                rule[0], file_path
            )
        )

        self.discoveries_queue.put(
            (file_path, line_number, match_data, rule[0], rule[1], rule[5])
        )

    def __scan_file_extension(
        self, file_extension: str
    ) -> Optional[Tuple[str, str, str, Pattern[str], str, str]]:
        """Scan the file extension.

        Args:
            file_extension (str): The file extension to scan.

        Returns:
            Optional[Tuple[str, str, str, Pattern[str], str, str]]: Return the
                matched rule.
        """

        for rule in self.rules.extension_rules:
            if rule[3] != self.empty_regex:  # Test for `regex` attribute
                if rule[3].match(file_extension):
                    return rule

            if rule[4] != "":  # Test for `match` attribute
                if file_extension == rule[4]:
                    return rule

        return None

    def __scan_file_name(
        self, file_name: str
    ) -> Optional[Tuple[str, str, str, Pattern[str], str, str]]:
        """Scan the file name.

        Args:
            file_name (str): The file name to scan.

        Returns:
            Optional[Tuple[str, str, str, Pattern[str], str, str]]: Return the
                matched rule.
        """

        for rule in self.rules.filename_rules:
            if rule[3] != self.empty_regex:  # Test for `regex` attribute
                if rule[3].match(file_name):
                    return rule

            if rule[4] != "":  # Test for `match` attribute
                if file_name == rule[4]:
                    return rule

        return None

    def __scan_file_path(
        self, file_path: str
    ) -> Optional[Tuple[str, str, str, Pattern[str], str, str]]:
        """Scan the file path.

        Args:
            file_path (str): The file path to scan.

        Returns:
            Optional[Tuple[str, str, str, Pattern[str], str, str]]: Return the
                matched rule.
        """

        for rule in self.rules.path_rules:
            if rule[3] != self.empty_regex:  # Test for `regex` attribute
                if rule[3].match(file_path):
                    return rule

            if rule[4] != "":  # Test for `match` attribute
                if file_path == rule[4]:
                    return rule

        return None

    def __scan_file_content(
        self, file_fd: BinaryIO
    ) -> Generator[
        Tuple[str, int, Tuple[str, str, str, Pattern[str], str, str]],
        None,
        None,
    ]:
        """Scan the file content for secrets.

        Args:
            file_fd (BinaryIO): The file descriptor to scan.

        Returns:
            None: Nothing

        Yields:
            Generator[
                Tuple[str, int, Tuple[str, str, str, Pattern[str], str, str]],
                None,
                None,]: Discoverd secrets with the matched rule.
        """

        line_nb = 0

        while True:
            line_nb = line_nb + 1

            try:
                # Get next line from file
                line = file_fd.readline()
            except Exception:
                self._logger.exception(
                    "Failed to read line `{0}` from `{1}`".format(
                        line_nb, file_fd.name
                    )
                )
                continue

            if not line:
                return None

            try:
                decoded_line = line.decode("utf-8")
            except UnicodeDecodeError:
                decoded_line = line.decode("utf-8", errors="ignore")

            for rule in self.rules.content_rules:
                if rule[3] != self.empty_regex:  # Test for `regex` attribute
                    if rule[3].search(decoded_line):
                        yield decoded_line.strip(), line_nb, rule

                if rule[4] != "":  # Test for `match` attribute
                    if rule[4] in decoded_line:
                        yield decoded_line.strip(), line_nb, rule
