"""A multi-threaded files indexer."""

from typing import Tuple

import logging
import os
from queue import Queue

from secrets_hunter.gitignore_parser import GitignoreParser
from secrets_hunter.rules_parser import RulesParser


def process_directory(
    dir_path: str,
    logger: logging.Logger,
    rules: RulesParser,
    gitignore_parser: GitignoreParser,
    work_queue: "Queue[Tuple[str, str]]",
) -> None:
    """List and classify files and directories under `dir_path`."""

    if not os.path.isdir(dir_path):
        return

    for name in os.listdir(dir_path):
        full_path = os.path.join(dir_path, name)

        # Handle sub-files
        if os.path.isfile(full_path):
            # Check for excluded file names
            if name in rules.excluded_files:
                logger.debug(
                    (
                        "File `{0}` excluded by the rule `exclusions.files`"
                    ).format(full_path)
                )

                continue

            # Check for excluded file size
            if os.path.getsize(full_path) > rules.excluded_file_size:
                logger.debug(
                    (
                        "File `{0}` excluded by the "
                        "rule `exclusions.file_size`"
                    ).format(full_path)
                )

                continue

            # Check for excluded file extensions
            if os.path.splitext(full_path)[1] in rules.excluded_extensions:
                logger.debug(
                    (
                        "File `{0}` excluded by the "
                        "rule `exclusions.extensions`"
                    ).format(full_path)
                )

                continue

            # Check for gitignore exclusions
            if gitignore_parser.match(full_path):
                logger.debug(
                    ("File `{0}` excluded by the `.gitignore` file").format(
                        full_path
                    )
                )

                continue

            # Add the sub-file to the files queue
            work_queue.put((full_path, "scanner"))
            continue

        # Handle sub-directories

        # Check for excluded directories names
        if name in rules.excluded_directories:
            logger.debug(
                (
                    "Directory `{0}` excluded by the "
                    "rule `exclusions.directories`"
                ).format(full_path)
            )

            continue

        # Check for gitignore exclusions
        if gitignore_parser.match(full_path):
            logger.debug(
                ("Directory `{0}` excluded by the `.gitignore` file").format(
                    full_path
                )
            )

            continue

        # Add the sub-directory to the directories queue
        work_queue.put((full_path, "indexer"))
        continue
