"""Secrets hunter rules parser module."""

from typing import List
from typing import Pattern
from typing import Tuple

import configparser
import os
import re


class RulesParser:
    """Parse the secrets hunter rules."""

    def __init__(self, configuration_file: str) -> None:
        """Initialize the secrets hunter rules from the INI file.

        Args:
            configuration_file (str): INI configuration file path.
        """

        self.configuration = configparser.ConfigParser()

        if os.path.isfile(configuration_file):
            try:
                config_file_fd = open(configuration_file, "r")
            except Exception:
                raise

            try:
                self.configuration.read_file(config_file_fd)
            except Exception:
                raise
            finally:
                config_file_fd.close()

        # Initialize the exclusion rules
        self.excluded_extensions = self.get_excluded_extensions()
        self.excluded_directories = self.get_excluded_directories()
        self.excluded_files = self.get_excluded_files()
        self.excluded_patterns = self.get_excluded_patterns()
        self.excluded_file_size = self.get_excluded_file_size()

        # Initialize the match rules
        self.filename_rules = self.get_rules("filename")
        self.path_rules = self.get_rules("path")
        self.extension_rules = self.get_rules("extension")
        self.content_rules = self.get_rules("contents")

    def get_excluded_extensions(self) -> List[str]:
        """Get the secrets hunter excluded extensions.

        Returns:
            List[str]: Excluded extensions list.
        """

        output = []

        if not self.configuration.has_section("exclusions"):
            return []

        if not self.configuration.has_option("exclusions", "extensions"):
            return []

        raw_extensions = self.configuration.get("exclusions", "extensions")

        for entry in raw_extensions.strip().splitlines():
            output.append(entry.strip())

        return output

    def get_excluded_directories(self) -> List[str]:
        """Get the secrets hunter excluded directories.

        Returns:
            List[str]: Excluded directories list.
        """

        output = []

        if not self.configuration.has_section("exclusions"):
            return []

        if not self.configuration.has_option("exclusions", "directories"):
            return []

        raw_directories = self.configuration.get("exclusions", "directories")

        for entry in raw_directories.strip().splitlines():
            output.append(entry.strip())

        return output

    def get_excluded_files(self) -> List[str]:
        """Get the secrets hunter excluded files.

        Returns:
            List[str]: Excluded files list.
        """

        output = []

        if not self.configuration.has_section("exclusions"):
            return []

        if not self.configuration.has_option("exclusions", "files"):
            return []

        raw_files = self.configuration.get("exclusions", "files")

        for entry in raw_files.strip().splitlines():
            output.append(entry.strip())

        return output

    def get_excluded_file_size(self) -> int:
        """Get the secrets hunter excluded file size.

        Returns:
            int: Maximum file size to scan.
        """

        if not self.configuration.has_section("exclusions"):
            return 1000000  # 1Mb

        if not self.configuration.has_option("exclusions", "file_size"):
            return 1000000  # 1Mb

        return self.configuration.getint("exclusions", "file_size")

    def get_excluded_patterns(self) -> List[str]:
        """Get the secrets hunter excluded scan patterns.

        Returns:
            int: Excluded scan patterns list.
        """

        output = []

        if not self.configuration.has_section("exclusions"):
            return []

        if not self.configuration.has_option("exclusions", "patterns"):
            return []

        raw_patterns = self.configuration.get("exclusions", "patterns")

        for entry in raw_patterns.strip().splitlines():
            output.append(entry.strip())

        return output

    def get_rules(
        self,
        part: str = "",  # filename, path, extension, contents
    ) -> List[Tuple[str, str, str, Pattern[str], str, str]]:
        """Get the secrets hunter scan rules.

        Args:
            part (str, optional): The rule concerned part. Defaults to "".

        Returns:
            List[Tuple[str, str, str, Pattern[str], str, str]]: Scan rules list
        """

        rules: List[Tuple[str, str, str, Pattern[str], str, str]] = []

        for section in self.configuration.sections():
            if not section.startswith("rule."):
                continue

            if not self.configuration.has_option(section, "part"):
                continue

            if part != "":
                if self.configuration.get(section, "part") != part:
                    continue

            rules.append(
                (
                    section.split(".")[1],
                    self.configuration.get(
                        section, "name", fallback="Unknown"
                    ),
                    self.configuration.get(section, "part", fallback=part),
                    re.compile(
                        self.configuration.get(
                            section, "regex", fallback="", raw=True
                        )
                    ),
                    self.configuration.get(
                        section, "match", fallback="", raw=True
                    ),
                    self.configuration.get(
                        section, "severity", fallback="none"
                    ),
                )
            )

        return rules
