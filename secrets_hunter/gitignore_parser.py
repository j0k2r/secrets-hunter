"""Gitignore parser module.

Adapted source code from: https://github.com/mherrmann/gitignore_parser

The gitignore_parser code is licensed under MIT License,
see: https://github.com/mherrmann/gitignore_parser/blob/master/LICENSE
"""

from typing import Optional
from typing import Tuple

import os
import pathlib
import re


class GitignoreParser:
    """Parse the .gitignore file."""

    def __init__(self, target_path: str) -> None:
        """Initialize the .gitignore file parser.

        Args:
            target_path (str): Scan target directory path.
        """

        self.__has_gitignore = False

        if not os.path.isdir(target_path):
            return

        self.target_path = target_path
        gitignore_path = os.path.join(target_path, ".gitignore")

        if not os.path.isfile(gitignore_path):
            return

        self.__has_gitignore = True

        try:
            file_fd = open(gitignore_path, "r")
        except Exception:
            raise

        try:
            file_data = file_fd.read()
        except Exception:
            raise
        finally:
            file_fd.close()

        self.has_negation = False

        self.rules = []
        for ignore_line in file_data.splitlines():
            ignore_line = ignore_line.rstrip("\n")

            rule = self.__rule_from_pattern(ignore_line, target_path)

            if rule is None:
                continue

            if rule[1]:
                self.has_negation = True

            self.rules.append(rule)

    def match(self, absolute_path: str) -> bool:
        """Check if a file absolute path is ignored by the .gitignore file.

        Args:
            absolute_path (str): Concerned file absolute path.

        Returns:
            bool: True, if the file path is in the .gitignore file,
                False otherwise.
        """

        if not self.__has_gitignore:
            return False

        relative_path = str(
            pathlib.Path(absolute_path).resolve().relative_to(self.target_path)
        )

        if relative_path.startswith("./"):
            relative_path = relative_path[2:]

        if not self.has_negation:
            for rule in self.rules:
                matched = re.search(rule[0], relative_path)

                if matched is not None:
                    return True

            return False
        else:
            for rule in self.rules:
                if re.search(rule[0], relative_path):
                    if not rule[1]:
                        return True

            return False

    @staticmethod
    def __fnmatch_pathname_to_regex(pattern: str) -> str:  # noqa: C901
        """Implements fnmatch style-behavior.

        The path separator will not match shell-style '*' and '.' wildcards.

        Args:
            pattern (str): Match pattern.

        Returns:
            str: Regex pattern.
        """

        i, n = 0, len(pattern)

        seps = [re.escape(os.sep)]
        if os.altsep is not None:
            seps.append(re.escape(os.altsep))

        seps_group = "[" + "|".join(seps) + "]"
        nonsep = r"[^{}]".format("|".join(seps))

        res = []
        while i < n:
            c = pattern[i]
            i += 1
            if c == "*":
                try:
                    if pattern[i] == "*":
                        i += 1
                        res.append(".*")
                        if pattern[i] == "/":
                            i += 1
                            res.append("".join([seps_group, "?"]))
                    else:
                        res.append("".join([nonsep, "*"]))
                except IndexError:
                    res.append("".join([nonsep, "*"]))
            elif c == "?":
                res.append(nonsep)
            elif c == "/":
                res.append(seps_group)
            elif c == "[":
                j = i
                if j < n and pattern[j] == "!":
                    j += 1
                if j < n and pattern[j] == "]":
                    j += 1
                while j < n and pattern[j] != "]":
                    j += 1
                if j >= n:
                    res.append("\\[")
                else:
                    stuff = pattern[i:j].replace("\\", "\\\\")
                    i = j + 1
                    if stuff[0] == "!":
                        stuff = "".join(["^", stuff[1:]])
                    elif stuff[0] == "^":
                        stuff = "".join("\\" + stuff)
                    res.append("[{}]".format(stuff))
            else:
                res.append(re.escape(c))

        res.append("$")

        return "".join(res)

    @staticmethod
    def __rule_from_pattern(  # noqa: C901
        pattern: str, base_path: str
    ) -> Optional[Tuple[str, bool]]:
        """Transform .gitignore match pattern to regex pattern.

        Args:
            pattern (str): .gitignore pattern.
            base_path (str): .gitignore absolute base directory path.

        Returns:
            Optional[Tuple[str, bool]]: The regex pattern and the negation flag
        """

        # Early returns follow
        # Discard comments and separators
        if pattern.strip() == "" or pattern[0] == "#":
            return None

        # Discard anything with more than two consecutive asterisks
        if pattern.find("***") > -1:
            return None

        # Strip leading bang before examining double asterisks
        if pattern[0] == "!":
            negation = True
            pattern = pattern[1:]
        else:
            negation = False

        # Discard anything with invalid double-asterisks -- they can appear
        # at the start or the end, or be surrounded by slashes
        for m in re.finditer(r"\*\*", pattern):
            start_index = m.start()
            if (
                start_index != 0
                and start_index != len(pattern) - 2
                and (
                    pattern[start_index - 1] != "/"
                    or pattern[start_index + 2] != "/"
                )
            ):
                return None

        # Special-casing '/', which doesn't match any files or directories
        if pattern.rstrip() == "/":
            return None

        # directory_only = pattern[-1] == "/"

        # A slash is a sign that we're tied to the base_path of our rule set.
        anchored = "/" in pattern[:-1]
        if pattern[0] == "/":
            pattern = pattern[1:]

        if pattern[0] == "*" and len(pattern) >= 2 and pattern[1] == "*":
            pattern = pattern[2:]
            anchored = False

        if pattern[0] == "/":
            pattern = pattern[1:]

        if pattern[-1] == "/":
            pattern = pattern[:-1]

        # patterns with leading hashes are escaped with a backslash in front,
        # unescape it
        if pattern[0] == "\\" and pattern[1] == "#":
            pattern = pattern[1:]

        # trailing spaces are ignored unless they are escaped with a backslash
        i = len(pattern) - 1
        striptrailingspaces = True
        while i > 1 and pattern[i] == " ":
            if pattern[i - 1] == "\\":
                pattern = pattern[: i - 1] + pattern[i:]
                i = i - 1
                striptrailingspaces = False
            else:
                if striptrailingspaces:
                    pattern = pattern[:i]
            i = i - 1

        regex = GitignoreParser.__fnmatch_pathname_to_regex(pattern)

        if anchored:
            regex = "".join(["^", regex])

        return (regex, negation)
