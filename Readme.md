# Secrets Hunter

`Secrets Hunter` is a simple engine developed to detect hardcoded secrets
within a code base.

This tool is designed to be a simple, fast and efficient scanner:

* No project dependencies
* Simple INI rules file format
* Exploit the `.gitignore` to exclude files and directories
* JSON output format

Scanning Docker image layers or Git commits is not supported and not planed.

## Getting started

### Prerequisites

* Python >= 3.7

### Usage

```bash
$ python3 -m secrets_hunter -h

usage: __main__.py [-h] [--version] [--no-ansi] [--verbose]
                   [--threads THREADS] [--output OUTPUT] [--format {json}]
                   --rules RULES SCAN_TARGET

A simple code base secrets scanner

positional arguments:
  SCAN_TARGET           Project source directory

options:
  -h, --help            show this help message and exit
  --version             show program version number and exit
  --no-ansi             disable ANSI output (default: False)
  --verbose, -v         increase output verbosity (default: Error)
  --threads THREADS, -t THREADS
                        threads number (default: 5)
  --output OUTPUT, -o OUTPUT
                        output path (default: STDOUT)
  --format {json}, -f {json}
                        output format (default: json)
  --rules RULES, -r RULES
                        rules file path
```

#### CLI

```bash
$ git clone https://github.com/j0k2r/secrets-hunter.git && cd secrets-hunter
$ python3 -m secrets_hunter -vvv --rules ./etc/secrets-hunter.ini TARGET
```

#### Python

```python
from secrets_hunter import core

target: str = "/TARGET"
rules_path: str = "/RULES.ini"
threads_nb: int = 5
output_format: str = "json"
output_path: str = "/tmp/secrets.json"

ret_code = core.run(
    target, rules_path, threads_nb, output_format, output_path
)
```

## Development

This project use [Poetry](https://python-poetry.org) as a dependency management
system.

__Poetry__ can be installed using __pip__:

```bash
$ export POETRY_PREVIEW=1
$ curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python -
$ poetry plugin add poetry-version-plugin
```

### Prerequisites

Multiple tools are used to lint, test and validate the annotation typing:

* `flake8`: Python linter
    * `flake8-fixme`: Check for FIXME and TODO keywords
    * `flake8-ensure-ascii`: Ensure that Python code contain only ASCII chars
    * `flake8-isort`: Ensure that the imports are sorted the way you expect
    * `flake8-sfs`: Check the Python string formatting style
    * `flake8-print`: Check for Print statements in python files
* `pydocstyle`: Python doc checker
* `black`: Python source formatter
* `pytest`: Python unit tester
* `isort`: Sort Python imports
* `bandit`: Check for common security issues in Python code
* `pre-commit`: Pre-commit hooks
* `coverage`: Measure code coverage of Python programs

### Setting up Dev

To install development dependencies use:

```bash
$ poetry install --no-root
```

### Unit testing

`unittest` is used for unit testing.

The testing process can be executed with:

```bash
$ poetry run python3 -m unittest -b
```

To measure the program code coverage, the `coverage` module must be run:

```bash
$ poetry run coverage run -m unittest -b
```

### Git hooks

The Git hooks must be initialized on the developer workstation before
committing changes:

```bash
$ poetry run pre-commit install
```

The Git hooks can be triggered manually using:

```bash
$ poetry run pre-commit run --all-files
```

## Similar projects

* [detect-secrets](https://github.com/Yelp/detect-secrets)
* [Gitleaks](https://github.com/zricethezav/gitleaks)
* [SecretScanner](https://github.com/deepfence/SecretScanner)
* [shhgit](https://github.com/eth0izzle/shhgit)
* [TruffleHog](https://github.com/trufflesecurity/trufflehog)
* [Whispers](https://github.com/Skyscanner/whispers)
