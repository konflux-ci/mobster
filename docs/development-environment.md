# Dev environment

## Setup
1. Install [Poetry](https://python-poetry.org/docs/#installation)
2. Install an environment with Poetry
   1. `poetry install`
   2. This will create a virtual environment in `.venv` and install all dependencies
   3. You can also use `poetry shell` to activate the virtual environment
3. Install [pre-commit hooks](#git-leaks-detection)

Note: You can also use a custom virtual environment based on your preference.

### Git leaks detection

Since the repository currently contains secret information in various encrypted forms there is high chance that developer may push a commit with
decrypted secrets by mistake. To avoid this problem we recommend
to use `Gitleaks` tool that prevent you from commit secret code into git history.

The repository is already pre-configured but each developer has to make final
config changes in his/her environment.

Follow the [documentation](https://github.com/gitleaks/gitleaks#pre-commit) to
configure Gitleaks on your computer.

## Package management
The project uses Poetry for package management. You can use the following commands to manage packages:
- `poetry add <package>`: Add a package to the project
- `poetry add --group dev <package>`: Add a package to the development group
- `poetry remove <package>`: Remove a package from the project
- `poetry update`: Update all packages to their latest versions
- `poetry install`: Install all packages listed in the `pyproject.toml` file
- `poetry lock`: Lock the dependencies to their current versions

The Petry project uses `poetry.lock` file to lock the dependencies to their current versions. This file is automatically generated by Poetry when you run `poetry install` or `poetry update`. You should not edit this file manually.

## Tox

The project uses Tox for testing and linting. You can use the following commands to run Tox:
- `tox`: Run all tests and linters
- `tox -e <env>`: Run a specific environment (e.g. `tox -e test` to run tests )
- `tox -e <env> -- <args>`: Run a specific environment with additional arguments (e.g. `tox -e test -- -v` to run tests for with verbose output)

### Code formatting
The project uses Ruff for code checking and formatting. You can use the following commands to check and format the code:

- `tox -e ruff`: Run Ruff to check the code

We highly recommend to configure your IDE to run Ruff on save. This will help you to keep the code clean and consistent.

### Testing
The project uses Pytest for testing. You can use the following commands to run tests:
- `tox -e test`: Run all tests
- `tox -e test -- -v`: Run all tests with verbose output
- `tox -e test -- -k <test_name>`: Run a specific test (e.g. `tox -e test -- -k test_example` to run the test named `test_example`)

## Integration Tests

The integration tests require external services to be running. These services
are provided locally via Docker Compose.

1. **Start the test services:**
   ```bash
   docker compose up -d
   ```

2. **Run the integration tests:**
   ```bash
   tox -e test-integration
   ```

## Building the container image

The project contains a Containerfile that can be used to build a container image. You can use the following command to build the image:
```bash
podman build -t <image_name> .
```
Replace `<image_name>` with the name you want to give to the image.

Then you can run the image using the following command:
```bash
podman run -it <image_name>
```
Replace `<image_name>` with the name of the image you built.
