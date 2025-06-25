# Release

The repository uses automated release process that consists of combination of
Github Actions and Konflux. The Github Actions take care of the release process
for the Python package and the Konflux takes care of the release process for the
container image.

## Github Release
The Mobster uses release-please CLI tool to automate the release process and
generate the release notes. Unfortunately we can't use the release-please
github action due to a security concern in the `konflux-ci` organization.

Because of that the release process is done manually using the
`release-please` CLI tool. The tool is used to generate the release notes and
bump the version in the `pyproject.toml` file.

### Release steps:
1. Pull the latest version from the repository. `git pull upstream main --tags`
2. Install the [release-please](https://github.com/googleapis/release-please/blob/main/docs/cli.md#running-release-please-cli) CLI tool if not already installed
3. Export the `GITHUB_TOKEN` environment variable with a personal access token
   that has `repo` scope. This token is used to authenticate with GitHub API.
   ```bash
   export GITHUB_TOKEN=<your_personal_access_token>
   ```
4. Run `make open-release-pr` to generate the release pull request.
   1. For a dry-run, you can use `make open-release-pr-dry-run` to see what changes
      would be made without actually creating the pull request.
5. Review the generated pull request and merge it into the main branch.
6. After the pull request is merged, run the following commands to create a new Github
   release and tag the commit: `make github-release` (or `make github-release-dry-run` for a dry-run).
   1. This command will create a new tag in the format `vX.Y.Z`
   2. It will also push the tag to the remote repository
   3. It creates a new Github release with auto-generated release notes
   4. It triggers a [PyPi release](#release-to-pypi)


## Release to PyPI
A github action is used to release the Python package to PyPI. The action is
triggered on every version tag (`vX.Y.Z`) being pushed to the repository.
The tag event is generated from the previous [release steps](#release-steps).

After the tag is pushed, the Github action will be triggered and it will
automatically build the package and upload it to [PyPI](https://pypi.org/project/mobster/).

## Release to registry
The Konflux is used to build and release the container image to the registry. The Konflux
is configured to build image for every open PR and also for every merged PR.

The intermediate images are pushed to internal repository:
- https://quay.io/repository/redhat-user-workloads/the-collective-tenant/mobster-f7a65

The final externally available image is pushed to user facing repository:
- https://quay.io/konflux-ci/mobster
