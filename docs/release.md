# Release

The repository uses automated release process that consists of combination of
Github Actions and Konflux. The Github Actions take care of the release process
for the Python package and the Konflux takes care of the release process for the
container image.

## Release to PyPI
The package is released to PyPI using the Github Actions. This repository uses
[release-please](https://github.com/googleapis/release-please-action) that automatically
creates a release PR and updates with every
incoming change. When the release is ready to be released, owner of the repository
should merge the PR. The release-please will automatically create a new release
and update the version in the `pyproject.toml` file. The release-please will also
create a new tag for the release.

In order for the release-please to work properly a conventional commit
messages are required. The commit messages should follow the
[conventional commit](https://www.conventionalcommits.org/en/v1.0.0/) format and
is enforced by the CI.

When a release-please successfully generate a new Github release, another Github
Action will build the package and upload it to PyPI.

## Release to registry
The Konflux is used to release the container image to the registry. The Konflux
is configured to build image for every open PR and also for every merged PR.

TODO: Add mode details about Konflux release process when a first release is done.
