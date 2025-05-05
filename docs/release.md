# Release

The repository uses automated release process that consists of combination of
Github Actions and Konflux. The Github Actions take care of the release process
for the Python package and the Konflux takes care of the release process for the
container image.

## Release to PyPI
A github action is used to release the Python package to PyPI. The action is
triggered on every version tag (`vX.Y.Z`) being pushed to the repository.

### Release steps:
1. Pull the latest version from the repository. `git pull upstream main`
2. Increment the version in `pyproject.toml` file. The version should be in the format
   `X.Y.Z` where `X` is the major version, `Y` is the minor version and `Z` is
   the patch version.
3. Commit the changes to the repository. `git commit -m "Bump version to X.Y.Z"`
4. Push the changes to the repository. `git push upstream main`
5. Create a new tag for the release. `git tag vX.Y.Z`
6. Push the tag to the repository. `git push upstream vX.Y.Z`

After the tag is pushed, the Github action will be triggered and it will
automatically build the package and upload it to PyPI.

## Release to registry
The Konflux is used to release the container image to the registry. The Konflux
is configured to build image for every open PR and also for every merged PR.

TODO: Add mode details about Konflux release process when a first release is done.
