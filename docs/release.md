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
1. Pull the latest version from the repository. `git pull upstream main`
2. Install the [release-please](https://github.com/googleapis/release-please/blob/main/docs/cli.md#running-release-please-cli) CLI tool if not already installed
3. Run the release-please command to generate the release notes and bump the version:
   ```bash
   release-please release-pr \
   --token=$GITHUB_TOKEN \ # personal access token with repo scope
   --repo-url=https://github.com/konflux-ci/mobster
   ```
4. Review the generated pull request and merge it into the main branch.
5. After the pull request is merged, tag the commit with the version number:
   ```bash
      git pull upstream main
      git tag vX.Y.Z
      git push upstream vX.Y.Z
   ```
6. Create a new release on GitHub with the tag `vX.Y.Z`. The release notes will
   be automatically generated based on commit diff.

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
