UPSTREAM_GITHUB_REPO:=https://github.com/konflux-ci/mobster

# Release section
.PHONY: open-release-pr-dry-run
open-release-pr-dry-run:
	@echo "Using relrease-please to open a release PR (dry run)"
	@release-please release-pr \
		--token=$(GITHUB_TOKEN) \
		--repo-url=$(UPSTREAM_GITHUB_REPO) \
		--dry-run

.PHONY: open-release-pr
open-release-pr:
	@echo "Using relrease-please to open a release PR"
	@release-please release-pr \
		--token=$(GITHUB_TOKEN) \
		--repo-url=$(UPSTREAM_GITHUB_REPO)

.PHONY: github-release-dry-run
github-release-dry-run:
	@echo "Using release-please to create a GitHub release (dry run)"
	@release-please github-release \
		--token=$(GITHUB_TOKEN) \
		--repo-url=$(UPSTREAM_GITHUB_REPO) \
		--dry-run

.PHONY: github-release
github-release:
	@echo "Using release-please to create a GitHub release"
	@release-please github-release \
		--token=$(GITHUB_TOKEN) \
		--repo-url=$(UPSTREAM_GITHUB_REPO)

.PHONY: install
install:
	@echo "Installing Mobster"
	poetry install

.PHONY: build-image
build-image:
	@echo "Building Docker image"
	podman build --target release -t mobster:latest .

.PHONY: build-dev-image
build-dev-image:
	@echo "Building development Docker image"
	podman build --target dev -t mobster:dev .

@PHONY: serve-docs
serve-docs:
	@echo "Serving documentation"
	mkdocs serve

.PHONY: build-docs
build-docs:
	@echo "Building documentation"
	mkdocs build
