FROM quay.io/konflux-ci/oras:3d83c68 AS oras
FROM registry.redhat.io/rhtas/cosign-rhel9:1.2.0-1744791100 AS cosign
FROM registry.access.redhat.com/ubi9/python-312@sha256:0b73e1df951c353d3938d8c552107d74213aba8c5b416466dc565875634196a4 AS builder

# Set the working directory in the container
WORKDIR /app
USER root

# Install system dependencies
RUN dnf install -y \
    gcc \
    && dnf update -y \
    && dnf clean all

# Copy the Poetry lock files to install dependencies
COPY pyproject.toml poetry.lock README.md /app/

# Install Poetry
RUN pip install --no-cache-dir --upgrade poetry==2.1.2

# Set the environment variable to tell Poetry to install the package in the virtual environment
ENV POETRY_VIRTUALENVS_IN_PROJECT=true

# Install the package dependencies via Poetry
RUN poetry install --no-root --without dev

# Copy the application code into the container
COPY src/mobster /app/src/mobster

# Copy scripts used in tekton tasks
COPY scripts/tekton /app/bin

# Install the package
RUN poetry install --without dev

# We don't want the AWS cli as a direct dependency of mobster, so we have to
# use a workaround.
RUN .venv/bin/pip install awscli==1.40.33

# Use Red Hat UBI 9 Python base image for the runtime
FROM registry.access.redhat.com/ubi9/python-312@sha256:0b73e1df951c353d3938d8c552107d74213aba8c5b416466dc565875634196a4

LABEL name="mobster" \
    description="A tool for generating and managing Software Bill of Materials (SBOM)" \
    maintainers="The Collective team"

# x-release-please-start-version
LABEL version="0.4.0"
# x-release-please-end

# Set the working directory in the container
WORKDIR /app

# Copy installed dependencies from the builder stage
COPY --from=builder /app /app

# Copy needed binaries for SBOM augmentation
COPY --from=oras /usr/bin/oras /usr/bin/oras
COPY --from=cosign /usr/local/bin/cosign /usr/bin/cosign

ENV PATH=/app/.venv/bin:$PATH
ENV PATH=/app/bin:$PATH

USER 1001

# Set the command to run your application
CMD [".venv/bin/mobster"]
