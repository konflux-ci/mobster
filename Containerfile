FROM quay.io/konflux-ci/oras:3d83c68 AS oras
FROM registry.redhat.io/rhtas/cosign-rhel9:1.2.0-1744791100 AS cosign
FROM registry.access.redhat.com/ubi9/python-312@sha256:e151f5a3319d75dec2a7d57241ba7bb75f1b09bc3f7092d7615ea9c5aedb114c AS builder

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

# Install the package
RUN poetry install --without dev

# Use Red Hat UBI 9 Python base image for the runtime
FROM registry.access.redhat.com/ubi9/python-312@sha256:e151f5a3319d75dec2a7d57241ba7bb75f1b09bc3f7092d7615ea9c5aedb114c

ARG TARGETARCH
ENV SYFT_VERSION=1.38.2

LABEL name="mobster" \
    description="A tool for generating and managing Software Bill of Materials (SBOM)" \
    maintainers="The Collective team"

# x-release-please-start-version
LABEL version="1.1.0"
# x-release-please-end


# Set the working directory in the container
WORKDIR /app

# Copy installed dependencies from the builder stage
COPY --from=builder /app /app

USER 0
# hadolint ignore=DL4006
RUN curl -L "https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${TARGETARCH}.tar.gz" | \
    tar -xz -C /usr/local/bin syft

# Copy needed binaries for SBOM augmentation
COPY --from=oras /usr/bin/oras /usr/bin/oras
COPY --from=cosign /usr/local/bin/cosign /usr/bin/cosign
# Copy license to the container
COPY LICENSE /licenses/

ENV PATH=/app/.venv/bin:$PATH
ENV PATH=/app/bin:$PATH

USER 1001

# Set the command to run your application
CMD [".venv/bin/mobster"]
