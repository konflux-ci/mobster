FROM quay.io/redhat-user-workloads/rhtap-integration-tenant/konflux-test:baf5e59d5d35615d0db13b46bd91194458011af8 AS builder
USER 1001
RUN ["echo", "foo"]

FROM quay.io/redhat-user-workloads/rhtap-shared-team-tenant/tssc-test:tssc-test-on-push-2m6dq-build-container AS runtime
RUN ["echo", "bar"]
