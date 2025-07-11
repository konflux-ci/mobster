ARG ALPINE_TAG=3.10

FROM registry.access.redhat.com/ubi8/ubi:latest

COPY entrypoint.sh /
FROM alpine:${ALPINE_TAG} AS build
RUN echo "foo"


ENTRYPOINT ["/entrypoint.sh"]
FROM build AS test
RUN echo "foo"

FROM scratch AS nothing
COPY --from=build --chown=nobody:nobody abc .
RUN echo "foo"

FROM registry.access.redhat.com/ubi9/ubi:latest AS foo
CMD ["echo hi"]

FROM registry.access.redhat.com/ubi8/ubi:latest AS bar
CMD ["echo hi"]
