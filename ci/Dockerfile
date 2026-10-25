# Tooling only: source is supplied by Compose or Woodpecker at run time.
FROM golang:1.26.6-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gcc libc6-dev postgresql-client \
    && rm -rf /var/lib/apt/lists/*

COPY ci/install-litestream.sh /tmp/install-litestream.sh
RUN sh /tmp/install-litestream.sh && rm /tmp/install-litestream.sh

ENV CGO_ENABLED=1
ENV LICD_TEST_LITESTREAM_BINARY=/usr/local/bin/litestream
WORKDIR /workspace
