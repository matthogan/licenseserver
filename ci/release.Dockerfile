FROM docker:29.2.1-cli AS dockercli
FROM local/licd-test:go1.26.6-litestream0.5.12-v1

RUN apt-get update && apt-get install -y --no-install-recommends python3 openssh-client \
    && rm -rf /var/lib/apt/lists/*
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-buildx /usr/local/libexec/docker/cli-plugins/docker-buildx
COPY ci/install-release-tools.sh /tmp/install-release-tools.sh
RUN sh /tmp/install-release-tools.sh && rm /tmp/install-release-tools.sh

# Trust is installed by the operator when building this image, not read from a tag.
COPY release/git-allowed-signers /opt/licd-release/git-allowed-signers
COPY release/policy.json /opt/licd-release/policy.json
