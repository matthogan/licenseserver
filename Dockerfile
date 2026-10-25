# syntax=docker/dockerfile:1.7
FROM golang:1.26.6-alpine3.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH
ARG TARGETVARIANT
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w" -o /out/licd ./cmd/licd && \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w" -o /out/licctl ./cmd/licctl

FROM alpine:3.22
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S -g 65532 licd && adduser -S -D -H -u 65532 -G licd licd && \
    install -d -m 0750 -o licd -g licd /var/lib/licd /var/lib/licd/archive /var/lib/licd/backups /var/lib/licd/restores /var/lib/licd/recovery-drills /var/log/licd /run/licd && \
    install -d -m 0700 -o licd -g licd /etc/licd/secrets && \
    install -d -m 0750 -o licd -g licd /etc/licd/tls
COPY --from=build /out/licd /usr/local/bin/licd
COPY --from=build /out/licctl /usr/local/bin/licctl
COPY --chown=65532:65532 configs/config.container.yaml /etc/licd/config.yaml
USER 65532:65532
VOLUME ["/var/lib/licd"]
EXPOSE 9443
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 CMD ["/usr/local/bin/licctl", "--config", "/etc/licd/config.yaml", "health"]
ENTRYPOINT ["/usr/local/bin/licd"]
CMD ["serve", "--config", "/etc/licd/config.yaml"]
