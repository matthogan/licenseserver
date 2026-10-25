.PHONY: build test test-race vet release-check release-snapshot

build:
	go build ./cmd/licd ./cmd/licctl

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

release-check:
	goreleaser check

release-snapshot:
	goreleaser release --snapshot --clean --skip=sign,sbom
