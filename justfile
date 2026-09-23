set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load

check: tidy typos fmt lint vet test-total fuzz build-windows

typos:
    typos

test:
    go test -race -count=1 -timeout 2m ./...

test-offline:
    go test -race -tags=e2e -run '^TestTorOffline' -v -timeout 2m .

test-total: test test-offline test-e2e-docker

# This recipe runs a private Tor network and private obfs4 bridge. The test
# container has no external network interface.
test-e2e-docker:
    ./e2e/run.sh

fuzz:
    go test -run '^$' -fuzz '^FuzzReplies$' -fuzztime 5s ./internal/control
    go test -run '^$' -fuzz '^FuzzProxyGreetingAuthAndConnect$' -fuzztime 5s .
    go test -run '^$' -fuzz '^FuzzTypedBridgeValidation$' -fuzztime 5s .

# This recipe connects to the public Tor network.
test-e2e:
    TOR_DRIVER_LIVE=1 go test -tags=e2e -run '^TestTorOnion' -v -timeout 15m .

# This recipe requires the TOR_BRIDGE_* variables described in docs/TESTING.md.
test-obfs4:
    TOR_DRIVER_LIVE=1 go test -tags=e2e -run '^TestTorObfs4' -v -timeout 8m .

vet:
    go vet ./...
    go vet -tags=e2e ./...

tidy:
    go mod tidy

lint:
    golangci-lint run ./...
    golangci-lint run --build-tags=e2e ./...

fmt:
    golangci-lint fmt ./...

build:
    go build ./...

build-windows:
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...

example *args:
    go run ./examples/onion-http {{ args }}
