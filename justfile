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

lint: lint-go lint-shell lint-python lint-nix lint-actions lint-docker lint-yaml lint-markdown

lint-go:
    golangci-lint run ./...
    golangci-lint run --build-tags=e2e ./...

lint-shell:
    shellcheck -x $(git ls-files '*.sh')

lint-python:
    ruff check .

lint-nix:
    deadnix --fail .
    statix check .
    nixfmt --check $(git ls-files '*.nix')

lint-actions:
    actionlint

lint-docker:
    hadolint e2e/Dockerfile

lint-yaml:
    yamllint cz.yaml .github/workflows

lint-markdown:
    markdownlint $(git ls-files '*.md')

fmt: fmt-go fmt-shell fmt-python fmt-nix

fmt-go:
    golangci-lint fmt ./...

fmt-shell:
    shfmt -w -i 4 -ci $(git ls-files '*.sh')

fmt-python:
    ruff format .

fmt-nix:
    nixfmt $(git ls-files '*.nix')

build:
    go build ./...

build-windows:
    GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build ./...

# These commands require Linux, KVM, and developer-supplied licensed media.
winvm-doctor:
    ./dev/winvm/doctor.sh

winvm-input-hashes:
    ./dev/winvm/doctor.sh --print-input-hashes

winvm-image:
    ./dev/winvm/build-image.sh

test-windows-vm:
    ./dev/winvm/run.sh

# This command connects to the public Tor network from the Windows VM.
test-windows-vm-public:
    ./dev/winvm/run.sh --public

winvm-clean:
    ./dev/winvm/run.sh --clean

winvm-shell run:
    ./dev/winvm/run.sh --shell {{ run }}

example *args:
    go run ./examples/onion-http {{ args }}
