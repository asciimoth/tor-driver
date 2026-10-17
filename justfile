set shell := ["bash", "-euo", "pipefail", "-c"]
set dotenv-load

check: tidy typos fmt lint vet test fuzz build-windows

# CI runs the Docker smoke tests in a separate job. Keep the complete Docker
# matrix in the local check target.
check-ci: check

typos:
    typos

test:
    go test -race -count=1 -timeout 2m ./...

fuzz:
    go test -run '^$' -fuzz '^FuzzReplies$' -fuzztime 5s ./internal/control
    go test -run '^$' -fuzz '^FuzzProxyGreetingAuthAndConnect$' -fuzztime 5s .
    go test -run '^$' -fuzz '^FuzzTypedBridgeValidation$' -fuzztime 5s .

# This recipe connects to the public Tor network.
test-e2e:
    go test -tags=e2e -run '^TestTorThroughDebugGoboxBackend$' -v -timeout 5m .

vet:
    go vet ./...
    go vet -tags=e2e ./...

tidy:
    go mod tidy

lint: lint-go lint-shell lint-python lint-nix lint-actions lint-yaml lint-markdown

lint-go:
    golangci-lint run ./...
    golangci-lint run --build-tags=e2e ./...

lint-shell:
    shellcheck -x $(rg --files -g '*.sh')

lint-python:
    ruff check .

lint-nix:
    deadnix --fail .
    statix check .
    nixfmt --check $(rg --files -g '*.nix')

lint-actions:
    actionlint

lint-yaml:
    yamllint cz.yaml .github/workflows

lint-markdown:
    markdownlint $(rg --files -g '*.md')

fmt: fmt-go fmt-shell fmt-python fmt-nix

fmt-go:
    golangci-lint fmt ./...

fmt-shell:
    shfmt -w -i 4 -ci $(rg --files -g '*.sh')

fmt-python:
    ruff format .

fmt-nix:
    nixfmt $(rg --files -g '*.nix')

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
