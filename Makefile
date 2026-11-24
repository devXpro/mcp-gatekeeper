.PHONY: lint test integration vuln ui

# PKGS narrows lint and test to some packages, e.g. `make -C <repo> lint PKGS=./auth/...`.
PKGS ?= ./...

lint:
	golangci-lint run $(PKGS)

test:
	go test -race $(PKGS)

# Tests that need Docker (a throwaway mongo:8.0 for store/mongostore).
integration:
	go test -race -tags integration $(PKGS)

# Known vulnerabilities reachable from the code (the go.mod toolchain's standard library and every module).
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...

# The admin UI package (ui/): typecheck, lint and unit tests.
ui:
	@if [ -f package.json ]; then npm ci && npm run typecheck && npm run lint && npm test; else echo "package.json not present yet, skipping"; fi
