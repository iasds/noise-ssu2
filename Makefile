
godoc:
	./callgraph.sh

# vuln runs govulncheck against all packages. Installs a govulncheck built
# against the current Go toolchain so it matches the go directive in go.mod
# (AUDIT L-3). Fails the build on any finding.
.PHONY: vuln
vuln:
	go install golang.org/x/vuln/cmd/govulncheck@latest
	$(shell go env GOPATH)/bin/govulncheck ./...

# test runs the full test suite with the race detector.
.PHONY: test
test:
	go test -race ./...

# vet runs go vet across the module.
.PHONY: vet
vet:
	go vet ./...
