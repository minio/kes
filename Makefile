PWD := $(shell pwd)
GOPATH := $(shell go env GOPATH)
LDFLAGS := $(shell go run buildscripts/gen-ldflags.go)

GOARCH := $(shell go env GOARCH)
GOOS := $(shell go env GOOS)

BUILD_LDFLAGS := '$(LDFLAGS)'

VERSION ?= $(shell git rev-parse --short HEAD)
TAG ?= "minio/kes:$(VERSION)"

all: build

checks:
	@echo "Checking dependencies"
	@(env bash $(PWD)/buildscripts/checkdeps.sh)

getdeps:
	@mkdir -p ${GOPATH}/bin
	@which golangci-lint 1>/dev/null || (echo "Installing golangci-lint" && curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(GOPATH)/bin v1.52.2)
	@which gofumpt 1>/dev/null || (echo "Installing gofumpt" && go install mvdan.cc/gofumpt@latest)
	@which govulncheck 1>/dev/null || (echo "Installing govulncheck" && go install golang.org/x/vuln/cmd/govulncheck@latest)

verifiers: getdeps vet fmt lint vuln

docker: build
	@docker build -t $(TAG) . -f Dockerfile

vet:
	@echo "Running $@"
	@GO111MODULE=on go vet github.com/minio/kes/...

fmt:
	@echo "Running $@"
	@GO111MODULE=on gofumpt -d kv/
	@GO111MODULE=on gofumpt -d internal/
	@GO111MODULE=on gofumpt -d edge/
	@GO111MODULE=on gofumpt -d kms/

lint:
	@echo "Running $@ check"
	@GO111MODULE=on ${GOPATH}/bin/golangci-lint cache clean
	@GO111MODULE=on ${GOPATH}/bin/golangci-lint run --timeout=5m --config ./.golangci.yml

vuln:
	@echo "Running $@ check"
	govulncheck ./...

# Builds kes locally.
build: checks
	@echo "Building kes binary to './kes'"
	@GO111MODULE=on CGO_ENABLED=0 go build -trimpath -tags kqueue --ldflags $(BUILD_LDFLAGS) -o $(PWD)/kes ./cmd/kes

# Runs the verifiers, builds kes and runs the tests.
test: verifiers build
	@echo "Running unit tests"
	@GO111MODULE=on CGO_ENABLED=0 go test -v -tags kqueue ./...

# Builds kes and installs it to $GOPATH/bin.
install: build
	@echo "Installing kes binary to '$(GOPATH)/bin/kes'"
	@mkdir -p $(GOPATH)/bin && cp -f $(PWD)/kes $(GOPATH)/bin/kes
	@echo "Installation successful. To learn more, try \"kes --help\"."

clean:
	@echo "Cleaning up all the generated files"
	@find . -name '*.test' | xargs rm -fv
	@find . -name '*~' | xargs rm -fv
	@rm -rvf kes
	@rm -rvf build
	@rm -rvf release
