VGO=go
GOFILES := $(shell find cmd pkg internal -name '*.go' -print)
GOBIN := $(shell $(VGO) env GOPATH)/bin
LINT := $(GOBIN)/golangci-lint
MOCKERY := $(GOBIN)/mockery

# Expect that FireFly compiles with CGO disabled
CGO_ENABLED=0
GOGC=30

.DELETE_ON_ERROR:

all: build test go-mod-tidy
test: deps lint
		$(VGO) test ./pkg/... ./internal/... ./cmd/... -cover -coverprofile=coverage.txt -covermode=atomic -timeout=30s
coverage.html:
		$(VGO) tool cover -html=coverage.txt
coverage: test coverage.html
lint: ${LINT}
		GOGC=20 $(LINT) run -v --timeout 5m
${MOCKERY}:
		$(VGO) install github.com/vektra/mockery/v3@v3.8.0
${LINT}:
		$(VGO) install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
mocks: ${MOCKERY}
		${MOCKERY}

firefly-evmconnect: ${GOFILES}
		$(VGO) build -o ./firefly-evmconnect -ldflags "-X main.buildDate=`date -u +\"%Y-%m-%dT%H:%M:%SZ\"` -X main.buildVersion=$(BUILD_VERSION)" -tags=prod -tags=prod -v ./evmconnect
go-mod-tidy: .ALWAYS
		$(VGO) mod tidy
build: firefly-evmconnect
.ALWAYS: ;
clean:
		$(VGO) clean
deps:
		$(VGO) get ./evmconnect
reference:
		$(VGO) test ./cmd -timeout=10s -tags docs
docker:
		docker build --build-arg BUILD_VERSION=${BUILD_VERSION} ${DOCKER_ARGS} -t hyperledger-firefly/evmconnect .
