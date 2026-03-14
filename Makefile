BINARY  := capsule
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.version=$(VERSION) -s -w"
GOFLAGS := -trimpath

.PHONY: build build-linux-amd64 build-linux-arm64 test lint clean release-dry

build:
	go build $(GOFLAGS) $(LDFLAGS) -o $(BINARY) .

build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(GOFLAGS) $(LDFLAGS) -o $(BINARY)-linux-amd64 .

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(GOFLAGS) $(LDFLAGS) -o $(BINARY)-linux-arm64 .

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -f $(BINARY) $(BINARY)-linux-*
	rm -rf dist/

release-dry:
	goreleaser release --snapshot --clean
