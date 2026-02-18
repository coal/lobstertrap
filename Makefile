.PHONY: build build-static test bench clean install

BINARY := agentguard
VERSION := 0.1.0
LDFLAGS := -ldflags="-s -w -X github.com/coal/lobstertrap/cmd.Version=$(VERSION)"

build:
	go build -o $(BINARY) .

build-static:
	CGO_ENABLED=0 go build $(LDFLAGS) -o $(BINARY) .

test:
	go test ./... -v

bench:
	go test ./internal/inspector/ -bench=. -benchmem

clean:
	rm -f $(BINARY) $(BINARY).exe

install:
	go install $(LDFLAGS) .

# Cross-compilation
build-linux:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 .

build-windows:
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY).exe .

build-darwin:
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-darwin-arm64 .

build-all: build-linux build-windows build-darwin
