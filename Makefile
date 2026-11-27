.PHONY: build test test-race clean

BIN_DIR := bin

build:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/vpn-server ./cmd/vpn-server
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/vpn-client ./cmd/vpn-client
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/vpnctl ./cmd/vpnctl
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o $(BIN_DIR)/vpn-tls-gateway ./cmd/vpn-tls-gateway

test:
	go test -v ./...

test-race:
	go test -race -v ./...

clean:
	rm -rf $(BIN_DIR)
