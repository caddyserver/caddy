CADDY_BINARY := caddyserver

all: test build

build:
	go build -o $(CADDY_BINARY) caddy/main.go

test:
	go test -v ./...

.PHONY: clean
clean:
	rm $(CADDY_BINARY)