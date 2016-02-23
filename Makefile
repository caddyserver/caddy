# For Go 1.6 vendoring is enabled by default, but let's
# not break 1.5 users if we don't have to.
GO   := GO15VENDOREXPERIMENT=1 go
pkgs  = $(shell $(GO) list ./... | grep -v /vendor/)

all: vet test build

vet:
	$(GO) vet $(pkgs)

test:
	$(GO) test $(pkgs)

build:
	mkdir -p bin/
	$(GO) build -o bin/caddy main.go

clean:
	rm -f bin/caddy
	rmdir bin/

.PHONY: all vet test build clean
