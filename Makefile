.PHONY: build test vet clean install

VERSION ?= dev
GOFLAGS ?= -buildvcs=false

build:
	go build $(GOFLAGS) -trimpath -o bin/hidpass ./cmd/hidpass

test:
	go test $(GOFLAGS) ./...

vet:
	go vet $(GOFLAGS) ./...

install: build
	install -o root -g root -m 0755 bin/hidpass /usr/local/bin/hidpass

clean:
	rm -rf bin
