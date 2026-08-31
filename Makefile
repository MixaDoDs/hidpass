# VERSION/COMMIT are injected at build time. The gc toolchain uses -ldflags -X;
# gccgo has no equivalent -X, so make writes a short init() file instead.
.PHONY: build test vet clean install uninstall

VERSION ?= dev
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
GOFLAGS ?= -buildvcs=false
PREFIX  ?= /usr/local
POLKIT_ACTIONS ?= /usr/share/polkit-1/actions
MODULE  := github.com/MixaDoDs/hidpass
LDFLAGS := -X $(MODULE)/internal/app.Version=$(VERSION) -X $(MODULE)/internal/app.Commit=$(COMMIT)
ZVERSION := internal/app/zversion.go

build:
	@if echo "$$(go env GOVERSION)" | grep -q gccgo; then \
		printf 'package app\n\nfunc init() {\n\tVersion = "%s"\n\tCommit = "%s"\n}\n' "$(VERSION)" "$(COMMIT)" > $(ZVERSION); \
		go build $(GOFLAGS) -trimpath -o bin/hidpass ./cmd/hidpass; \
		status=$$?; rm -f $(ZVERSION); exit $$status; \
	else \
		go build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o bin/hidpass ./cmd/hidpass; \
	fi

test:
	go test $(GOFLAGS) ./...

vet:
	go vet $(GOFLAGS) ./...

install: build
	install -o root -g root -m 0755 bin/hidpass $(PREFIX)/bin/hidpass
	install -d -m 0755 $(POLKIT_ACTIONS)
	install -o root -g root -m 0644 contrib/polkit/org.hidpass.policy $(POLKIT_ACTIONS)/org.hidpass.policy

uninstall:
	-$(PREFIX)/bin/hidpass uninstall
	rm -f $(PREFIX)/bin/hidpass
	rm -f $(POLKIT_ACTIONS)/org.hidpass.policy

clean:
	rm -rf bin
	rm -f $(ZVERSION)
