VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
TARGETS := windows/amd64 windows/arm64 linux/amd64 linux/arm64 darwin/amd64 darwin/arm64
DIST    := dist

.PHONY: all test vet checksums universal clean generate help \
	windows-amd64 windows-arm64 linux-amd64 linux-arm64 darwin-amd64 darwin-arm64

all: windows-amd64 windows-arm64 linux-amd64 linux-arm64 darwin-amd64 darwin-arm64

# $(1)=os $(2)=arch $(3)=extension
define build_target
$(1)-$(2):
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=$(1) GOARCH=$(2) go build -trimpath -ldflags "$(LDFLAGS)" -o $(DIST)/sonar-$(1)-$(2)$(3) .
endef

$(eval $(call build_target,windows,amd64,.exe))
$(eval $(call build_target,windows,arm64,.exe))
$(eval $(call build_target,linux,amd64,))
$(eval $(call build_target,linux,arm64,))
$(eval $(call build_target,darwin,amd64,))
$(eval $(call build_target,darwin,arm64,))

test:
	go test ./...

vet:
	go vet ./...

generate:
	go generate ./internal/oui

checksums:
	cd $(DIST) && files=$$(ls sonar-* | sort) && \
	if command -v sha256sum >/dev/null 2>&1; then sha256sum $$files > SHA256SUMS; \
	else shasum -a 256 $$files > SHA256SUMS; fi

universal:
	@test "$$(uname -s)" = "Darwin" || { echo "universal requires macOS (lipo)"; exit 1; }
	lipo -create -output $(DIST)/sonar-darwin-universal $(DIST)/sonar-darwin-amd64 $(DIST)/sonar-darwin-arm64

clean:
	rm -rf $(DIST)

help:
	@echo "Targets (VERSION=$(VERSION)):"
	@echo "  all         build all 6 binaries into dist/"
	@echo "  <os>-<arch> single target: $(subst /,-,$(TARGETS))"
	@echo "  test        go test ./..."
	@echo "  vet         go vet ./..."
	@echo "  checksums   write dist/SHA256SUMS"
	@echo "  universal   macOS only: lipo amd64+arm64 into one binary"
	@echo "  generate    go generate ./internal/oui"
	@echo "  clean       remove dist/"
