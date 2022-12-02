# Copyright IBM Corp All Rights Reserved.
# Copyright London Stock Exchange Group All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# -------------------------------------------------------------
# This makefile defines the following targets
#
#   - all (default) - builds all targets and runs all tests
#   - license - check all go files for license headers
#   - fabric-ca-server - builds the fabric-ca-server executable
#   - fabric-ca-client - builds the fabric-ca-client executable
#   - all-tests - runs unit and integration tests
#   - int-tests - runs the go-test based integration tests
#   - unit-tests - runs the go-test based unit tests
#   - checks - runs all check conditions (license, format, imports, lint and vet)
#   - docker - builds/cleans the fabric-ca docker image
#   - docker-fvt - builds/cleans the fabric-ca functional verification testing image
#   - release - builds fabric-ca-client binary for the host platform. Binary built with this target will not support pkcs11
#   - dist - builds release package for the host platform
#   - clean - cleans the build area
#   - release-clean - cleans the binaries for all target platforms
#   - dist-clean - cleans release packages for all target platforms
#   - clean-all - cleans the build area and release packages
#   - gotools - Installs go tools, such as: golint, goimports, gocov
#   - vendor - vendors third-party packages

PROJECT_NAME 		= fabric-ca
VERSION            ?= $(shell git describe --tags `git rev-list --tags --max-count=1`)

GO_VER 				= 1.18.8
ALPINE_VER 			= 3.17
DEBIAN_VER			= buster-20221114

ARCH				= $(shell go env GOARCH)
OS					= $(shell go env GOOS)
PLATFORM			= $(OS)-$(ARCH)
RELEASE_PLATFORMS 	= linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64
RELEASE_PKGS 		= fabric-ca-server fabric-ca-client
PG_VER				= 11
PKGNAME				= github.com/hyperledger/$(PROJECT_NAME)
METADATA_VAR		= Version=$(VERSION)
GO_SOURCE 			= $(shell find . -name '*.go')
GO_TAGS             = pkcs11
GO_LDFLAGS 			= $(patsubst %,-X $(PKGNAME)/lib/metadata.%,$(METADATA_VAR))
TOOLS 				= build/tools
DOCKER_BUILD       ?= docker build    # qemu, e.g: docker buildx build --platform linux/arm64
DOCKER_REGISTRY    ?= docker.io/hyperledger
DOCKER_IMAGE 		= $(DOCKER_REGISTRY)/fabric-ca
DOCKER_FVT_IMAGE    = $(DOCKER_REGISTRY)/fabric-ca-fvt
DOCKER_GO_LDFLAGS  += $(GO_LDFLAGS)
DOCKER_GO_LDFLAGS  += -linkmode external -extldflags '-lpthread -static'

path-map.fabric-ca-client := cmd/fabric-ca-client
path-map.fabric-ca-server := cmd/fabric-ca-server

export GO_LDFLAGS

default: all

all: fabric-ca-server fabric-ca-client docker

checks: license vet lint format imports

license: .FORCE
	@scripts/check_license

format: .FORCE
	@scripts/check_format

imports: $(TOOLS)/goimports
	@scripts/check_imports

lint: $(TOOLS)/golint
	@scripts/check_lint

vet: .FORCE
	@scripts/check_vet

include gotools.mk

docs: gotools fabric-ca-client fabric-ca-server
	@scripts/regenDocs

fabric-ca-client: bin/fabric-ca-client
fabric-ca-server: bin/fabric-ca-server

bin/%: $(GO_SOURCE)
	mkdir -p bin && go build -o bin/${@F} -tags "$(GO_TAGS)" -ldflags "$(GO_LDFLAGS)" $(PKGNAME)/$(path-map.${@F})

docker:
	$(DOCKER_BUILD) \
		--build-arg GO_VER=${GO_VER} \
		--build-arg GO_TAGS=${GO_TAGS} \
		--build-arg GO_LDFLAGS="${DOCKER_GO_LDFLAGS}" \
		--build-arg ALPINE_VER=${ALPINE_VER} \
		-t $(DOCKER_IMAGE) \
		.


# The debian test image includes software which has not been ported to arm64.
# To run this test locally on an arm / M1, use buildx to emulate an amd64:
# DOCKER_BUILD="docker buildx build --platform linux/amd64"
docker-fvt:
	$(DOCKER_BUILD) \
		-f images/fabric-ca-fvt/Dockerfile \
		--build-arg DEBIAN_VER=${DEBIAN_VER} \
		--build-arg GO_VER=${GO_VER} \
		--build-arg GO_TAGS=${GO_TAGS} \
		--build-arg GO_LDFLAGS="${DOCKER_GO_LDFLAGS}" \
		--build-arg PG_VER=${PG_VER} \
		-t $(DOCKER_FVT_IMAGE) \
		.

test: unit-tests

all-tests: unit-tests int-tests

int-tests: gotools fabric-ca-server fabric-ca-client
	@scripts/run_integration_tests

unit-tests: gotools fabric-ca-server fabric-ca-client
	@scripts/run_unit_tests

unit-test: unit-tests

vendor: .FORCE
	@go mod tidy
	@go mod vendor

fvt-tests: docker-fvt
	@docker run \
		--rm \
		-v $(shell pwd):/build/fabric-ca \
		$(DOCKER_FVT_IMAGE)

release: $(patsubst %,release/%, $(PLATFORM))

release/windows-%: 	GOOS=windows
release/linux-%: 	GOOS=linux
release/darwin-%:	GOOS=darwin

release/%-amd64: 	GOARCH=amd64
release/%-arm64: 	GOARCH=arm64

release/windows-amd64: CC=x86_64-w64-mingw32-gcc
release/windows-amd64: $(patsubst %,release/windows-amd64/bin/%, $(RELEASE_PKGS))

release/darwin-amd64: CC=clang
release/darwin-amd64: $(patsubst %,release/darwin-amd64/bin/%, $(RELEASE_PKGS))

release/darwin-arm64: CC=clang
release/darwin-arm64: $(patsubst %,release/darwin-arm64/bin/%, $(RELEASE_PKGS))

release/linux-amd64: CC=x86_64-linux-gnu-gcc
release/linux-amd64: $(patsubst %,release/linux-amd64/bin/%, $(RELEASE_PKGS))

release/linux-arm64: CC=aarch64-linux-gnu-gcc
release/linux-arm64: $(patsubst %,release/linux-arm64/bin/%, $(RELEASE_PKGS))

release/%/bin/fabric-ca-client: GO_TAGS+= caclient
release/%/bin/fabric-ca-client: $(GO_SOURCE)
	mkdir -p $(@D)
	CC=$(CC) CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(abspath $@) -tags "$(GO_TAGS)" -ldflags "$(GO_LDFLAGS)" $(PKGNAME)/$(path-map.$(@F))

release/%/bin/fabric-ca-server: $(GO_SOURCE)
	mkdir -p $(@D)
	CC=$(CC) CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(abspath $@) -tags "$(GO_TAGS)" -ldflags "$(GO_LDFLAGS)" $(PKGNAME)/$(path-map.$(@F))

.PHONY: dist
dist: dist/$(PLATFORM)

dist/%: release/%
	$(eval PLATFORM = ${patsubst dist/%,%,${@}})
	tar -zcvf release/hyperledger-fabric-ca-$(PLATFORM)-$(VERSION).tar.gz -C release/$(PLATFORM) bin

.PHONY: clean
clean: release-clean
	-@rm -rf build bin ||:

.PHONY: clean-all
clean-all: clean dist-clean

release-clean:
	-@rm -rf release/

.PHONY: dist-clean
dist-clean:
	-@rm -rf release/*.tar.gz ||:

.FORCE:
