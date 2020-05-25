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
#   - unit-tests - runs the go-test based unit tests
#   - checks - runs all check conditions (license, format, imports, lint and vet)
#   - docker[-clean] - builds/cleans the fabric-ca docker image
#   - docker-fvt[-clean] - builds/cleans the fabric-ca functional verification testing image
#   - release - builds fabric-ca-client binary for the host platform. Binary built with this target will not support pkcs11
#   - release-all - builds fabric-ca-client binary for all target platforms. Binaries built with this target will not support pkcs11
#   - dist - builds release package for the host platform
#   - dist-all - builds release packages for all target platforms
#   - clean - cleans the build area
#   - release-clean - cleans the binaries for all target platforms
#   - dist-clean - cleans release packages for all target platforms
#   - clean-all - cleans the build area and release packages
#   - docker-thirdparty - pulls thirdparty images (postgres)
#   - gotools - Installs go tools, such as: golint, goimports, gocov
#   - vendor - vendors third-party packages

PROJECT_NAME = fabric-ca
ALPINE_VER ?= 3.11
DEBIAN_VER ?= stretch
BASE_VERSION = 2.0.0
PREV_VERSION = 2.0.0-alpha
IS_RELEASE = false

ARCH=$(shell go env GOARCH)
MARCH=$(shell go env GOOS)-$(shell go env GOARCH)
STABLE_TAG ?= $(ARCH)-$(BASE_VERSION)-stable

ifneq ($(IS_RELEASE),true)
EXTRA_VERSION ?= snapshot-$(shell git rev-parse --short HEAD)
PROJECT_VERSION=$(BASE_VERSION)-$(EXTRA_VERSION)
FABRIC_TAG ?= latest
else
PROJECT_VERSION=$(BASE_VERSION)
FABRIC_TAG ?= $(ARCH)-$(BASE_VERSION)
endif

ifeq ($(ARCH),s390x)
PG_VER=11
else
PG_VER=11
endif

PKGNAME = github.com/hyperledger/$(PROJECT_NAME)

METADATA_VAR = Version=$(PROJECT_VERSION)

GO_VER = 1.14.1
GO_SOURCE := $(shell find . -name '*.go')
GO_LDFLAGS = $(patsubst %,-X $(PKGNAME)/lib/metadata.%,$(METADATA_VAR))
export GO_LDFLAGS

IMAGES = $(PROJECT_NAME)
FVTIMAGE = $(PROJECT_NAME)-fvt

RELEASE_PLATFORMS = linux-amd64 darwin-amd64 linux-ppc64le linux-s390x windows-amd64
RELEASE_PKGS = fabric-ca-client fabric-ca-server

TOOLS = build/tools

path-map.fabric-ca-client := cmd/fabric-ca-client
path-map.fabric-ca-server := cmd/fabric-ca-server

include docker-env.mk

all: docker unit-tests

include gotools.mk

docker: $(patsubst %,build/image/%/$(DUMMY), $(IMAGES))

docker-fvt: $(patsubst %,build/image/%/$(DUMMY), $(FVTIMAGE))

# should be removed once CI scripts are updated
docker-all: docker

# should be removed once CI scripts are updated
docker-fabric-ca: docker

changelog:
	./scripts/changelog.sh v$(PREV_VERSION) HEAD v$(BASE_VERSION)

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

docs: gotools fabric-ca-client fabric-ca-server
	@scripts/regenDocs

fabric-ca-client: bin/fabric-ca-client
fabric-ca-server: bin/fabric-ca-server

bin/%: $(GO_SOURCE)
	@echo "Building ${@F} in bin directory ..."
	@mkdir -p bin && go build -o bin/${@F} -tags "pkcs11" -ldflags "$(GO_LDFLAGS)" $(PKGNAME)/$(path-map.${@F})
	@echo "Built bin/${@F}"

build/image/fabric-ca/$(DUMMY):
	@mkdir -p $(@D)
	$(eval TARGET = ${patsubst build/image/%/$(DUMMY),%,${@}})
	@echo "Docker:  building $(TARGET) image"
	$(DBUILD) -f images/$(TARGET)/Dockerfile \
		--build-arg GO_VER=${GO_VER} \
		--build-arg GO_TAGS=pkcs11 \
		--build-arg GO_LDFLAGS="${DOCKER_GO_LDFLAGS}" \
		--build-arg ALPINE_VER=${ALPINE_VER} \
		-t $(BASE_DOCKER_NS)/$(TARGET) .
	docker tag $(BASE_DOCKER_NS)/$(TARGET) \
		$(DOCKER_NS)/$(TARGET):$(BASE_VERSION)
	docker tag $(BASE_DOCKER_NS)/$(TARGET) \
		$(DOCKER_NS)/$(TARGET):$(DOCKER_TAG)
	@touch $@

build/image/fabric-ca-fvt/$(DUMMY):
	@mkdir -p $(@D)
	$(eval TARGET = ${patsubst build/image/%/$(DUMMY),%,${@}})
	@echo "Docker:  building $(TARGET) image"
	$(DBUILD) -f images/$(TARGET)/Dockerfile \
		--build-arg GO_VER=${GO_VER} \
		--build-arg GO_TAGS=pkcs11 \
		--build-arg GO_LDFLAGS="${DOCKER_GO_LDFLAGS}" \
		--build-arg PG_VER=${PG_VER} \
		-t $(BASE_DOCKER_NS)/$(TARGET) .
	@touch $@


all-tests: gotools fabric-ca-server fabric-ca-client
	@scripts/run_unit_tests
	@scripts/run_integration_tests

unit-tests: gotools fabric-ca-server fabric-ca-client
	@scripts/run_unit_tests

unit-test: unit-tests

int-tests: gotools fabric-ca-server fabric-ca-client
	@scripts/run_integration_tests

vendor: .FORCE
	@echo > go.mod
	@go mod tidy -modfile vendor.mod
	@go mod vendor  -modfile vendor.mod
	@rm go.mod

container-tests: docker

load-test: docker-clean docker-fvt
	@docker run -p 8888:8888 -p 8054:8054 -v $(shell pwd):/opt/gopath/src/github.com/hyperledger/fabric-ca -e FABRIC_CA_SERVER_PROFILE_PORT=8054 --name loadTest -td hyperledger/fabric-ca-fvt test/fabric-ca-load-tester/launchServer.sh 3
	@test/fabric-ca-load-tester/runLoad.sh -B
	@docker kill loadTest

ci-tests: all-tests docs fvt-tests

fvt-tests: docker-clean docker-fvt
	@docker run -v $(shell pwd):/opt/gopath/src/github.com/hyperledger/fabric-ca ${DOCKER_NS}/fabric-ca-fvt

%-docker-clean:
	$(eval TARGET = ${patsubst %-docker-clean,%,${@}})
	-docker images -q $(DOCKER_NS)/$(TARGET):latest | xargs -I '{}' docker rmi -f '{}'
	-docker images -q $(NEXUS_URL)/*:$(STABLE_TAG) | xargs -I '{}' docker rmi -f '{}'
	-@rm -rf build/image/$(TARGET) ||:

docker-clean: $(patsubst %,%-docker-clean, $(IMAGES) $(PROJECT_NAME)-fvt)
	@rm -rf build/docker/bin/* ||:

native: fabric-ca-client fabric-ca-server

release: $(patsubst %,release/%, $(MARCH))
release-all: $(patsubst %,release/%, $(RELEASE_PLATFORMS))

release/windows-amd64: GOOS=windows
release/windows-amd64: CC=/usr/bin/x86_64-w64-mingw32-gcc
release/windows-amd64: $(patsubst %,release/windows-amd64/bin/%, $(RELEASE_PKGS))

release/darwin-amd64: GOOS=darwin
release/darwin-amd64: CC=/usr/bin/clang
release/darwin-amd64: $(patsubst %,release/darwin-amd64/bin/%, $(RELEASE_PKGS))

release/linux-amd64: GOOS=linux
release/linux-amd64: $(patsubst %,release/linux-amd64/bin/%, $(RELEASE_PKGS))

release/%-amd64: GOARCH=amd64

release/linux-%: GOOS=linux

release/linux-ppc64le: GOARCH=ppc64le
release/linux-ppc64le: CC=/usr/bin/powerpc64le-linux-gnu-gcc
release/linux-ppc64le: $(patsubst %,release/linux-ppc64le/bin/%, $(RELEASE_PKGS))

release/linux-s390x: GOARCH=s390x
release/linux-s390x: $(patsubst %,release/linux-s390x/bin/%, $(RELEASE_PKGS))

release/%/bin/fabric-ca-client: GO_TAGS+= caclient
release/%/bin/fabric-ca-client: $(GO_SOURCE)
	@echo "Building $@ for $(GOOS)-$(GOARCH)"
	mkdir -p $(@D)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(abspath $@) -tags "$(GO_TAGS)" -ldflags "$(GO_LDFLAGS)" $(PKGNAME)/$(path-map.$(@F))

release/%/bin/fabric-ca-server: $(GO_SOURCE)
	@echo "Building $@ for $(GOOS)-$(GOARCH)"
	mkdir -p $(@D)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(abspath $@) -tags "$(GO_TAGS)" -ldflags "$(GO_LDFLAGS)" $(PKGNAME)/$(path-map.$(@F))

# Pull thirdparty docker images
# Currently the target is available but unused. If you are implementing a new
# test using the ifrit DB runners, you must add the docker-thirdparty target
# to the test target you are running i.e. (unit-tests, int-tests, all-tests).
.PHONY: docker-thirdparty
docker-thirdparty:
	docker pull postgres:9.6
	docker pull mysql:5.7

.PHONY: dist
dist: dist-clean release
	cd release/$(MARCH) && tar -czvf hyperledger-fabric-ca-$(MARCH)-$(PROJECT_VERSION).tar.gz *
dist-all: dist-clean release-all $(patsubst %,dist/%, $(RELEASE_PLATFORMS))
dist/windows-amd64:
	cd release/windows-amd64 && tar -czvf hyperledger-fabric-ca-windows-amd64-$(PROJECT_VERSION).tar.gz *
dist/darwin-amd64:
	cd release/darwin-amd64 && tar -czvf hyperledger-fabric-ca-darwin-amd64-$(PROJECT_VERSION).tar.gz *
dist/linux-amd64:
	cd release/linux-amd64 && tar -czvf hyperledger-fabric-ca-linux-amd64-$(PROJECT_VERSION).tar.gz *
dist/linux-ppc64le:
	cd release/linux-ppc64le && tar -czvf hyperledger-fabric-ca-linux-ppc64le-$(PROJECT_VERSION).tar.gz *
dist/linux-s390x:
	cd release/linux-s390x && tar -czvf hyperledger-fabric-ca-linux-s390x-$(PROJECT_VERSION).tar.gz *

.PHONY: clean
clean: docker-clean release-clean
	-@rm -rf build bin ||:

.PHONY: clean-all
clean-all: clean dist-clean

%-release-clean:
	$(eval TARGET = ${patsubst %-release-clean,%,${@}})
	-@rm -rf release/$(TARGET)
release-clean: $(patsubst %,%-release-clean, $(RELEASE_PLATFORMS))

.PHONY: dist-clean
dist-clean:
	-@rm -rf release/windows-amd64/hyperledger-fabric-ca-windows-amd64-$(PROJECT_VERSION).tar.gz ||:
	-@rm -rf release/darwin-amd64/hyperledger-fabric-ca-darwin-amd64-$(PROJECT_VERSION).tar.gz ||:
	-@rm -rf release/linux-amd64/hyperledger-fabric-ca-linux-amd64-$(PROJECT_VERSION).tar.gz ||:
	-@rm -rf release/linux-ppc64le/hyperledger-fabric-ca-linux-ppc64le-$(PROJECT_VERSION).tar.gz ||:
	-@rm -rf release/linux-s390x/hyperledger-fabric-ca-linux-s390x-$(PROJECT_VERSION).tar.gz ||:

.FORCE:
