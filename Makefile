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
#   - docker[-clean] - ensures all docker images are available[/cleaned]
#   - docker-fabric-ca - build the fabric-ca docker image
#   - bench - Runs benchmarks in all the packages and stores the results in /tmp/bench.results
#   - bench-cpu - Runs the benchmarks in the specified package with cpu profiling
#   - bench-mem - Runs the benchmarks in the specified package with memory profiling
#   - bench-clean - Removes all benchmark related files
#   - benchcmp - Compares benchmarks results of current and previous release
#   - release - builds fabric-ca-client binary for the host platform. Binary built with this target will not support pkcs11
#   - release-all - builds fabric-ca-client binary for all target platforms. Binaries built with this target will not support pkcs11
#   - dist - builds release package for the host platform
#   - dist-all - builds release packages for all target platforms
#   - clean - cleans the build area
#   - release-clean - cleans the binaries for all target platforms
#   - dist-clean - cleans release packages for all target platforms
#   - clean-all - cleans the build area and release packages

PROJECT_NAME = fabric-ca
BASE_VERSION = 1.4.4
PREV_VERSION = 1.4.3
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
PGVER=10
else
PGVER=10
endif

BASEIMAGE_RELEASE = 0.4.16
PKGNAME = github.com/hyperledger/$(PROJECT_NAME)

METADATA_VAR = Version=$(PROJECT_VERSION)

GO_SOURCE := $(shell find . -name '*.go')
GO_LDFLAGS = $(patsubst %,-X $(PKGNAME)/lib/metadata.%,$(METADATA_VAR))
export GO_LDFLAGS

IMAGES = $(PROJECT_NAME)
FVTIMAGE = $(PROJECT_NAME)-fvt

RELEASE_PLATFORMS = linux-amd64 darwin-amd64 linux-ppc64le linux-s390x windows-amd64
RELEASE_PKGS = fabric-ca-client

path-map.fabric-ca-client := cmd/fabric-ca-client
path-map.fabric-ca-server := cmd/fabric-ca-server

include docker-env.mk

all: rename docker unit-tests

rename: .FORCE
	@scripts/rename-repo

docker: $(patsubst %,build/image/%/$(DUMMY), $(IMAGES))

docker-all: docker

docker-fabric-ca: docker

docker-fvt: $(patsubst %,build/image/%/$(DUMMY), $(FVTIMAGE))

changelog:
	./scripts/changelog.sh v$(PREV_VERSION) HEAD v$(BASE_VERSION)

checks: license vet lint format imports

license: .FORCE
	@scripts/check_license

format: .FORCE
	@scripts/check_format

imports: .FORCE
	@scripts/check_imports

lint: .FORCE
	@scripts/check_lint

vet: .FORCE
	@scripts/check_vet

docs: fabric-ca-client fabric-ca-server
	@scripts/regenDocs

fabric-ca-client: bin/fabric-ca-client
fabric-ca-server: bin/fabric-ca-server

bin/%: $(GO_SOURCE)
	@echo "Building ${@F} in bin directory ..."
	@mkdir -p bin && go build -o bin/${@F} -tags "pkcs11" -ldflags "$(GO_LDFLAGS)" $(PKGNAME)/$(path-map.${@F})
	@echo "Built bin/${@F}"

# We (re)build a package within a docker context but persist the $GOPATH/pkg
# directory so that subsequent builds are faster
build/docker/bin/%:
	@echo "Building $@"
	@mkdir -p $(@D) build/docker/$(@F)/pkg
	@$(DRUN) \
		-v $(abspath build/docker/bin):/opt/gopath/bin \
		-v $(abspath build/docker/$(@F)/pkg):/opt/gopath/pkg \
		$(BASE_DOCKER_NS)/fabric-baseimage:$(BASE_DOCKER_TAG) \
		go install -ldflags "$(DOCKER_GO_LDFLAGS)" $(PKGNAME)/$(path-map.${@F})
	@touch $@

build/image/%/$(DUMMY): Makefile build/image/%/payload
	$(eval TARGET = ${patsubst build/image/%/$(DUMMY),%,${@}})
	$(eval DOCKER_NAME = $(DOCKER_NS)/$(TARGET))
	@echo "Building docker $(TARGET) image"
	@cat images/$(TARGET)/Dockerfile.in \
		| sed -e 's|_BASE_NS_|$(BASE_DOCKER_NS)|g' \
		| sed -e 's|_NS_|$(DOCKER_NS)|g' \
		| sed -e 's|_NEXUS_REPO_|$(NEXUS_URL)|g' \
		| sed -e 's|_BASE_TAG_|$(BASE_DOCKER_TAG)|g' \
		| sed -e 's|_FABRIC_TAG_|$(FABRIC_TAG)|g' \
		| sed -e 's|_STABLE_TAG_|$(STABLE_TAG)|g' \
		| sed -e 's|_TAG_|$(DOCKER_TAG)|g' \
		| sed -e 's|_PGVER_|$(PGVER)|g' \
		> $(@D)/Dockerfile
	$(DBUILD) -t $(DOCKER_NAME) --build-arg FABRIC_CA_DYNAMIC_LINK=$(FABRIC_CA_DYNAMIC_LINK) $(@D)
	docker tag $(DOCKER_NAME) $(DOCKER_NAME):$(DOCKER_TAG)
	@touch $@

build/image/fabric-ca/payload: \
	build/docker/bin/fabric-ca-client \
	build/docker/bin/fabric-ca-server \
	build/fabric-ca.tar.bz2
build/image/fabric-ca-fvt/payload: \
	build/docker/bin/fabric-ca-client \
	build/docker/bin/fabric-ca-server \
	build/fabric-ca-fvt.tar.bz2
build/image/%/payload:
	@echo "Copying $^ to $@"
	mkdir -p $@
	cp $^ $@

build/fabric-ca.tar.bz2: $(shell git ls-files images/fabric-ca/payload)

build/fabric-ca-fvt.tar.bz2: $(shell find images/fabric-ca-fvt/payload/ -maxdepth 1)

build/%.tar.bz2:
	@echo "Building $@"
	@tar -jc -C images/$*/payload $(notdir $^) > $@

all-tests: checks fabric-ca-server fabric-ca-client
	@scripts/run_unit_tests
	@scripts/run_integration_tests

unit-tests: fabric-ca-server fabric-ca-client
	@scripts/run_unit_tests

unit-test: unit-tests

int-tests: checks fabric-ca-server fabric-ca-client
	@scripts/run_integration_tests

# Runs benchmarks in all the packages and stores the benchmarks in /tmp/bench.results
bench: checks fabric-ca-server fabric-ca-client
	@scripts/run_benchmarks

# Runs benchmarks in the specified package with cpu profiling
# e.g. make bench-cpu pkg=github.com/hyperledger/fabric-ca/lib
bench-cpu: checks fabric-ca-server fabric-ca-client
	@scripts/run_benchmarks -C -P $(pkg)

# Runs benchmarks in the specified package with memory profiling
# e.g. make bench-mem pkg=github.com/hyperledger/fabric-ca/lib
bench-mem: checks fabric-ca-server fabric-ca-client
	@scripts/run_benchmarks -M -P $(pkg)

# e.g. make benchcmp prev_rel=v1.0.0
benchcmp: guard-prev_rel bench
	@scripts/compare_benchmarks $(prev_rel)

guard-%:
	@if [ "${${*}}" = "" ]; then \
		echo "Environment variable $* not set"; \
		exit 1; \
	fi


# Removes all benchmark related files (bench, bench-cpu, bench-mem and *.test)
bench-clean:
	@scripts/run_benchmarks -R

container-tests: docker

load-test: docker-clean docker-fvt
	@docker run -p 8888:8888 -p 8054:8054 -v $(shell pwd):/opt/gopath/src/github.com/hyperledger/fabric-ca -e FABRIC_CA_SERVER_PROFILE_PORT=8054 --name loadTest -td hyperledger/fabric-ca-fvt test/fabric-ca-load-tester/launchServer.sh 3
	@test/fabric-ca-load-tester/runLoad.sh -B
	@docker kill loadTest

fvt-tests:
	@scripts/run_fvt_tests

ci-tests: docker-clean all-tests docker-fvt docs
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
release/windows-amd64: GO_TAGS+= caclient
release/windows-amd64: $(patsubst %,release/windows-amd64/bin/%, $(RELEASE_PKGS))

release/darwin-amd64: GOOS=darwin
release/darwin-amd64: CC=/usr/bin/clang
release/darwin-amd64: GO_TAGS+= caclient
release/darwin-amd64: $(patsubst %,release/darwin-amd64/bin/%, $(RELEASE_PKGS))

release/linux-amd64: GOOS=linux
release/linux-amd64: GO_TAGS+= caclient
release/linux-amd64: $(patsubst %,release/linux-amd64/bin/%, $(RELEASE_PKGS))

release/%-amd64: GOARCH=amd64

release/linux-%: GOOS=linux

release/linux-ppc64le: GOARCH=ppc64le
release/linux-ppc64le: GO_TAGS+= caclient
release/linux-ppc64le: CC=/usr/bin/powerpc64le-linux-gnu-gcc
release/linux-ppc64le: $(patsubst %,release/linux-ppc64le/bin/%, $(RELEASE_PKGS))

release/linux-s390x: GOARCH=s390x
release/linux-s390x: GO_TAGS+= caclient
release/linux-s390x: $(patsubst %,release/linux-s390x/bin/%, $(RELEASE_PKGS))

release/%/bin/fabric-ca-client: $(GO_SOURCE)
	@echo "Building $@ for $(GOOS)-$(GOARCH)"
	mkdir -p $(@D)
	GOOS=$(GOOS) GOARCH=$(GOARCH) go build -o $(abspath $@) -tags "$(GO_TAGS)" -ldflags "$(GO_LDFLAGS)" $(PKGNAME)/$(path-map.$(@F))

.PHONY: dist
dist: dist-clean release
	cd release/$(MARCH) && tar -czvf hyperledger-fabric-ca-$(MARCH).$(PROJECT_VERSION).tar.gz *
dist-all: dist-clean release-all $(patsubst %,dist/%, $(RELEASE_PLATFORMS))
dist/windows-amd64:
	cd release/windows-amd64 && tar -czvf hyperledger-fabric-ca-windows-amd64.$(PROJECT_VERSION).tar.gz *
dist/darwin-amd64:
	cd release/darwin-amd64 && tar -czvf hyperledger-fabric-ca-darwin-amd64.$(PROJECT_VERSION).tar.gz *
dist/linux-amd64:
	cd release/linux-amd64 && tar -czvf hyperledger-fabric-ca-linux-amd64.$(PROJECT_VERSION).tar.gz *
dist/linux-ppc64le:
	cd release/linux-ppc64le && tar -czvf hyperledger-fabric-ca-linux-ppc64le.$(PROJECT_VERSION).tar.gz *
dist/linux-s390x:
	cd release/linux-s390x && tar -czvf hyperledger-fabric-ca-linux-s390x.$(PROJECT_VERSION).tar.gz *

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
	-@rm -rf release/windows-amd64/hyperledger-fabric-ca-windows-amd64.$(PROJECT_VERSION).tar.gz ||:
	-@rm -rf release/darwin-amd64/hyperledger-fabric-ca-darwin-amd64.$(PROJECT_VERSION).tar.gz ||:
	-@rm -rf release/linux-amd64/hyperledger-fabric-ca-linux-amd64.$(PROJECT_VERSION).tar.gz ||:
	-@rm -rf release/linux-ppc64le/hyperledger-fabric-ca-linux-ppc64le.$(PROJECT_VERSION).tar.gz ||:
	-@rm -rf release/linux-s390x/hyperledger-fabric-ca-linux-s390x.$(PROJECT_VERSION).tar.gz ||:

.FORCE:

generate-metrics-doc:
	@echo "Generating metrics reference documentation..."
	@./scripts/metrics_doc.sh
