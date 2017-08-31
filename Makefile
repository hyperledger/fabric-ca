# Copyright IBM Corp All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#		 http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# -------------------------------------------------------------
# This makefile defines the following targets
#
#   - all (default) - builds all targets and runs all tests
#   - license - check all go files for license headers
#   - fabric-ca-server - builds the fabric-ca-server executable
#   - fabric-ca-client - builds the fabric-ca-client executable
#   - unit-tests - Performs checks first and runs the go-test based unit tests
#   - checks - runs all check conditions (license, format, imports, lint and vet)
#   - docker[-clean] - ensures all docker images are available[/cleaned]
#   - bench - Runs benchmarks in all the packages and stores the results in /tmp/bench.results
#   - bench-cpu - Runs the benchmarks in the specified package with cpu profiling
#   - bench-mem - Runs the benchmarks in the specified package with memory profiling
#   - bench-clean - Removes all benchmark related files
#   - benchcmp - Compares benchmarks results of current and previous release
#   - clean - cleans the build area

PROJECT_NAME   = fabric-ca
BASE_VERSION   = 1.0.1
PREV_VERSION   = 1.0.0
IS_RELEASE     = false

ifneq ($(IS_RELEASE),true)
EXTRA_VERSION ?= snapshot-$(shell git rev-parse --short HEAD)
PROJECT_VERSION=$(BASE_VERSION)-$(EXTRA_VERSION)
else
PROJECT_VERSION=$(BASE_VERSION)
endif

ARCH=$(shell uname -m)
ifeq ($(ARCH),s390x)
PGVER=9.4
else
PGVER=9.5
endif

BASEIMAGE_RELEASE = 0.3.1
PKGNAME = github.com/hyperledger/$(PROJECT_NAME)

METADATA_VAR = Version=$(PROJECT_VERSION)

GO_SOURCE := $(shell find . -name '*.go')
GO_LDFLAGS = $(patsubst %,-X $(PKGNAME)/cmd.%,$(METADATA_VAR))
export GO_LDFLAGS

DOCKER_ORG = hyperledger
IMAGES = $(PROJECT_NAME)
FVTIMAGE = $(PROJECT_NAME)-fvt

path-map.fabric-ca-client := ./cmd/fabric-ca-client
path-map.fabric-ca-server := ./cmd/fabric-ca-server

include docker-env.mk

all: rename docker unit-tests

rename: .FORCE
	@scripts/rename-repo

docker: $(patsubst %,build/image/%/$(DUMMY), $(IMAGES))

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
	@mkdir -p bin && go build -o bin/${@F} -ldflags "$(GO_LDFLAGS)" $(path-map.${@F})
	@echo "Built bin/${@F}"

# We (re)build a package within a docker context but persist the $GOPATH/pkg
# directory so that subsequent builds are faster
build/docker/bin/%:
	@echo "Building $@"
	@mkdir -p $(@D) build/docker/$(@F)/pkg
	@$(DRUN) \
		-v $(abspath build/docker/bin):/opt/gopath/bin \
		-v $(abspath build/docker/$(@F)/pkg):/opt/gopath/pkg \
		hyperledger/fabric-baseimage:$(BASE_DOCKER_TAG) \
		go install -ldflags "$(DOCKER_GO_LDFLAGS)" $(PKGNAME)/$(path-map.${@F})
	@touch $@

build/docker/busybox:
	@echo "Building $@"
	@$(DRUN) \
		hyperledger/fabric-baseimage:$(BASE_DOCKER_TAG) \
		make -f busybox/Makefile install BINDIR=$(@D)

build/image/%/$(DUMMY): Makefile build/image/%/payload
	$(eval TARGET = ${patsubst build/image/%/$(DUMMY),%,${@}})
	$(eval DOCKER_NAME = $(DOCKER_ORG)/$(TARGET))
	@echo "Building docker $(TARGET) image"
	@cat images/$(TARGET)/Dockerfile.in \
		| sed -e 's/_BASE_TAG_/$(BASE_DOCKER_TAG)/g' \
		| sed -e 's/_TAG_/$(DOCKER_TAG)/g' \
		| sed -e 's/_PGVER_/$(PGVER)/g' \
		> $(@D)/Dockerfile
	$(DBUILD) -t $(DOCKER_NAME) $(@D)
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

unit-tests: checks fabric-ca-server fabric-ca-client
	@scripts/run_tests

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

# Removes all benchmark related files (bench, bench-cpu, bench-mem and *.test)
bench-clean:
	@scripts/run_benchmarks -R

# Compares benchmarks results of current and previous release
# Previous release git tag must be specified using the prev_rel variable.
# e.g. make benchcmp prev_rel=v1.0.0
benchcmp: guard-prev_rel bench
	@scripts/compare_benchmarks $(prev_rel)

guard-%:
	@ if [ "${${*}}" = "" ]; then \
		echo "Environment variable $* not set"; \
		exit 1; \
	fi

container-tests: docker

load-test: docker-clean docker-fvt
	@docker run -p 8888:8888 -p 8054:8054 -v $(shell pwd):/opt/gopath/src/github.com/hyperledger/fabric-ca -e FABRIC_CA_SERVER_PROFILE_PORT=8054 --name loadTest -td hyperledger/fabric-ca-fvt test/fabric-ca-load-tester/launchServer.sh 3
	@test/fabric-ca-load-tester/runLoad.sh -B
	@docker kill loadTest

fvt-tests:
	@scripts/run_fvt_tests

ci-tests: docker-clean docker-fvt unit-tests
	@docker run -v $(shell pwd):/opt/gopath/src/github.com/hyperledger/fabric-ca hyperledger/fabric-ca-fvt

%-docker-clean:
	$(eval TARGET = ${patsubst %-docker-clean,%,${@}})
	-docker images -q $(DOCKER_ORG)/$(TARGET):latest | xargs -I '{}' docker rmi -f '{}'
	-@rm -rf build/image/$(TARGET) ||:

docker-clean: $(patsubst %,%-docker-clean, $(IMAGES) $(PROJECT_NAME)-fvt)
	@rm -rf build/docker/bin/* ||:

.PHONY: clean

clean: docker-clean
	-@rm -rf build bin ||:

.FORCE:
