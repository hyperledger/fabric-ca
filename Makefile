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
#   - clean - cleans the build area

PROJECT_NAME   = fabric-ca
BASE_VERSION   = 1.0.0-alpha3
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

fabric-ca-client: bin/fabric-ca-client
fabric-ca-server: bin/fabric-ca-server

bin/%:
	@echo "Building ${@F} in bin directory ..."
	@mkdir -p bin && go build -o bin/${@F} $(path-map.${@F})
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
	images/fabric-ca-fvt/base.ldif \
	images/fabric-ca-fvt/add-users.ldif \
	images/fabric-ca-fvt/start.sh
build/image/%/payload:
	@echo "Copying $^ to $@"
	mkdir -p $@
	cp $^ $@

build/fabric-ca.tar.bz2: $(shell git ls-files images/fabric-ca/payload)

build/%.tar.bz2:
	@echo "Building $@"
	@tar -jc -C images/$*/payload $(notdir $^) > $@

unit-tests: checks fabric-ca-server fabric-ca-client
	@scripts/run_tests

container-tests: docker

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
