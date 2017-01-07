# Copyright IBM Corp All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#		 http://www.apache.org/licenses/LICENSE-2.0
#
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
#   - cop - builds the cop executable
#   - unit-tests - Performs checks first and runs the go-test based unit tests
#   - checks - runs all check conditions (license, format, imports, lint and vet)
#   - ldap-tests - runs the LDAP tests
#   - docker[-clean] - ensures all docker images are available[/cleaned]
#   - clean - cleans the build area

PROJECT_NAME   = fabric-cop
BASE_VERSION   = 0.7.0
IS_RELEASE     = false

ifneq ($(IS_RELEASE),true)
EXTRA_VERSION ?= snapshot-$(shell git rev-parse --short HEAD)
PROJECT_VERSION=$(BASE_VERSION)-$(EXTRA_VERSION)
else
PROJECT_VERSION=$(BASE_VERSION)
endif

# Check that all dependencies are installed
EXECUTABLES = go docker git curl
K := $(foreach exec,$(EXECUTABLES),\
	$(if $(shell which $(exec)),some string,$(error "No $(exec) in PATH: Check dependencies")))

ARCH=$(shell uname -m)
BASEIMAGE_RELEASE = 0.2.2
PKGNAME = github.com/hyperledger/$(PROJECT_NAME)
SAMPLECONFIG = $(shell git ls-files images/cop/config)

DOCKER_ORG = hyperledger
IMAGES = $(PROJECT_NAME) $(PROJECT_NAME)-runtime

image-path-map.fabric-cop         := cop
image-path-map.fabric-cop-runtime := runtime

include docker-env.mk

all: docker unit-tests

docker: $(patsubst %,build/image/%/$(DUMMY), $(IMAGES))

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

cop:
	@echo "Building cop in bin directory ..."
	@mkdir -p bin && cd cli && go build -o ../bin/cop
	@echo "Built bin/cop"

# We (re)build a package within a docker context but persist the $GOPATH/pkg
# directory so that subsequent builds are faster
build/docker/bin/cop:
	@echo "Building $@"
	@mkdir -p $(@D) build/docker/$(@F)/pkg
	@$(DRUN) \
		-v $(abspath build/docker/bin):/opt/gopath/bin \
		-v $(abspath build/docker/$(@F)/pkg):/opt/gopath/pkg \
		hyperledger/fabric-baseimage:$(BASE_DOCKER_TAG) \
		go install -ldflags "$(DOCKER_GO_LDFLAGS)" $(PKGNAME)/cli
	mv build/docker/bin/cli $@
	@touch $@

build/docker/busybox:
	@echo "Building $@"
	@$(DRUN) \
		hyperledger/fabric-baseimage:$(BASE_DOCKER_TAG) \
		make -f busybox/Makefile install BINDIR=$(@D)

build/image/$(PROJECT_NAME)/$(DUMMY): build/image/$(PROJECT_NAME)-runtime/$(DUMMY)

# payload definitions
build/image/$(PROJECT_NAME)/payload:	build/docker/bin/cop \
					build/sampleconfig.tar.bz2
build/image/$(PROJECT_NAME)-runtime/payload:	build/docker/busybox

build/image/%/payload:
	mkdir -p $@
	cp $^ $@

build/image/%/$(DUMMY): Makefile build/image/%/payload
	$(eval TARGET = ${patsubst build/image/%/$(DUMMY),%,${@}})
	$(eval DOCKER_NAME = $(DOCKER_ORG)/$(TARGET))
	@echo "Building docker $(TARGET) image"
	@cat images/$(image-path-map.$(TARGET))/Dockerfile.in \
		| sed -e 's/_BASE_TAG_/$(BASE_DOCKER_TAG)/g' \
		| sed -e 's/_TAG_/$(DOCKER_TAG)/g' \
		> $(@D)/Dockerfile
	$(DBUILD) -t $(DOCKER_NAME) $(@D)
	docker tag $(DOCKER_NAME) $(DOCKER_NAME):$(DOCKER_TAG)
	@touch $@

build/sampleconfig.tar.bz2: $(SAMPLECONFIG)
	tar -jc -C images/cop/config $(patsubst images/cop/config/%,%,$(SAMPLECONFIG)) > $@

unit-tests: checks cop
	@scripts/run_tests

container-tests: ldap-tests

ldap-tests:
	@scripts/run_ldap_tests

%-docker-clean:
	$(eval TARGET = ${patsubst %-docker-clean,%,${@}})
	-docker images -q $(DOCKER_ORG)/$(TARGET):latest | xargs -I '{}' docker rmi -f '{}'
	-@rm -rf build/image/$(TARGET) ||:

docker-clean: $(patsubst %,%-docker-clean, $(IMAGES))

.PHONY: clean
clean: docker-clean
	-@rm -rf build bin ||:

.FORCE:
