# Copyright the Hyperledger Fabric contributors. All rights reserved.
#
# SPDX-License-Identifier: Apache-2.0

GOTOOLS = gendoc gocov gocov-xml goimports golint

.PHONY: gotools
gotools: $(patsubst %,build/tools/%, $(GOTOOLS))

build/tools/%: tools/go.mod tools/tools.go
	@mkdir -p $(@D)
	@$(eval TOOL = ${subst build/tools/,,${@}})
	@$(eval FQP = $(shell grep ${TOOL} tools/tools.go | cut -d " " -f2 | grep ${TOOL}\"$))
	@echo Installing ${TOOL} at ${CURDIR}/$(TOOLS) from ${FQP}
	@cd tools && GO111MODULE=on GOBIN=${CURDIR}/$(TOOLS) go install ${FQP}