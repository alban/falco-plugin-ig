#
# Copyright (C) 2021 The Falco Authors.
# Copyright (C) 2023 The Inspektor Gadget authors.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#

SHELL=/bin/bash -o pipefail
GO ?= go

NAME := ig
OUTPUT := libfalco-plugin-$(NAME).so

CONTAINER_REPO ?= ghcr.io/inspektor-gadget/falco-with-ig
IMAGE_TAG ?= latest
PLATFORMS ?= "linux/amd64,linux/arm64"

OCI_FALCO_PLUGIN ?= $(USER)test.azurecr.io/falco-plugin-ig
OCI_FALCO_PLUGIN_VERSION ?= 0.1.0

all: $(OUTPUT)

.PHONY: container-build
container-build:
	docker buildx build --platform=$(PLATFORMS) -t $(CONTAINER_REPO):$(IMAGE_TAG) \
		--push \
		-f Dockerfile .

.PHONY: falco-plugin
falco-plugin:
	rm -f $(OUTPUT)
	docker build -t $(CONTAINER_REPO):$(IMAGE_TAG) -f Dockerfile .
	container_id=$(shell docker create "$(CONTAINER_REPO):$(IMAGE_TAG)") ; \
	docker cp "$$container_id:/usr/share/falco/plugins/$(OUTPUT)" "$(OUTPUT)" ; \
	docker rm "$$container_id"
	falcoctl registry push \
		$(OCI_FALCO_PLUGIN):$(OCI_FALCO_PLUGIN_VERSION) \
		--config /dev/null \
		--type plugin \
		--version "$(OCI_FALCO_PLUGIN_VERSION)" \
		--tag latest \
		--platform linux/amd64 \
		--requires plugin_api_version:2.0.0 \
		--name $(NAME) \
		$(OUTPUT)
	falcoctl registry push \
		$(OCI_FALCO_PLUGIN)-ruleset:$(OCI_FALCO_PLUGIN_VERSION) \
		--config /dev/null \
		--type rulesfile \
		--version "$(OCI_FALCO_PLUGIN_VERSION)" \
		--tag latest \
		--name $(NAME)-rules \
		$(NAME)_rules.yaml

clean:
	@rm -f *.so *.h

$(OUTPUT): *.go
	@GODEBUG=cgocheck=2 $(GO) build -buildmode=c-shared -o $(OUTPUT)
