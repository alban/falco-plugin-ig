#
# Copyright (C) 2021 The Falco Authors.
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

all: $(OUTPUT)

.PHONY: container-build
container-build:
	docker buildx build --platform=$(PLATFORMS) -t $(CONTAINER_REPO):$(IMAGE_TAG) \
		--push \
		-f Dockerfile .


clean:
	@rm -f *.so *.h

$(OUTPUT): *.go
	@GODEBUG=cgocheck=2 $(GO) build -buildmode=c-shared -o $(OUTPUT)
