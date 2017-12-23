#
# This file has been adapted from the original located at
# https://raw.githubusercontent.com/eawsy/aws-lambda-go-shim/master/src/Makefile.example
#
# See also: https://github.com/eawsy/aws-lambda-go-shim#quick-hands-on
#

HANDLER ?= handler
PACKAGE ?= vault-test

AWS_ACCOUNT_ID ?= $(shell aws sts get-caller-identity | jq -r '.Account')
AWS_REGION ?= $(shell aws configure get region)

STACK_NAME ?= Go-Vault-Resource-Test
STACK_BUCKET ?= $(PACKAGE)-$(AWS_ACCOUNT_ID)-$(AWS_REGION)

ifeq ($(OS),Windows_NT)
	GOPATH ?= $(USERPROFILE)/go
	GOPATH := /$(subst ;,:/,$(subst \,/,$(subst :,,$(GOPATH))))
	CURDIR := /$(subst :,,$(CURDIR))
	RM := del /q
else
	GOPATH ?= $(HOME)/go
	RM := rm -f
endif

MAKEFILE = $(word $(words $(MAKEFILE_LIST)),$(MAKEFILE_LIST))

docker:
	docker run --rm \
		-e HANDLER=$(HANDLER) \
		-e PACKAGE=$(PACKAGE) \
		-e GOPATH=$(GOPATH) \
		-e LDFLAGS='$(LDFLAGS)'  \
		-e AWS_ACCOUNT_ID=$(AWS_ACCOUNT_ID) \
		-e AWS_REGION=$(AWS_REGION) \
		-v $(CURDIR):$(CURDIR): \
		$(foreach GP,$(subst :, ,$(GOPATH)),-v $(GP):$(GP)):Z \
		-w $(CURDIR) \
		eawsy/aws-lambda-go-shim:latest make -f $(MAKEFILE) all

.PHONY: docker

all: build pack perm

.PHONY: all

build:
	go build -buildmode=plugin -ldflags='-w -s $(LDFLAGS)' -o $(HANDLER).so

.PHONY: build

pack:
	pack $(HANDLER) $(HANDLER).so $(PACKAGE).zip

.PHONY: pack

perm:
	chown $(shell stat -c '%u:%g' .) $(HANDLER).so $(PACKAGE).zip

.PHONY: perm

clean:
	$(RM) $(HANDLER).so $(PACKAGE).zip

.PHONY: clean

stack-deploy: $(PACKAGE).template
	aws ec2 describe-key-pairs --key-names $(PACKAGE) > /dev/null 2>&1 || aws ec2 import-key-pair --key-name $(PACKAGE) --public-key-material file://$(HOME)/.ssh/id_rsa.pub
	aws cloudformation deploy --capabilities CAPABILITY_IAM --template-file $(PACKAGE).template --stack-name $(STACK_NAME) \
		--parameter-overrides VaultKeyPair=$(PACKAGE) AvailabilityZones=$(AWS_REGION)a,$(AWS_REGION)b,$(AWS_REGION)c


stack-delete:
	aws cloudformation delete-stack --stack-name $(STACK_NAME)
	aws cloudformation wait stack-delete-complete --stack-name $(STACK_NAME)

.PHONY: stack-deploy stack-delete

$(PACKAGE).template: $(PACKAGE).cfn.yaml $(PACKAGE).zip Makefile
	aws s3 ls s3://$(STACK_BUCKET) > /dev/null 2>&1 || aws s3 mb s3://$(STACK_BUCKET)
	aws cloudformation package \
		--template-file $(PACKAGE).cfn.yaml --output-template-file $(PACKAGE).template \
		--s3-bucket $(STACK_BUCKET) --s3-prefix lambda/$(PACKAGE)
	aws s3 cp $(PACKAGE).template s3://$(STACK_BUCKET)/$(PACKAGE).template

$(PACKAGE).zip: Makefile *.go
	@make docker
