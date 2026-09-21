include .project/gomod-project.mk
BUILD_FLAGS=
# -test.v -race
TEST_FLAGS=

.PHONY: *

.SILENT:

default: help

all: clean tools generate covtest

#
# clean produced files
#
clean:
	go clean ./...
	rm -rf \
		${COVPATH} \
		${PROJ_BIN}

tools:
	go install github.com/effective-security/cov-report/cmd/cov-report@latest
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	go install golang.org/x/vuln/cmd/govulncheck@latest
	go install github.com/princjef/gomarkdoc/cmd/gomarkdoc@latest

build:
	echo "nothing to build yet"

#
# regenerate the API reference under Documentation/api (one file per package)
#
docs:
	rm -rf Documentation/api
	mkdir -p Documentation/api
	for pkg in $$(go list ./... | grep -v '/tests/'); do \
		out=Documentation/api/$$(echo $$pkg | sed 's#${REPO_NAME}/##; s#/#_#g').md; \
		gomarkdoc --output $$out --repository.default-branch main $$pkg || exit 1; \
	done
	echo "API reference written to Documentation/api"
