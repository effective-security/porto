include .project/gomod-project.mk
export GO111MODULE=on
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
	go install github.com/go-phorce/cov-report/cmd/cov-report@v1.1.0
	go install github.com/mattn/goveralls@v0.0.12
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.53.3

build:
	echo "nothing to build yet"

coveralls-github:
	echo "Running coveralls"
	goveralls -v -coverprofile=coverage.out -service=github -package ./...
