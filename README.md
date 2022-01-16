# porto

[![Coverage Status](https://coveralls.io/repos/github/effective-security/porto/badge.svg?branch=main)](https://coveralls.io/github/effective-security/porto?branch=main)

Go packages

## Requirements

1. GoLang 1.17+

## Contribution

* `make all` complete build and test
* `make test` run the tests
* `make testshort` runs the tests skipping the end-to-end tests and the code coverage reporting
* `make covtest` runs the tests with end-to-end and the code coverage reporting
* `make coverage` view the code coverage results from the last make test run.
* `make generate` runs go generate to update any code generated files
* `make fmt` runs go fmt on the project.
* `make lint` runs the go linter on the project.

run `make all` once, then run `make build` or `make test` as needed.

First run:

    make all

Tests:

    make test

Optionally run golang race detector with test targets by setting RACE flag:

    make test RACE=true

Review coverage report:

    make covtest coverage
