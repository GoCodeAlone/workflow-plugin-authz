#!/bin/sh
# Run this script after the system recovers from the fork resource issue.
# It fetches new dependencies, builds, and runs tests.

set -e
cd "$(dirname "$0")"

export GOPRIVATE=github.com/GoCodeAlone/*

echo "==> go mod tidy"
go mod tidy

echo "==> go build"
go build ./...

echo "==> go vet"
go vet ./...

echo "==> go test (race detector)"
go test ./... -v -race -count=1
