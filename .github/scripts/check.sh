#!/usr/bin/env bash
set -euo pipefail
files=$(gofmt -l .)
if [[ -n "$files" ]]; then
  printf 'Go formatting required:\n%s\n' "$files" >&2
  exit 1
fi
go mod verify
go vet ./...
go test -race ./... -count=1
