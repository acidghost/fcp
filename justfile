program := 'fcp'

version := 'SNAPSHOT-'+`git describe --tags --always --dirty 2>/dev/null || printf 'unknown'`
commit_sha := `(git rev-parse --verify HEAD 2>/dev/null || printf 'unknown') | tr -d '\n'`
build_time := `date -u '+%Y-%m-%d_%H:%M:%S'`

ldflags := '-s -w -X main.buildVersion='+version \
        +' -X main.buildCommit='+commit_sha \
        +' -X main.buildDate='+build_time

goos := if os() == 'macos' { 'darwin' } else { os() }
goarch := if arch() == 'aarch64' { 'arm64' } else if arch() == 'x86_64' { 'amd64' } else { arch() }

alias b := build
alias r := run

build-all: (build 'darwin' 'arm64') (build 'linux' 'arm64') (build 'linux' 'amd64')

build os=goos arch=goarch: build-dir
    CGO_ENABLED=0 GOOS={{os}} GOARCH={{arch}} \
        go build \
            -ldflags '{{ldflags}}' \
            -o build/{{program}}-{{os}}-{{arch}}

build-dir:
    mkdir -p build

run *args: build
    ./build/{{program}}-{{goos}}-{{goarch}} {{args}}

vendor:
    go mod tidy
    go mod vendor

fmt:
    go fmt ./...

test:
    go test ./...

vet:
    go vet ./...

check: fmt vet test lint

lint:
    golangci-lint run

install: build
    cp -v './build/{{program}}-{{goos}}-{{goarch}}' "$(go env GOBIN)/{{program}}"

clean:
    rm -rf build

help:
    @just --list
