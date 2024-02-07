.PHONY: build clean

VERSION := $(shell git describe --tags --abbrev=0)
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%S%Z')
CLI_BIN := totp

build:
	go build -ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)" -o $(CLI_BIN)

clean:
	rm -f $(CLI_BIN)
