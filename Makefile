LOCAL := $(PWD)/.local
export PATH := $(LOCAL)/bin:$(PATH)
export GOBIN := $(LOCAL)/bin

ifeq ($(OS),Windows_NT)
	BINSUFFIX:=.exe
else
	BINSUFFIX:=
endif

LINTER := $(GOBIN)/golangci-lint$(BINSUFFIX)

$(LINTER):
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.52.2

lint: $(LINTER)
	$(LINTER) run
.PHONY: lint

test:
	go test -v ./...

.PHONY: test