SHELL=/bin/bash -o pipefail
GO ?= go

NAME := syslogsrv
OUTPUT := lib$(NAME).so
DESTDIR := /usr/share/falco/plugins

ifeq ($(DEBUG), 1)
    GODEBUGFLAGS= GODEBUG=cgocheck=2
else
    GODEBUGFLAGS= GODEBUG=cgocheck=0
endif

all: $(OUTPUT)

clean:
	@rm -f $(OUTPUT)

$(OUTPUT):
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -o $(OUTPUT) ./plugin

readme:
	@$(READMETOOL) -p ./$(OUTPUT) -f README.md # does not work

build: clean
	@$(GODEBUGFLAGS) $(GO) build -buildmode=c-shared -o $(OUTPUT) ./plugin

install: build
	mv $(OUTPUT) $(DESTDIR)/
