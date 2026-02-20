ROOT := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))
SRC := $(ROOT)/src/main.rs
VERUS := $(ROOT)/.toolchain/verus/verus

.PHONY: verify build
all: verify build

verify:
	. "$$HOME/.cargo/env" && $(VERUS) $(SRC)

build:
	. "$$HOME/.cargo/env" && cd $(ROOT) && $(VERUS) src/main.rs --no-verify --compile
