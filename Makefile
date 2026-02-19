CC := clang
CXX := clang++

CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11
CXXFLAGS ?= -O2 -fPIC
CPPFLAGS ?= -Iinclude

BUILD_DIR := build
.DEFAULT_GOAL := all

include pass/build.mk
include loader/build.mk
include samples/build.mk

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

all: pass loader samples

pass: $(PASS_SO)

loader: $(LOADER_TOOL)

.PHONY: all pass loader clean samples

clean:
	rm -rf $(BUILD_DIR)
