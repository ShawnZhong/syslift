LLVM_VERSION ?= 18

CC := clang-$(LLVM_VERSION)
CXX := clang++-$(LLVM_VERSION)
LLVM_CONFIG := llvm-config-$(LLVM_VERSION)

CFLAGS ?= -O2 -Wall -Wextra -Werror -std=c11
CXXFLAGS ?= -O2 -fPIC
CPPFLAGS ?= -Iinclude

BUILD_DIR := build
.DEFAULT_GOAL := all

include pass/build.mk
include loader/build.mk
include samples/build.mk
include loader_verus/build.mk

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

.PHONY: all
all: pass loader samples

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
