SAMPLE_SRCS := $(wildcard samples/*.c)
SAMPLE_NAMES := $(patsubst samples/%.c,%,$(SAMPLE_SRCS))
SAMPLE_BINS := $(addprefix $(BUILD_DIR)/,$(SAMPLE_NAMES))

SAMPLE_CLANG_FLAGS := -O2 -Ithird_party/nolibc -fpass-plugin=$(PASS_SO) -nostdlib -static

$(BUILD_DIR)/%: samples/%.c $(PASS_SO) | $(BUILD_DIR)
	$(CC) $(SAMPLE_CLANG_FLAGS) $< -o $@

.PHONY: samples
samples: $(SAMPLE_BINS)
