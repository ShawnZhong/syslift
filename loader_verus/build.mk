LOADER_VERUS_OUT := $(BUILD_DIR)/loader_verus
LOADER_VERUS_RS := $(sort $(wildcard loader_verus/*.rs))
VERUS_BIN := .verus/verus-x86-linux/verus

$(LOADER_VERUS_OUT): $(LOADER_VERUS_RS) | $(BUILD_DIR)
	$(VERUS_BIN) loader_verus/main.rs --compile -o $@

.PHONY: verus
verus: $(LOADER_VERUS_OUT)
