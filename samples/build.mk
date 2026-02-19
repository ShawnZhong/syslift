SAMPLE_SRCS := $(wildcard samples/*.c)
SAMPLE_NAMES := $(patsubst samples/%.c,%,$(SAMPLE_SRCS))
SAMPLE_BINS := $(addprefix $(BUILD_DIR)/,$(SAMPLE_NAMES))

$(BUILD_DIR)/%: samples/%.c cc.sh $(PASS_SO) | $(BUILD_DIR)
	./cc.sh $< $(BUILD_DIR)/$*

samples: $(SAMPLE_BINS)
