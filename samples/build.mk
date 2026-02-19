SAMPLE_SRCS := $(wildcard samples/*.c)
SAMPLE_NAMES := $(patsubst samples/%.c,%,$(SAMPLE_SRCS))
SAMPLE_ELFS := $(addprefix $(BUILD_DIR)/,$(addsuffix .elf,$(SAMPLE_NAMES)))

$(BUILD_DIR)/%.elf: samples/%.c cc.sh $(PASS_SO) | $(BUILD_DIR)
	./cc.sh $< $(BUILD_DIR)/$*

samples: $(SAMPLE_ELFS)
