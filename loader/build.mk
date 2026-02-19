LOADER_TOOL := $(BUILD_DIR)/loader
LOADER_SRC := loader/loader.cpp
LOADER_CXXFLAGS ?= -O2 -Wall -Wextra -Werror -std=c++17

$(LOADER_TOOL): $(LOADER_SRC) | $(BUILD_DIR)
	$(CXX) $(LOADER_CXXFLAGS) $(CPPFLAGS) $< -o $@
