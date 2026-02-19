LOADER_TOOL := $(BUILD_DIR)/loader
LOADER_SRCS := $(sort $(wildcard loader/*.cpp))
LOADER_HDRS := $(sort $(wildcard loader/*.h))
LOADER_VENDOR_HDRS := third_party/cxxopts/cxxopts.hpp $(sort $(wildcard third_party/elfio/*.hpp))
LOADER_CXXFLAGS ?= -O2 -Wall -Wextra -Werror -std=c++17
LOADER_CPPFLAGS := $(CPPFLAGS) -Ithird_party -Ithird_party/cxxopts

$(LOADER_TOOL): $(LOADER_SRCS) $(LOADER_HDRS) $(LOADER_VENDOR_HDRS) | $(BUILD_DIR)
	$(CXX) $(LOADER_CXXFLAGS) $(LOADER_CPPFLAGS) $(LOADER_SRCS) -o $@
