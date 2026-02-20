PASS_SO := $(BUILD_DIR)/libSysliftCollectSyscallsPass.so
PASS_SRC := pass/SysliftCollectSyscalls.cpp

PASS_LLVM_CXXFLAGS := $(shell $(LLVM_CONFIG) --cxxflags)
PASS_LLVM_LDFLAGS := $(shell $(LLVM_CONFIG) --ldflags --system-libs --libs core passes codegen support)

$(PASS_SO): $(PASS_SRC) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) $(CPPFLAGS) $(PASS_LLVM_CXXFLAGS) -shared $< -o $@ $(PASS_LLVM_LDFLAGS)
