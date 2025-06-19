LLVM_CONFIG := llvm-config
LLVM_BINDIR := $(shell $(LLVM_CONFIG) --bindir)
LLVM_LIBDIR := $(shell $(LLVM_CONFIG) --libdir)
LLVM_FLAGS  := $(shell $(LLVM_CONFIG) --cxxflags) -ggdb
ifeq ($(words $(shell $(LLVM_CONFIG) --libs)),1)
LLVM_LIBS   := $(shell $(LLVM_CONFIG) --libs)
else
LLVM_LIBS   :=
endif
CXX         := $(LLVM_BINDIR)/clang++

TARGETS     := lemonade.so attribute.so

all: $(TARGETS)

%.so: %.cc
	$(CXX) -fPIC '-Wno-#warnings' -shared $(LLVM_FLAGS) -L$(LLVM_LIBDIR) $(LLVM_LIBS) $^ -o $@

clean:
	$(RM) $(TARGETS)

.PHONY: all clean
