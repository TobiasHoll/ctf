CXX      := clang++
FFLAGS   := -fpie -fno-plt -fomit-frame-pointer \
	    -fno-exceptions -fno-rtti \
	    -fno-asynchronous-unwind-tables -fno-unwind-tables \
	    -finstrument-function-entry-bare
DFLAGS := -D_HXP_DEBUG -D_HXP_DEBUG_IDS # -D_HXP_AES_SELFTEST
DEPFLAGS := -MMD -MP
CXXFLAGS := -std=c++23 -O3 -Wall -Wextra -maes -mavx2
LDFLAGS  := -s -fuse-ld=lld -Wl,-O1,-z,relro,-z,now,--build-id=none \
	    -nodefaultlibs -lc

TARGET := chekhov
OBJECTS := main.o

DEPS := $(OBJECTS:.o=.d)

all: $(TARGET) $(TARGET).debug

$(TARGET): $(OBJECTS)
	$(CXX) $(FFLAGS) $(LDFLAGS) -o $@ $^

$(TARGET).debug: $(OBJECTS:.o=.do) | $(TARGET)
	$(CXX) $(FFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.cc
	$(CXX) $(FFLAGS) -c $(CXXFLAGS) $(DEPFLAGS) -o $@ $<

%.do: %.cc
	$(CXX) $(FFLAGS) -c $(CXXFLAGS) $(DFLAGS) -o $@ $<

clean:
	$(RM) $(OBJECTS)
	$(RM) $(OBJECTS:.o=.do)
	$(RM) $(DEPS)
	$(RM) $(TARGET) $(TARGET).debug

.DEFAULT_GOAL := all
.PHONY: all clean

-include $(DEPS)
