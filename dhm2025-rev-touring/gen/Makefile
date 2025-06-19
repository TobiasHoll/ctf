CXX      := clang++
DEPFLAGS := -MMD -MP
CXXFLAGS := -std=c++23 -O3 -g -Wall -Wextra
LDFLAGS  := -fuse-ld=lld -Wl,-O1,-z,relro,-z,now,--build-id=none \

TARGET := assembler
OBJECTS := assembler.o

DEPS := $(OBJECTS:.o=.d)

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(FFLAGS) $(LDFLAGS) -o $@ $^

%.o: %.cc
	$(CXX) $(FFLAGS) -c $(CXXFLAGS) $(DEPFLAGS) -o $@ $<

clean:
	$(RM) $(OBJECTS)
	$(RM) $(DEPS)
	$(RM) $(TARGET)

.DEFAULT_GOAL := all
.PHONY: all clean

-include $(DEPS)
