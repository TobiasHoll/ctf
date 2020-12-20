CXX      := g++
WFLAGS   := -Wall -Wextra -Wno-pmf-conversions
CXXFLAGS := -pie -fpie -fomit-frame-pointer -fno-stack-protector -std=gnu++17
OPTFLAGS := -O3 -flto -s
SPECIAL  := -mno-red-zone -ffixed-r14 -ffixed-r15

SETTINGS := -DHAVE_ASSERTS -D'required_stack_size=64*1024*1024'

restless: restless.cc stdlib.tcc main.tcc
	$(CXX) $(WFLAGS) $(CXXFLAGS) $(OPTFLAGS) $(SETTINGS) $(SPECIAL) $< -o $@
