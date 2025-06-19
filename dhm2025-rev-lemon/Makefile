CC := clang
ARCH := -m32
CDEBUG := -Og -g3 # -O3
LDEBUG := # -s
PFLAGS := -fplugin=$(realpath plugin/attribute.so) -fpass-plugin=$(realpath plugin/lemonade.so) \
	  -Xclang -llvm-verify-each # Sanity-check that we don't mangle the IR too badly.
CFLAGS := $(CDEBUG) -std=c23 -Wall -fpic -fomit-frame-pointer -Wall -Wextra -fno-stack-protector -fno-builtin $(PFLAGS)
LFLAGS := $(LDEBUG) -fuse-ld=lld -fpie -Wl,-z,now,-z,relro,--sort-common,-O1,-Tlemon.ld,--shuffle-sections='*lemonade*=1337'

TARGET := lemon
OBJECTS := lemon.o rt.o

$(TARGET): encrypted-flag.bin $(OBJECTS)
	$(CC) $(ARCH) $(LFLAGS) $(wordlist 2,$(words $^),$^) -o $@
	cp $@ raw.01.lemon
	python3 postprocess.py $@
	cp $@ raw.02.lemon
	strip -s --strip-section-headers $@

encrypted-flag.bin: encrypt.py flag.txt solution.txt
	python3 $^ $@

%.o: %.c | $(INC)
	$(CC) $(ARCH) $(CFLAGS) $^ -c -o $@

%.S: %.c
	$(CC) $(ARCH) $(CFLAGS) $^ -S -c -o $@

clean:
	$(RM) $(OBJECTS) $(GENERATED)

distclean: clean
	$(RM) $(TARGET)

test: $(TARGET)
	./$(TARGET) $(shell cat solution.txt)

.PHONY: clean distclean test
