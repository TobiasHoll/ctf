CFLAGS := -O2 -fno-plt -pie
LFLAGS := -s -Wl,--no-relax,-z,dynamic-undefined-weak
OBJECTS := main.o crt.o lib.o implant.o
STAGES := $(wildcard stage*.s)

all: bin

%.o: %.c shared.h
	$(CC) $(CFLAGS) -c $< -o $@

flag.gen.s: flag.py
	python3 flag.py $@

main.o: main.c $(STAGES) flag.gen.s

implant.gen.h: main.o gen.py
	python3 gen.py $< $@

implant.o: implant.c implant.s implant.gen.h | main.o

crt.o: crt.S
	$(CC) $(CFLAGS) -c $^ -o $@

bin: $(OBJECTS)
	$(CC) $(CFLAGS) $(LFLAGS) $^ -o $@
	python3 patch.py $@ main.o || { $(RM) $@; exit 1; }

clean:
	$(RM) bin $(OBJECTS) implant.gen.h

.PHONY: all clean
