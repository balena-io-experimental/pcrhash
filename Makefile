CC ?= gcc-11
CFLAGS ?= -Wall -pedantic

all: tcgtool

tcgtool: uefi.o sha256.o pecoff.o

.PHONY: clean
clean:
	rm -f tcgtool *.o
