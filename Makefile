CC ?= gcc-11
CFLAGS ?= -Wall -pedantic

all: tcgtool

tcgtool: uefi.o

.PHONY: clean
clean:
	rm tcgtool
