CC ?= gcc-11
CFLAGS ?= -Wall -pedantic

all: tcgtool

.PHONY: clean
clean:
	rm tcgtool
