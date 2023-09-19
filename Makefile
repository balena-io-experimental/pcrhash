CC ?= gcc-11
CFLAGS ?= -Wall -pedantic

all: pcrhash

.PHONY: clean
clean:
	rm pcrhash
