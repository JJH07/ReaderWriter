CC ?= cc
CPPFLAGS ?=
CFLAGS ?= -O2 -g
CFLAGS += -std=c11 -Wall -Wextra -Wpedantic -Werror
LDFLAGS ?=
LDLIBS ?=

.PHONY: all clean test sanitize
all: ssu_ofm ssu_vim

ssu_ofm: ssu_ofm.o rw_common.o

ssu_vim: ssu_vim.o rw_common.o

ssu_ofm.o ssu_vim.o rw_common.o: rw_common.h

test: all
	python3 -m unittest discover -s tests -v

sanitize:
	$(MAKE) clean
	$(MAKE) CFLAGS='-O1 -g -std=c11 -Wall -Wextra -Wpedantic -Werror -fsanitize=address,undefined -fno-omit-frame-pointer -fno-pie' LDFLAGS='-fsanitize=address,undefined -no-pie' test

clean:
	$(RM) ssu_ofm ssu_vim *.o
