CC=gcc
CFLAGS=-c
CLIBS=-lpthread

ODIR=build

SRC := $(wildcard *.c)
OBJ = $(addprefix $(ODIR)/, $(SRC:.c=.o))

all: $(OBJ)
	$(CC) $(CLIBS) $(OBJ) -o $(ODIR)/main

$(ODIR)/%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

.PHONY: clean

clean:
	rm -rf build