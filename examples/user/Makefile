CC = gcc
CFLAGS = -shared -lcrypt

SRC = user.c
TARGET = user.so
DEST = /tmp/user.so

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) -o $(TARGET) $(SRC) $(CFLAGS)

install: $(TARGET)
	cp $(TARGET) $(DEST)

clean:
	rm -f $(TARGET)

.PHONY: all install clean
