CC=gcc
CFLAGS=-O3 -march=native -mtune=native -flto -funroll-loops
LDFLAGS=-lpthread
TARGET=secret_scanner

all: $(TARGET)

$(TARGET): scanner.c
	$(CC) $(CFLAGS) -o $(TARGET) scanner.c $(LDFLAGS)
	strip $(TARGET)  # Remove símbolos, binário menor

clean:
	rm -f $(TARGET)

install:
	cp $(TARGET) ../../