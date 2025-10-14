CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread
LDFLAGS = -lssl -lcrypto

TARGET = http_downloader
SRC = http_downloader.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o part_* 