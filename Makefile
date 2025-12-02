CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -O2
LDFLAGS = 

TARGET  = rserver
SRC     = server.c

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)
