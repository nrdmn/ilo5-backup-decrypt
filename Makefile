CFLAGS=-Wall -Wextra -O2
LFLAGS=-lcrypto -lssl

BINARIES=license backup_decrypt backup_encrypt backup_content_md5

all: $(BINARIES)

%: %.c
	$(CC) $(CFLAGS) $< $(LFLAGS) -o $@

clean:
	rm -f *.o $(BINARIES)
