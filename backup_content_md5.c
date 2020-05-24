// compile with -lcrypto

#include <stdio.h>
#include <openssl/md5.h>

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s <filename>\n", argv[0]);
		return 1;
	}

	FILE *file;
	if (!(file = fopen(argv[1], "r"))) {
		fputs("Can't open file!\n", stderr);
		return 2;
	}

	if (fseek(file, 0x90, SEEK_SET)) {
		fputs("Can't seek to 0x90!\n", stderr);
		return 3;
	}

	char buf[0x200];
	for (int i = 0; i < 0x200; i++) {
		buf[i] = i % 0x4d;
	}

	MD5_CTX ctx;
	char result[16];
	MD5_Init(&ctx);
	MD5_Update(&ctx, buf, 0x200);

	while (fread(buf, 1, 0x200, file) != 0) {
		MD5_Update(&ctx, buf, 0x200);
	}

	MD5_Final(result, &ctx);

	for (int i = 0; i < 16; i++) {
		printf("%02hhx ", result[i]);
	}
	puts("");
	return 0;
}
