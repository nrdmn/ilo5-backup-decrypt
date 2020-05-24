// compile with -lcrypto -lssl
// THIS PROGRAM DOES NOT SEEM TO WORK CORRECTLY

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

static void callback(int a, int b, void *c)
{
	putchar('.');
}

static bool myrand_seeded = false;
static uint32_t myrand_state[2] = {0, 0};

static void myrand_seed(const void *buf, int num)
{
	int x = *(uint32_t *)buf;
	myrand_seeded = true;
	myrand_state[0] = x & 0xffff;
	myrand_state[1] = (x << 1) >> 0x11;
}

static unsigned char myrand_get_byte_(uint32_t state[2])
{
	// this function is probably wrong
	uint32_t foo;
	uint32_t bar;

	foo = state[0] * 0x3aa8 + 0xf4627;
	bar = state[1] * 0x3aa8 + (foo >> 0x10);
	foo &= 0xffff;
	while (bar > 0x78f0) {
		if (foo < 0x10000) {
			foo += 0x10000;
			bar--;
		}
		foo -= 0xe079;
		bar -= 0x78f0;
	}
	state[0] = foo;
	state[1] = bar;
	return foo >> 4;
}

static unsigned char myrand_get_byte()
{
	if (!myrand_seeded) {
		myrand_seeded = true;
		myrand_state[0] = 1;
	}
	return myrand_get_byte_(myrand_state);
}

static int myrand_nopseudo_bytes(unsigned char *buf, int num)
{
	for (int i = 0; i < num; i++) {
		buf[i] = myrand_get_byte();
	}
	return 1;
}

static RAND_METHOD myrand = {
	myrand_seed,
	myrand_nopseudo_bytes,
	NULL,
	NULL,
	NULL,
	NULL,
};

struct header {
	char magic1[8];
	uint64_t size;
	unsigned char content_md5[16];
	char magic2[16];
	char version[32];
	char type[32];
	unsigned char password_md5[16];
	char zeros[16];
};

static const char magic1[8] = {0x49, 0x4c, 0xfa, 0x42, 0x01, 0x01, 0x00, 0x00};

int main(int argc, char **argv)
{
	SSL_library_init();
	RAND_cleanup();
	RAND_set_rand_method(&myrand);

	if (argc != 4) {
		fprintf(stderr, "usage: %s <chip id> <input file> <output file>\n", argv[0]);
		fprintf(stderr, "chip id must be 16 lower case hex digits\n");
		return 1;
	}

	FILE *in_file = fopen(argv[2], "r");
	FILE *out_file = fopen(argv[3], "w+");

	// high security crypto happens here
	char key_length[4] = {0, 0, 1, 0};
	char key[0x100];
	char iv[0x10];
	memset(iv, 0, 0x10);
	char salt[0x40];
	memset(salt, 0, 0x40);
	// seed rng
	char pbkdf2_result[0x80];
	PKCS5_PBKDF2_HMAC(argv[1], 16, salt, 0x40, 0x2f59, EVP_sha384(), 0x80, pbkdf2_result);
	RAND_seed(pbkdf2_result, 4);

	// generate key
	RSA *rsakey = RSA_generate_key(0x800, 0x10001, callback, NULL);
	EVP_PKEY *pkey = EVP_PKEY_new();
	EVP_PKEY_set1_RSA(pkey, rsakey);
	EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
	unsigned char *key_ptr = key;
	int ekl;
	EVP_SealInit(cipher_ctx, EVP_aes_256_cbc(), &key_ptr, &ekl, iv, &pkey, 1);

	// write key info
	fseek(out_file, sizeof(struct header), SEEK_SET);
	// just write the same key 5 times
	for (int i = 0; i < 5; i++) {
		fwrite(salt, 0x40, 1, out_file);
		fwrite(key_length, 4, 1, out_file);
		fwrite(key, 0x100, 1, out_file);
		fwrite(iv, 0x10, 1, out_file);
	}

	char buf[0x2000];
	char out[0x2000];
	size_t read_len;
	int out_len;
	while (read_len = fread(buf, 1, 0x1000, in_file)) {
		EVP_SealUpdate(cipher_ctx, out, &out_len, buf, read_len);
		fwrite(out, out_len, 1, out_file);
	}
	EVP_SealFinal(cipher_ctx, out, &out_len);
	fwrite(out, out_len, 1, out_file);

	struct header header;
	memset(&header, 0, sizeof(struct header));
	memcpy(&header.magic1, &magic1, 8);
	header.size = ftell(out_file);
	header.magic2[0] = 1;
	memcpy(&header.version, "1.40", 4);
	memcpy(&header.type, "iLO 5 Backup file", 17);

	char md5buf[0x200];
	for (int i = 0; i < 0x200; i++) {
		md5buf[i] = i % 0x4d;
	}
	MD5_CTX md5_ctx;
	MD5_Init(&md5_ctx);
	MD5_Update(&md5_ctx, md5buf, 0x200);
	fseek(out_file, 0x90, SEEK_SET);
	while (fread(md5buf, 1, 0x200, out_file) != 0) {
		MD5_Update(&md5_ctx, md5buf, 0x200);
	}

	/* write content hash */
	MD5_Final(&header.content_md5, &md5_ctx);

	/* write empty password hash */
	MD5_Init(&md5_ctx);
	MD5_Final(&header.password_md5, &md5_ctx);

	rewind(out_file);
	fwrite(&header, sizeof(struct header), 1, out_file);

	return 0;
}
