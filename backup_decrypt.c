// compile with -lcrypto -lssl

#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>

static void callback(int a, int b, void *c)
{
	putchar('.');
}

static bool myrand_seeded = false;
static uint32_t myrand_state;

static void myrand_seed(const void *buf, int num)
{
	myrand_seeded = true;
	myrand_state = *(uint32_t *)buf & 0x7fffffff;
}

static unsigned char myrand_get_byte()
{
	if (!myrand_seeded) {
		myrand_seeded = true;
		myrand_state = 1;
	}
	myrand_state = ((uint64_t)myrand_state * 0x3aa8 + 0xf4627) % 0x78f0e079;
	return myrand_state >> 4;
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
	assert(in_file);
	fseek(in_file, 0x90, SEEK_SET);
	FILE *out_file = fopen(argv[3], "w");
	assert(out_file);


	puts("reading salt from file");
	char salt[0x40];
	fread(salt, 0x40, 1, in_file);


	puts("read ek length from file");
	int ek_len;
	fread(&ek_len, 4, 1, in_file);
	// flip endianness
	ek_len = ek_len << 0x18 | (ek_len >> 8 & 0xff) << 0x10 | (ek_len >> 0x10 & 0xff) << 8 | ek_len >> 0x18;
	assert(ek_len == 256);


	puts("read ek from file");
	char ek[256];
	fread(ek, ek_len, 1, in_file);


	puts("read iv from file");
	int iv_len = EVP_CIPHER_iv_length(EVP_aes_256_cbc());
	assert(iv_len == 16);

	char iv[16];
	fread(iv, iv_len, 1, in_file);


	puts("seed rng");
	char pbkdf2_result[0x80];
	assert(strlen(argv[1]) == 16);
	PKCS5_PBKDF2_HMAC(argv[1], 16, salt, 0x40, 0x2f59, EVP_sha384(), 0x80, pbkdf2_result);
	//RAND_seed(pbkdf2_result, 0x80);
	RAND_seed(pbkdf2_result, 4); // lol entropy


	puts("generate rsa key");
	RSA *key = RSA_generate_key(0x800, 0x10001, callback, NULL);
	assert(key);
	puts("done");


	EVP_PKEY *pkey = EVP_PKEY_new();
	assert(pkey);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	assert(ctx);
	assert(EVP_PKEY_set1_RSA(pkey, key));
	assert(EVP_PKEY_size(pkey) == ek_len);
	EVP_OpenInit(ctx, EVP_aes_256_cbc(), ek, ek_len, iv, pkey);

	fseek(in_file, 0x90 + 0x154*5, SEEK_SET);
	char buf[0x2000];
	char out[0x2000];
	int out_len;
	size_t read_len;
	while (read_len = fread(buf, 1, 0x1000, in_file)) {
		assert(EVP_OpenUpdate(ctx, out, &out_len, buf, read_len));
		fwrite(out, out_len, 1, out_file);
	}
	EVP_OpenFinal(ctx, out, &out_len);
	fwrite(out, out_len, 1, out_file);

	return 0;
}
