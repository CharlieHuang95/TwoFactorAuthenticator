#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"
#include "lib/sha1.h"

//#define SHA1_DIGEST_LENGTH 100
/*
char* hash_sha1(char* secret_hex) {
	SHA1_INFO	ctx;
	uint8_t		sha[SHA1_DIGEST_LENGTH];

	sha1_init(&cts);
	sha1_update(&ctx, secret_hex, strlen(secret_hex));
	sha1_final(&ctx, sha);

	return sha;
}
*/

#define BLOCK_SIZE 64 // 512 / 8 bits = 64 bytes (SHA1)

char* get_hmac(uint8_t* secret_hex, uint8_t message) {
	uint8_t ipad[BLOCK_SIZE];
	uint8_t opad[BLOCK_SIZE];
	int i;
	for (i = 0; i < 10; i++) {
		ipad[i] = secret_hex[i] & 0x36;
		opad[i] = secret_hex[i] & 0x5c;
	}
	// SHA1(secret_hex, ipad) -> inner_hash
	// SHA1(message, opad) -> outer_hash
	// return outer_hash
	SHA1_INFO ctx_in;
	SHA1_INFO ctx_out;
	sha1_init(&ctx_in);
	sha1_update(&ctx_in, secret_hex, BLOCK_SIZE);
		
}

static int
validateHOTP(char * secret_hex, char * HOTP_string)
{
	SHA1_INFO       ctx;
	char         sha[SHA1_DIGEST_LENGTH];
	printf("%s", secret_hex);
	sha1_init(&ctx);
        sha1_update(&ctx, secret_hex, strlen(secret_hex));
        sha1_final(&ctx, sha);
	printf("%s", sha);
	printf("%s", HOTP_string);
	return strcmp(sha, HOTP_string) == 0 ? 1 : 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	return (0);
}

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char *	secret_hex_in_ascii = argv[1];
	char *	HOTP_value = argv[2];
	char *	TOTP_value = argv[3];

        assert (strlen(secret_hex_in_ascii) <= 20);
        assert (strlen(HOTP_value) == 6);
        assert (strlen(TOTP_value) == 6);

	// Interpret the value as a hexadecimal. It would have been read in
	// as an ascii, thus having twice the length that is should have.
	// Let's compact it to half of its size
	uint8_t secret[10];
	uint8_t secret_hex[10];
	int i, len;

    	len = strlen(secret_hex_in_ascii);
    	if (secret_hex[len-1] == '\n')
        	secret_hex[--len] = '\0';

	for (i = 0; i < (len / 2); i++) {
		sscanf(secret_hex_in_ascii + 2*i, "%02X", &secret_hex[i]);
    	}

	printf("\nSecret (Hex): %s\nHTOP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
