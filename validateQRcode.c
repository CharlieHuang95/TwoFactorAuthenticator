#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

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

#define DEBUG 0 


#define BLOCK_SIZE 64 // 512 / 8 bits = 64 bytes (SHA1)

void get_hmac(uint8_t* secret_hex, uint8_t* message, uint8_t* sha_out) {
    if (DEBUG) { printf("\nget_hmac %s, %s, %s\n", secret_hex, message, sha_out); fflush(stdout); }
    uint8_t secret_key_padded[BLOCK_SIZE];
	uint8_t ipad[BLOCK_SIZE];
	uint8_t opad[BLOCK_SIZE];
    uint8_t sha_1[SHA1_DIGEST_LENGTH];
	int i;
	for (i = 0; i < 10; i++) {
        secret_key_padded[i] = secret_hex[i];
    }
    for (; i < BLOCK_SIZE; i++) {
        secret_key_padded[i] = 0x00;
    }
    for (i = 0; i < BLOCK_SIZE; i++) {
        ipad[i] = secret_key_padded[i] ^ 0x36;
        opad[i] = secret_key_padded[i] ^ 0x5c;
    }

	// SHA1(secret_hex, ipad) -> inner_hash
	// SHA1(message, opad) -> outer_hash
	// return outer_hash
    SHA1_INFO ctx_in;
    SHA1_INFO ctx_out;
    sha1_init(&ctx_in);

    // If we take the hash with two updates, it is the same as taking a single
    // hash with the two inputs concatenated
    sha1_update(&ctx_in, ipad, BLOCK_SIZE);
    sha1_update(&ctx_in, message, 8);

    sha1_final(&ctx_in, sha_1);

    sha1_init(&ctx_out);
    sha1_update(&ctx_out, opad, BLOCK_SIZE);
    sha1_update(&ctx_out, sha_1, SHA1_DIGEST_LENGTH);
    sha1_final(&ctx_out, sha_out);
}

int dynamic_truncation(uint8_t* hash) {
    // Get the lower order 4 bits of String[19]
    int offset = hash[19] & 0xf;
    if (DEBUG) { printf("offset is %d\n", offset); }

    // Obtain P, return the last 31 bits of it
    int bin_code = (hash[offset] & 0x7f) << 24 |
                   (hash[offset+1] & 0xff) << 16 |
                   (hash[offset+2] & 0xff) << 8 |
                   (hash[offset+3] & 0xff);
    return bin_code;
}

static int validateHOTP(char * secret_hex, char * HOTP_string) {
    if (DEBUG) { printf("%s %s", secret_hex, HOTP_string); fflush(stdout); }
	SHA1_INFO       ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];
    
    if (DEBUG) { printf("about to call get_hmax"); fflush(stdout); }
    uint8_t counter[8] = { 0, 0, 0, 0, 0, 0, 0, 1 };
    get_hmac(secret_hex, counter, sha);
    int bin_code = dynamic_truncation(sha) % 1000000;
    if (DEBUG) printf("Binary code is %d\n", bin_code);
    int HOTP_int = atoi(HOTP_string);
    if (DEBUG) printf("HOTP %d\n", bin_code);
	return bin_code == HOTP_int ? 1 : 0;
}

static int
validateTOTP(char * secret_hex, char * TOTP_string)
{
	SHA1_INFO       ctx;
	uint8_t sha[SHA1_DIGEST_LENGTH];
    if (DEBUG) { printf("about to call get_hmax"); fflush(stdout); }
	int period = 30;
	int T = time(NULL) / period;
	// convert time to binary vector
	uint8_t message[8] = {0};
	message[7] = 0x0FF & T;
	message[6] = 0x0FF & (T>>8);
	message[5] = 0x0FF & (T>>16);
	message[4] = 0x0FF & (T>>24);
	if (DEBUG) { printf("\n%d\n", T); }
	if (DEBUG) { int i; for (i=0;i<8;i++){ printf("%d\n", message[i]); }}
    get_hmac(secret_hex, message, sha);
	int bin_code = dynamic_truncation(sha) % 1000000;
	int TOTP_int = atoi(TOTP_string);
	if (DEBUG) printf("TOTP %d\n", bin_code);
	return bin_code == TOTP_int ? 1 : 0;
}

int main(int argc, char * argv[]) {
	if ( argc != 4 ) {
		printf("Usage: %s [secretHex] [HOTP] [TOTP]\n", argv[0]);
		return(-1);
	}

	char* secret_hex_in_ascii = argv[1];
	char* HOTP_value = argv[2];
	char* TOTP_value = argv[3];

    assert(strlen(secret_hex_in_ascii) == 20);
    assert(strlen(HOTP_value) == 6);
    assert(strlen(TOTP_value) == 6);

	// Interpret the value as a hexadecimal. It would have been read in
	// as an ascii, thus having twice the length that is should have.
	// Let's compact it to half of its size
	uint8_t secret[10];
	uint8_t secret_hex[10];
	int i, len;

    len = strlen(secret_hex_in_ascii);
	for (i = 0; i < (len / 2); i++) {
		sscanf(secret_hex_in_ascii + 2*i, "%02x", &secret_hex[i]);
    }

	printf("\nSecret (Hex): %s\nHOTP Value: %s (%s)\nTOTP Value: %s (%s)\n\n",
		secret_hex_in_ascii,
		HOTP_value,
		validateHOTP(secret_hex, HOTP_value) ? "valid" : "invalid",
		TOTP_value,
		validateTOTP(secret_hex, TOTP_value) ? "valid" : "invalid");

	return(0);
}
