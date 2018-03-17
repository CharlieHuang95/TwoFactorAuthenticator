#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

#define BUFFER_SIZE 100
#define MAX_KEY_SIZE 20

#define DEBUG 0

int main(int argc, char * argv[]) {
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char* issuer = argv[1];
	char* accountName = argv[2];
	char* secret_hex = argv[3];

	assert(strlen(secret_hex) == MAX_KEY_SIZE);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	char buf_hotp[BUFFER_SIZE];
	char buf_totp[BUFFER_SIZE];
	
	uint8_t secret[BUFFER_SIZE/2];
	uint8_t secret_hex_buf[BUFFER_SIZE];
	int i = 0;
	
	// Prepare secret_hex into format accepted by base32_encode
	for (i = 0; i < strlen(secret_hex)/2; i++) {
	    sscanf(secret_hex + 2*i, "%02x", &secret[i]);
	}
    if (DEBUG) { printf("%s", secret); fflush(stdout); }

	// Write encoded secret into secret_hex_buf
	base32_encode(secret,
		      strlen(secret),
              secret_hex_buf,
		      BUFFER_SIZE);
		      
    // display HOTP and TOTP QR codes
	snprintf(buf_hotp, BUFFER_SIZE, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",
		 urlEncode(accountName), urlEncode(issuer),
		 secret_hex_buf); 
	displayQRcode(buf_hotp);
	
	snprintf(buf_totp, BUFFER_SIZE, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",
		 urlEncode(accountName), urlEncode(issuer),
		 secret_hex_buf); 
	displayQRcode(buf_totp);
	
	return (0);
}
