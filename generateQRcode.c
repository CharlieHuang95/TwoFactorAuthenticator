#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "lib/encoding.h"

int
main(int argc, char * argv[])
{
	if ( argc != 4 ) {
		printf("Usage: %s [issuer] [accountName] [secretHex]\n", argv[0]);
		return(-1);
	}

	char *	issuer = argv[1];
	char *	accountName = argv[2];
	char *	secret_hex = argv[3];

	assert (strlen(secret_hex) <= 20);

	printf("\nIssuer: %s\nAccount Name: %s\nSecret (Hex): %s\n\n",
		issuer, accountName, secret_hex);

	// Create an otpauth:// URI and display a QR code that's compatible
	// with Google Authenticator
	char buf_hotp[100];
	char buf_totp[100];
	
	uint8_t secret[10];
	uint8_t secret_hex_buf[100];
	int i = 0;
	
	// Prepare secret_hex into format accepted by base32_encode
	for (i = 0; i<strlen(secret_hex)/2; i++) {
	    sscanf(secret_hex + 2*i, "%02x", &secret[i]);
	}
    printf("%s", secret);	
	// Write encoded secret into secret_hex_buf
	base32_encode(secret,
		      strlen(secret),
                      secret_hex_buf,
		      100);
		      
    // display HOTP and TOTP QR codes
	snprintf(buf_hotp, 100, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",
		 urlEncode(accountName), urlEncode(issuer),
		 secret_hex_buf); 
	displayQRcode(buf_hotp);
	
	snprintf(buf_totp, 100, "otpauth://totp/%s?issuer=%s&secret=%s&period=30",
		 urlEncode(accountName), urlEncode(issuer),
		 secret_hex_buf); 
	displayQRcode(buf_totp);
	
	return (0);
}
