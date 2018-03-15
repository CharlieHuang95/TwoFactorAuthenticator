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
	char buf[100];
	char secret_hex_buf[100];
	base32_encode(secret_hex,
		      strlen(secret_hex),
                      secret_hex_buf,
		      100);
	snprintf(buf, 100, "otpauth://hotp/%s?issuer=%s&secret=%s&counter=1",
		 urlEncode(accountName), urlEncode(issuer),
		 secret_hex_buf); 

	displayQRcode(buf);

	return (0);
}
