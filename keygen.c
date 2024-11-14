// gcc -o keygen keygen.c -lssl -lcrypto
// usage: ./keygen <name or initials>

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>

static const int KEY_SIZE = 2048; // NIST recommended RSA key size

void handle_openssl_error() {
	ERR_print_errors_fp( stderr );
	exit( EXIT_FAILURE );
}

void save_key_to_file( EVP_PKEY *pkey, const char *name ){
	char pub_filename[ 256 ];
	char priv_filename[ 256 ];

	snprintf( pub_filename, sizeof( pub_filename ), "public_%s.pem", name );
	snprintf( priv_filename, sizeof( priv_filename ), "private_%s.pem", name );

	FILE *pub_file = fopen( pub_filename, "wb" );
	if( !pub_file ){
		perror( "Failed to open public key file" );
		exit( EXIT_FAILURE );
	}

	FILE *priv_file = fopen( priv_filename, "wb" );
	if( !priv_file ){
		perror( "Failed to open private key file" );
		fclose( pub_file );
		exit( EXIT_FAILURE );
	}

	// Write the public key in PEM format
	if( !PEM_write_PUBKEY( pub_file, pkey ) ) handle_openssl_error();

	// Write the private key in PEM format
	if( !PEM_write_PrivateKey( priv_file, pkey, NULL, NULL, 0, NULL, NULL ) ) handle_openssl_error();

	fclose( pub_file );
	fclose( priv_file );

	printf( "Keys saved as %s and %s\n", pub_filename, priv_filename );
}

int main( int argc, char *argv[] ){
	if( argc != 2 ){
		fprintf( stderr, "Usage: %s <name>\n", argv[0] );
		return 1;
	}

	const char *name = argv[1];

	// Generate RSA key
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id( EVP_PKEY_RSA, NULL );
	if( !ctx) handle_openssl_error();

	if( EVP_PKEY_keygen_init( ctx) <= 0 ) handle_openssl_error();
	if( EVP_PKEY_CTX_set_rsa_keygen_bits( ctx, KEY_SIZE ) <= 0 ) handle_openssl_error();

	EVP_PKEY *pkey = NULL;
	if( EVP_PKEY_keygen( ctx, &pkey) <= 0 ) handle_openssl_error();

	save_key_to_file( pkey, name );

	EVP_PKEY_free( pkey );
	EVP_PKEY_CTX_free( ctx );

	return 0;
}

