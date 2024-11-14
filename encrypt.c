/*
 * encrypt.c - File Encryption Program
 *
 * This program encrypts a file using AES-256 and RSA encryption.
 *
 * Compilation Instructions:
 *   To compile for local use:
 *	 gcc -o encrypt4_xyz encrypt.c -lssl -lcrypto -DPUB_KEY_FILE=\"public_xyz.pem\" -DENCRYPTED_FILE_EXTENSION=\".xyz\"
 *
 *   To compile a remote standalone version (with public key embedded directly):
 *	 gcc -o encrypt4_xyz encrypt4_xyz_remote.c -lssl -lcrypto
 *
 * Usage:
 *   ./encrypt4_xyz <file_to_encrypt>
 *
 * Output:
 *   Creates an encrypted file with the same name as the input, plus the specified extension (e.g., ".xyz").
 */

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define PUB_KEY_BASE64 as an empty placeholder to be replaced by the Makefile
#define PUB_KEY_BASE64 ""

// Helper function to handle OpenSSL errors
void handle_openssl_error(){
	ERR_print_errors_fp( stderr );
	exit( EXIT_FAILURE );
}

// Load the embedded public key from the Base64 string
EVP_PKEY *load_public_key(){
	BIO *bio = BIO_new_mem_buf( (void *)PUB_KEY_BASE64, -1 );
	if( !bio) handle_openssl_error();

	EVP_PKEY *evp_key = PEM_read_bio_PUBKEY( bio, NULL, NULL, NULL );
	BIO_free( bio );

	if( !evp_key ) handle_openssl_error();
	return evp_key;
}

// Encrypt a symmetric key using the public RSA key
int rsa_encrypt_key( EVP_PKEY *pub_key, unsigned char *symmetric_key, size_t symmetric_key_len, unsigned char *encrypted_key ){
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new( pub_key, NULL );
	if( !ctx) handle_openssl_error();

	if( EVP_PKEY_encrypt_init( ctx) <= 0 ) handle_openssl_error();
	size_t encrypted_key_len;
	if( EVP_PKEY_encrypt( ctx, NULL, &encrypted_key_len, symmetric_key, symmetric_key_len ) <= 0 ) handle_openssl_error();

	if( EVP_PKEY_encrypt( ctx, encrypted_key, &encrypted_key_len, symmetric_key, symmetric_key_len ) <= 0 ) handle_openssl_error();

	EVP_PKEY_CTX_free( ctx );
	return (int)encrypted_key_len;
}

// Encrypt a file using RSA and AES
void encrypt_file( const char *filename, EVP_PKEY *pub_key ){
	FILE *file = fopen( filename, "rb" );
	if( !file ){
		perror("Failed to open input file" );
		exit( EXIT_FAILURE );
	}

	fseek( file, 0, SEEK_END );
	size_t file_size = ftell( file );
	fseek( file, 0, SEEK_SET );

	unsigned char *file_data = malloc( file_size );
	if( !file_data ){
		perror("Failed to allocate memory for file data");
		fclose( file );
		exit( EXIT_FAILURE );
	}
	fread( file_data, 1, file_size, file );
	fclose( file );

	unsigned char symmetric_key[32];
	if( !RAND_bytes( symmetric_key, sizeof( symmetric_key))) handle_openssl_error();

	unsigned char encrypted_key[256];
	int encrypted_key_len = rsa_encrypt_key( pub_key, symmetric_key, sizeof( symmetric_key ), encrypted_key );

	EVP_CIPHER_CTX *aes_ctx = EVP_CIPHER_CTX_new();
	if( !aes_ctx) handle_openssl_error();

	unsigned char iv[EVP_MAX_IV_LENGTH];
	if( !RAND_bytes( iv, sizeof( iv))) handle_openssl_error();

	EVP_EncryptInit_ex( aes_ctx, EVP_aes_256_cbc(), NULL, symmetric_key, iv );

	char output_filename[256];
	snprintf( output_filename, sizeof( output_filename ), "%s.[EXT]", filename );
	FILE *output_file = fopen( output_filename, "wb" );
	if( !output_file ){
		perror("Failed to open output file" );
		EVP_CIPHER_CTX_free( aes_ctx );
		free( file_data );
		exit( EXIT_FAILURE );
	}

	fwrite(&encrypted_key_len, sizeof( encrypted_key_len), 1, output_file );
	fwrite( encrypted_key, 1, encrypted_key_len, output_file );
	fwrite( iv, 1, sizeof( iv), output_file );

	unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	int outlen;
	for (size_t i = 0; i < file_size; i += 1024 ){
		int chunk_size = (i + 1024 < file_size) ? 1024 : file_size - i;
		EVP_EncryptUpdate( aes_ctx, outbuf, &outlen, file_data + i, chunk_size );
		fwrite( outbuf, 1, outlen, output_file );
	}

	EVP_EncryptFinal_ex( aes_ctx, outbuf, &outlen );
	fwrite( outbuf, 1, outlen, output_file );

	fclose( output_file );
	EVP_CIPHER_CTX_free( aes_ctx );
	free( file_data );

	printf( "File encrypted successfully as %s\n", output_filename );
}

int main( int argc, char *argv[] ){
	if( argc != 2 ){
		fprintf( stderr, "Usage: %s <input_file>\n", argv[0] );
		return 1;
	}

	EVP_PKEY *pub_key = load_public_key();
	encrypt_file( argv[1], pub_key );
	EVP_PKEY_free( pub_key );

	return 0;
}

