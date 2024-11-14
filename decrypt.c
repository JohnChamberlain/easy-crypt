/*
 * decrypt.c - File Decryption Program
 *
 * This program decrypts a file encrypted with AES-256 and RSA, using the recipient’s private key.
 *
 * Compilation Instructions:
 *   Use the Makefile to compile the program, specifying the private key file and extension:
 *	 make decrypt EXT=xyz PRIV_KEY_FILE=private_xyz.pem
 *
 * Usage:
 *   ./decrypt4_xyz <file_to_decrypt>
 *
 * Output:
 *   The decrypted file is saved with the original name, minus the extension (e.g., ".xyz"), or with ".plaintext" if the extension is missing.
 */

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Define PRIV_KEY_BASE64 as an empty placeholder to be replaced by the Makefile
#define PRIV_KEY_BASE64 ""

// Helper function to handle OpenSSL errors
void handle_openssl_error(){
	ERR_print_errors_fp( stderr );
	exit( EXIT_FAILURE );
}

// Load the embedded private key from the Base64 string
EVP_PKEY* load_private_key(){
	BIO* bio = BIO_new_mem_buf( (void*)PRIV_KEY_BASE64, -1 );
	if( !bio ) handle_openssl_error();

	EVP_PKEY* evp_key = PEM_read_bio_PrivateKey( bio, NULL, NULL, NULL );
	BIO_free( bio );

	if( !evp_key ) handle_openssl_error();
	return evp_key;
}

// Decrypt the symmetric key using the private RSA key
int rsa_decrypt_key( EVP_PKEY* priv_key, unsigned char* encrypted_key, size_t encrypted_key_len, unsigned char* symmetric_key ){
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new( priv_key, NULL );
	if( !ctx ) handle_openssl_error();

	if( EVP_PKEY_decrypt_init( ctx ) <= 0 ) handle_openssl_error();
	size_t symmetric_key_len;
	if( EVP_PKEY_decrypt( ctx, NULL, &symmetric_key_len, encrypted_key, encrypted_key_len ) <= 0 ) handle_openssl_error();

	if( EVP_PKEY_decrypt( ctx, symmetric_key, &symmetric_key_len, encrypted_key, encrypted_key_len ) <= 0 ) handle_openssl_error();

	EVP_PKEY_CTX_free( ctx );
	return (int)symmetric_key_len;
}

// Function to adjust the decrypted file name based on "[EXT]"
char* generate_output_filename( const char* input_filename ){
	size_t len = strlen( input_filename );
	const char *ext = ".[EXT]";  // This is substituted into the source code file by the makefile

	// Check if the input filename ends with ".[EXT]"
	if( len > strlen( ext ) && strcmp( input_filename + len - strlen( ext ), ext ) == 0 ){
		char *output_filename = malloc(len - strlen(ext) + 1 );
		if (!output_filename) return NULL;
		strncpy( output_filename, input_filename, len - strlen( ext ));
		output_filename[ len - strlen( ext )] = '\0';  // Remove the extension
		return output_filename;
	} else {
		// Append ".plaintext" if it doesn't end with "[EXT]"
		char *output_filename = malloc( len + 10 );  // ".plaintext" + '\0'
		if( !output_filename ) return NULL;
		snprintf( output_filename, len + 10, "%s.plaintext", input_filename );
		return output_filename;
	}
}

// Function to decrypt a file using RSA and AES
void decrypt_file( const char* filename_input, const char* filename_output, EVP_PKEY* priv_key ){
	FILE* file_input = fopen( filename_input, "rb" );
	if( !file_input ){
		fprintf( stderr, "failed to open input file: %s\n", filename_input );
		exit( EXIT_FAILURE );
	}

	int encrypted_key_len;
	fread( &encrypted_key_len, sizeof( encrypted_key_len ), 1, file_input );
	unsigned char encrypted_key[256];
	fread( encrypted_key, 1, encrypted_key_len, file_input );

	unsigned char symmetric_key[32];
	rsa_decrypt_key( priv_key, encrypted_key, encrypted_key_len, symmetric_key );

	unsigned char iv[EVP_MAX_IV_LENGTH];
	fread( iv, 1, sizeof( iv ), file_input );

	EVP_CIPHER_CTX* aes_ctx = EVP_CIPHER_CTX_new();
	if( !aes_ctx ) handle_openssl_error();

	EVP_DecryptInit_ex( aes_ctx, EVP_aes_256_cbc(), NULL, symmetric_key, iv );

	FILE* file_output = fopen( filename_output, "wb" );
	if( !file_output ){
		fprintf( stderr, "failed to open output file: %s\n", filename_output );
		EVP_CIPHER_CTX_free( aes_ctx );
		fclose( file_input );
		exit( EXIT_FAILURE );
	}

	unsigned char inbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	unsigned char outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
	int inlen, outlen;
	while( ( inlen = fread( inbuf, 1, 1024, file_input ) ) > 0 ){
		EVP_DecryptUpdate( aes_ctx, outbuf, &outlen, inbuf, inlen );
		fwrite( outbuf, 1, outlen, file_output );
	}

	EVP_DecryptFinal_ex( aes_ctx, outbuf, &outlen );
	fwrite( outbuf, 1, outlen, file_output );

	fclose( file_output );
	fclose( file_input );
	EVP_CIPHER_CTX_free( aes_ctx );

	printf( "File %s decrypted and written to %s\n", filename_input, filename_output );
}

int main( int argc, char* argv[] ){
	if( argc != 2 ){
		fprintf( stderr, "Usage: %s <encrypted_file>\n", argv[0] );
		return 1;
	}
	char* input_filename = argv[1];
	if( strlen( input_filename ) == 0 ){
		fprintf( stderr, "input file name is blank" );
		return 1;
	}
	
	char *output_filename = generate_output_filename( input_filename );
	if( ! output_filename ){
		fprintf( stderr, "Failed to generate output filename.\n");
		return 1;
	}

	EVP_PKEY* priv_key = load_private_key();
	decrypt_file( input_filename, output_filename, priv_key );
	EVP_PKEY_free( priv_key );

	return 0;
}

