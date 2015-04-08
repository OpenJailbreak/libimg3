/*
 * libimg3-1.0 - img3crypt.c
 * Functions for handling with Apple's IMG3 format
 *
 * Copyright (c) 2013 Crippy-Dev Team. All Rights Reserved.
 * Copyright (c) 2010-2013 Joshua Hill. All Rights Reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define _DEBUG

#include <libimg3-1.0/libimg3.h>
#include <libcrippy-1.0/libcrippy.h>

#define IMG3_MODE_DECRYPT 1
#define IMG3_MODE_ENCRYPT 2

static int img3_quiet = 0;
static int img3_verbose = 0;
static char* img3_input = NULL;
static char* img3_output = NULL;
static char* img3_template = NULL;

void print_usage() {
	printf("img3crypt - IMG3 file encryption/decryption tool\n");
	printf("Usage: ./img3crypt [args]\n");
	printf("\t-v\t\tStart in verbose mode.\n");
	printf("\t-h\t\tShow this help.\n");
	printf("\t-q\t\tQuiet mode, no output given.\n");
	printf("\t-d <input>\tDecrypt file given\n");
	printf("\t-e <input>\tEncrypt file given\n");
	printf("\t-t <template>\tTemplate to encrypt file with\n");
	printf("\t-o <output>\tFile to write the output to\n");
	printf("\t-k <iv>\tAES Key to encrypt or decrypt with\n");
	printf("\t-i <iv>\tAES IV to encrypt or decrypt with\n");
	exit(1);
}

void hexToBytes(const char* hex, uint8_t** buffer, size_t* bytes) {
	*bytes = strlen(hex) / 2;
	*buffer = (uint8_t*) malloc(*bytes);
	size_t i;
	for(i = 0; i < *bytes; i++) {
		uint32_t byte;
		sscanf(hex, "%2x", &byte);
		(*buffer)[i] = byte;
		hex += 2;
	}
}

void hexToInts(const char* hex, unsigned int** buffer, size_t* bytes) {
	*bytes = strlen(hex) / 2;
	*buffer = (unsigned int*) malloc((*bytes) * sizeof(int));
	size_t i;
	for(i = 0; i < *bytes; i++) {
		sscanf(hex, "%2x", &((*buffer)[i]));
		hex += 2;
	}
}

int main(int argc, char* argv[]) {
	int i = 0;
	int opt = 0;
	int mode = 0;
	int action = 0;
	char* iv_str = NULL;
	char* key_str = NULL;
	char* argument = NULL;
	img3_error_t error = 0;

	if (argc == 1)
		print_usage();
	while ((opt = getopt(argc, argv, "vqhd::e::t::o::i::k::")) > 0) {
		switch (opt) {
		case 'v':
			img3_verbose += 1;
			break;

		case 'h':
			print_usage();
			break;

		case 'q':
			img3_quiet = 1;
			break;

		case 'd':
			if(mode != 0) {
				debug("Unable to use both -d and -e flags at once\n");
				return -1;
			}
			mode = IMG3_MODE_DECRYPT;
			img3_input = optarg;
			break;

		case 'e':
			if(mode != 0) {
				debug("Unable to use both -d and -e flags at once\n");
				return -1;
			}
			mode = IMG3_MODE_ENCRYPT;
			img3_input = optarg;
			break;

		case 't':
			img3_template = optarg;
			break;

		case 'o':
			img3_output = optarg;
			break;

		case 'i':
			iv_str = optarg;
			break;

		case 'k':
			key_str = optarg;
			break;

		default:
			fprintf(stderr, "Unknown argument\n");
			return -1;
		}
	}

	// TODO: Sanity check arguments being passed
	if(img3_input == NULL || img3_output == NULL) {
		error("Please specify encrypt or decrypt\n");
		return -1;
	}

	debug("Opening Img3 file %s\n", img3_input);
	img3_file_t* image = img3_open(img3_input);
	if(image) {
		debug("File opened successfully\n");
		if(mode == IMG3_MODE_DECRYPT) {
			debug("Setting Img3 Key and IV\n");
			img3_set_key(image, key_str, iv_str);
			debug("Decrypting Img3 file\n");
			img3_decrypt(image);
			// No template requested, so just dump binary
			if(img3_output) {
				debug("Found output file listed as %s\n", img3_output);
				if(image->decrypted) {
					debug("Image claims it's decrypted, dump raw data\n");
					file_write(img3_output, image->raw, image->size);
				}
			}
		} else if(mode == IMG3_MODE_ENCRYPT) {
			debug("Encrypting Img3 file\n");
			img3_set_key(image, key_str, iv_str);
			img3_encrypt(image);
		}

		debug("Closing Img3 file\n");
		img3_free(image);
	}


	return 0;
}
