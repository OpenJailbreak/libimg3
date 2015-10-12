/*
 * libimg3-1.0 - libimg3.h
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

#ifndef IMG3_H
#define IMG3_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	kNorContainer = 0x696D6733,  // img3
	kImg3Container = 0x496D6733, // Img3
	k8900Container = 0x30303938, // 8900
	kImg2Container = 0x494D4732  // IMG2
} img3_container_t;

typedef enum {
	kDataElement = 0x44415441, // DATA
	kTypeElement = 0x54595045, // TYPE
	kKbagElement = 0x4B424147, // KBAG
	kShshElement = 0x53485348, // SHSH
	kCertElement = 0x43455254, // CERT
	kChipElement = 0x43484950, // CHIP
	kProdElement = 0x50524F44, // PROD
	kSdomElement = 0x53444F4D, // SDOM
	kVersElement = 0x56455253, // VERS
	kBordElement = 0x424F5244, // BORD
	kSepoElement = 0x5345504F, // SEPO
	kEcidElement = 0x45434944, // ECID
	kUnknElement = 0x53414c54  // FIXME
} img3_element_type_t;

typedef struct {
	uint32_t signature;
	uint32_t full_size;
	uint32_t data_size;
	uint32_t shsh_offset;
	uint32_t image_type;
} img3_header_t;

typedef struct {
	uint32_t signature;
	uint32_t full_size;
	uint32_t data_size;
} img3_element_header_t;

typedef struct {
	img3_element_header_t* header;
	img3_element_type_t type;
	uint8_t* data;
	uint32_t size;
} img3_element_t;

typedef struct {
    uint32_t state;
    uint32_t type;
    uint8_t iv[16];
    uint8_t key[32];
} img3_kbag_element_t;

typedef struct {
	uint8_t* iv;
	uint8_t* key;
	uint8_t* raw;
	uint8_t* data;
	uint32_t bits;
	uint32_t size;
	uint32_t decrypted;
	uint32_t num_elements;
	uint32_t idx_ecid_element;
	uint32_t idx_shsh_element;
	uint32_t idx_cert_element;
	img3_header_t* header;
	img3_element_t** elements;
} img3_file_t;

typedef enum {
	IMG3_E_SUCCESS = 0,
	IMG3_E_NOMEM = 1,
	IMG3_E_NOELEMENT = 2,
	IMG3_E_INVALIDSIZE = 3
} img3_error_t;

img3_file_t* img3_open(const char* path);
img3_file_t* img3_load(uint8_t* data, size_t size);
void img3_debug(img3_file_t* image);
void img3_free(img3_file_t* image);

img3_error_t img3_decrypt(img3_file_t* image);
img3_error_t img3_encrypt(img3_file_t* image);
img3_error_t img3_set_key(img3_file_t* image, const char* key, const char* iv);

img3_element_t* img3_element_load(uint8_t* data);
void img3_element_free(img3_element_t* element);

img3_error_t img3_replace_signature(img3_file_t* image, uint8_t* signature);
img3_error_t img3_serialize(img3_file_t* image, uint8_t** pdata, size_t* psize);
img3_error_t img3_save(img3_file_t image, const char* path);

img3_error_t img3_decompress(img3_file_t* image);


#ifdef __cplusplus
}
#endif

#endif
