/*
 * libimg3-1.0 - libimg3.c
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
#include <stdint.h>
#include <string.h>

#include <img3-1.0/libimg3.h>
#include <libcrippy-1.0/libcrippy.h>


img3_file_t* img3_open(const char* path) {
	uint32_t size = 0;
	uint8_t* data = NULL;
	img3_file_t* image = NULL;
	if (path) {
		int x = file_read(path, &data, &size);
		if(x > 0 && x == size) {
			image = img3_load(data, size);
		}
	}
	return image;
}

img3_file_t* img3_load(uint8_t* data, size_t size) {
	int data_offset = 0;
	img3_element_t* element;
	img3_header_t* header = (img3_header_t*) data;
	if (header->signature != kImg3Container) {
		error("ERROR: Invalid IMG3 file\n");
		return NULL;
	}

	img3_file_t* image = (img3_file_t*) malloc(sizeof(img3_file_t));
	if (image == NULL) {
		error("ERROR: Unable to allocate memory for IMG3 file\n");
		return NULL;
	}
	memset(image, '\0', sizeof(img3_file_t));
	image->data = data;
	image->size = size;

	image->header = (img3_header_t*) malloc(sizeof(img3_header_t));
	if (image->header == NULL) {
		error("ERROR: Unable to allocate memory for IMG3 header\n");
		img3_free(image);
		return NULL;
	}
	memcpy(image->header, data, sizeof(img3_header_t));
	data_offset += sizeof(img3_header_t);

	img3_element_header_t* current = NULL;
	while (data_offset < size) {
		current = (img3_element_header_t*) &data[data_offset];
		switch (current->signature) {
		case kTypeElement:
			element = img3_parse_element(&data[data_offset]);
			if (element == NULL) {
				error("ERROR: Unable to parse TYPE element\n");
				img3_free(image);
				return NULL;
			}
			image->elements[image->num_elements++] = element;
			debug("Parsed TYPE element\n");
			break;

		case kDataElement:
			element = img3_parse_element(&data[data_offset]);
			if (element == NULL) {
				error("ERROR: Unable to parse DATA element\n");
				img3_free(image);
				return NULL;
			}
			image->elements[image->num_elements++] = element;
			debug("Parsed DATA element\n");
			break;

		case kVersElement:
			element = img3_parse_element(&data[data_offset]);
			if (element == NULL) {
				error("ERROR: Unable to parse VERS element\n");
				img3_free(image);
				return NULL;
			}
			image->elements[image->num_elements++] = element;
			debug("Parsed VERS element\n");
			break;

		case kSepoElement:
			element = img3_parse_element(&data[data_offset]);
			if (element == NULL) {
				error("ERROR: Unable to parse SEPO element\n");
				img3_free(image);
				return NULL;
			}
			image->elements[image->num_elements++] = element;
			debug("Parsed SEPO element\n");
			break;

		case kBordElement:
			element = img3_parse_element(&data[data_offset]);
			if (element == NULL) {
				error("ERROR: Unable to parse BORD element\n");
				img3_free(image);
				return NULL;
			}
			image->elements[image->num_elements++] = element;
			debug("Parsed BORD element\n");
			break;

		case kChipElement:
			element = img3_parse_element(&data[data_offset]);
			if (element == NULL) {
				error("ERROR: Unable to parse CHIP element\n");
				img3_free(image);
				return NULL;
			}
			image->elements[image->num_elements++] = element;
			debug("Parsed CHIP element\n");
			break;

		case kKbagElement:
			element = img3_parse_element(&data[data_offset]);
			if (element == NULL) {
				error("ERROR: Unable to parse first KBAG element\n");
				img3_free(image);
				return NULL;
			}
			image->elements[image->num_elements++] = element;
			debug("Parsed KBAG element\n");
			break;

		case kEcidElement:
			element = img3_parse_element(&data[data_offset]);
			if (element == NULL) {
				error("ERROR: Unable to parse ECID element\n");
				img3_free(image);
				return NULL;
			}
			image->idx_ecid_element = image->num_elements;
			image->elements[image->num_elements++] = element;
			debug("Parsed ECID element\n");
			break;

		case kShshElement:
			element = img3_parse_element(&data[data_offset]);
			if (element == NULL) {
				error("ERROR: Unable to parse SHSH element\n");
				img3_free(image);
				return NULL;
			}
			image->idx_shsh_element = image->num_elements;
			image->elements[image->num_elements++] = element;
			debug("Parsed SHSH element\n");
			break;

		case kCertElement:
			element = img3_parse_element(&data[data_offset]);
			if (element == NULL) {
				error("ERROR: Unable to parse CERT element\n");
				img3_free(image);
				return NULL;
			}
			image->idx_cert_element = image->num_elements;
			image->elements[image->num_elements++] = element;
			debug("Parsed CERT element\n");
			break;

		case kUnknElement:
			element = img3_parse_element(&data[data_offset]);
			if (element == NULL) {
				error("ERROR: Unable to parse UNKN element\n");
				img3_free(image);
				return NULL;
			}
			image->elements[image->num_elements++] = element;
			debug("Parsed UNKN element\n");
			break;

		default:
			error("ERROR: Unknown IMG3 element type %08x\n", current->signature);
			img3_free(image);
			return NULL;
		}
		data_offset += current->full_size;
	}

	return image;
}


img3_error_t img3_decrypt(img3_file_t* image, uint8_t* iv, uint8_t* key) {
	return IMG3_E_SUCCESS;
}

img3_error_t img3_encrypt(img3_file_t* image, uint8_t* iv, uint8_t* key) {
	return IMG3_E_SUCCESS;
}

img3_element_t* img3_parse_element(char* data) {
	img3_element_header_t* element_header = (img3_element_header_t*) data;
	img3_element_t* element = (img3_element_t*) malloc(sizeof(img3_element_t));
	if (element == NULL) {
		error("ERROR: Unable to allocate memory for IMG3 element\n");
		return NULL;
	}
	memset(element, '\0', sizeof(img3_element_t));

	element->data = (char*) malloc(element_header->full_size);
	if (element->data == NULL) {
		error("ERROR: Unable to allocate memory for IMG3 element data\n");
		free(element);
		return NULL;
	}
	memcpy(element->data, data, element_header->full_size);
	element->header = (img3_element_header_t*) element->data;
	element->type = (img3_element_type_t) element->header->signature;

	return element;
}

void img3_free(img3_file_t* image) {
	if (image != NULL) {
		if (image->header != NULL) {
			free(image->header);
		}

		int i;
		for (i = 0; i < image->num_elements; i++) {
			img3_free_element(image->elements[i]);
			image->elements[i] = NULL;
		}
		free(image);
		image = NULL;
	}
}

void img3_free_element(img3_element_t* element) {
	if (element != NULL) {
		if (element->data != NULL) {
			free(element->data);
			element->data = NULL;
		}
		free(element);
		element = NULL;
	}
}

img3_error_t img3_replace_signature(img3_file_t* image, char* signature) {
	int i, oldidx;
	int offset = 0;
	img3_element_t* ecid = img3_parse_element(&signature[offset]);
	if (ecid == NULL || ecid->type != kEcidElement) {
		error("ERROR: Unable to find ECID element in signature\n");
		return IMG3_E_NOELEMENT;
	}
	offset += ecid->header->full_size;

	img3_element_t* shsh = img3_parse_element(&signature[offset]);
	if (shsh == NULL || shsh->type != kShshElement) {
		error("ERROR: Unable to find SHSH element in signature\n");
		return IMG3_E_NOELEMENT;
	}
	offset += shsh->header->full_size;

	img3_element_t* cert = img3_parse_element(&signature[offset]);
	if (cert == NULL || cert->type != kCertElement) {
		error("ERROR: Unable to find CERT element in signature\n");
		return IMG3_E_NOELEMENT;
	}
	offset += cert->header->full_size;

	if (image->idx_ecid_element >= 0) {
		img3_free_element(image->elements[image->idx_ecid_element]);
		image->elements[image->idx_ecid_element] = ecid;
	} else {
		if (image->idx_shsh_element >= 0) {
			// move elements by 1
			oldidx = image->idx_shsh_element;
			for (i = image->num_elements-1; i >= oldidx; i--) {
				image->elements[i+1] = image->elements[i];
				switch (image->elements[i+1]->type) {
				case kShshElement:
					image->idx_shsh_element = i+1;
					break;
				case kCertElement:
					image->idx_cert_element = i+1;
					break;
				case kEcidElement:
					image->idx_ecid_element = i+1;
					break;
				default:
					break;
				}
			}
			image->elements[oldidx] = ecid;
			image->idx_ecid_element = oldidx;
			image->num_elements++;
		} else {
			// append if not found
			image->elements[image->num_elements] = ecid;
			image->idx_ecid_element = image->num_elements;
			image->num_elements++;
		}
	}

	if (image->idx_shsh_element >= 0) {
		img3_free_element(image->elements[image->idx_shsh_element]);
		image->elements[image->idx_shsh_element] = shsh;
	} else {
		if (image->idx_cert_element >= 0) {
			// move elements by 1
			oldidx = image->idx_cert_element;
			for (i = image->num_elements-1; i >= oldidx; i--) {
				image->elements[i+1] = image->elements[i];
				switch (image->elements[i+1]->type) {
				case kShshElement:
					image->idx_shsh_element = i+1;
					break;
				case kCertElement:
					image->idx_cert_element = i+1;
					break;
				case kEcidElement:
					image->idx_ecid_element = i+1;
					break;
				default:
					break;
				}
			}
			image->elements[oldidx] = shsh;
			image->idx_shsh_element = oldidx;
			image->num_elements++;
		} else {
			// append if not found
			image->elements[image->num_elements] = shsh;
			image->idx_shsh_element = image->num_elements;
			image->num_elements++;
		}

		error("%s: ERROR: no SHSH element found to be replaced\n", __func__);
		img3_free_element(shsh);
		return IMG3_E_NOELEMENT;
	}

	if (image->idx_cert_element >= 0) {
		img3_free_element(image->elements[image->idx_cert_element]);
		image->elements[image->idx_cert_element] = cert;
	} else {
		// append if not found
		image->elements[image->num_elements] = cert;
		image->idx_cert_element = image->num_elements;
		image->num_elements++;
	}

	return IMG3_E_SUCCESS;
}

img3_error_t img3_serialize(img3_file_t* image, char** pdata, int* psize) {
	int i;
	int offset = 0;
	int size = sizeof(img3_header_t);

	// Add up the size of the image first so we can allocate our memory
	for (i = 0; i < image->num_elements; i++) {
		size += image->elements[i]->header->full_size;
	}

	debug("reconstructed size: %d\n", size);

	char* data = (char*) malloc(size);
	if (data == NULL) {
		return IMG3_E_NOMEM;
	}

	// Add data to our new header (except shsh_offset)
	img3_header_t* header = (img3_header_t*) data;
	header->full_size = size;
	header->signature = image->header->signature;
	header->data_size = size - sizeof(img3_header_t);
	header->image_type = image->header->image_type;
	offset += sizeof(img3_header_t);

	// Copy each section over to the new buffer
	for (i = 0; i < image->num_elements; i++) {
		memcpy(&data[offset], image->elements[i]->data, image->elements[i]->header->full_size);
		if (image->elements[i]->type == kShshElement) {
			header->shsh_offset = offset - sizeof(img3_header_t);
		}
		offset += image->elements[i]->header->full_size;
	}

	if (offset != size) {
		error("ERROR: Incorrectly sized image data\n");
		free(data);
		*pdata = 0;
		*psize = 0;
		return IMG3_E_INVALIDSIZE;
	}

	*pdata = data;
	*psize = size;
	return IMG3_E_SUCCESS;
}


img3_error_t img3_save(img3_file_t image, const char* path) {
	return IMG3_E_SUCCESS;
}
