#ifndef SRC_LZSS_H_
#define SRC_LZSS_H_

#include <stdint.h>

#define COMP_SIGNATURE 0x636F6D70
#define LZSS_SIGNATURE 0x6C7A7373

typedef struct {
	uint32_t signature;
	uint32_t compression_type;
	uint32_t checksum;
	uint32_t length_uncompressed;
	uint32_t length_compressed;
	uint8_t  padding[0x16C];
	uint8_t  data[0];
} __attribute__((__packed__)) comp_header_t;

uint32_t lzadler32(uint8_t* buf, int32_t len);
int lzss_decompress(uint8_t* dst, uint8_t* src, uint32_t srclen);
uint8_t* lzss_compress(uint8_t* dst, uint32_t dstlen, uint8_t* src, uint32_t srcLen);


#endif /* SRC_LZSS_H_ */
