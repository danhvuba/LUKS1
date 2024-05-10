#include <openssl/sha.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

// my computer is little endian, so i define a byte reverse function
#define LITTLE_ENDIAN

#ifndef LITTLE_ENDIAN
#define byteReverse16(x) x
#define byteReverse32(x) x
#else
#define byteReverse16(x) __builtin_bswap16(x)
#define byteReverse32(x) __builtin_bswap32(x)
#endif

#define SECTOR_SIZE 512

int AF_merge(const char *src, char *dst, size_t blocksize,
			 unsigned int blocknumbers);

size_t AF_split_sectors(size_t blocksize, unsigned int blocknumbers);
