#include "af_SHA256.h"

static void XORblock(const char *src1, const char *src2, char *dst, size_t n)
{
	size_t j;

	for (j = 0; j < n; j++)
		dst[j] = src1[j] ^ src2[j];
}

static int hash_buf(const char *src, char *dst, uint32_t iv,
					size_t len)
{
	char *iv_char = (char *)&iv;
	iv = byteReverse32(iv);

	char m[32 + 4];
	memcpy(m, iv_char, 4);
	memcpy(m + 4, src, 32);
	SHA256(m, 32 + 4, dst);
	return 0;
}

static int diffuse(char *src, char *dst, size_t size)
{
	//  sha256 hash_size = 32
	int r, hash_size = 32; 
	unsigned int digest_size;
	unsigned int i, blocks, padding;

	digest_size = hash_size;

	blocks = size / digest_size;
	padding = size % digest_size;

	for (i = 0; i < blocks; i++)
	{
		r = hash_buf(src + digest_size * i,
					 dst + digest_size * i,
					 i, (size_t)digest_size);
		if (r < 0)
			return r;
	}

	if (padding)
	{
		r = hash_buf(src + digest_size * i,
					 dst + digest_size * i,
					 i, (size_t)padding);
		if (r < 0)
			return r;
	}

	return 0;
}

int AF_merge(const char *src, char *dst,
			 size_t blocksize, unsigned int blocknumbers)
{
	unsigned int i;
	char *bufblock;
	int r;

	bufblock = (char *)malloc(blocksize);
	memset(bufblock, 0, blocksize);


	for (i = 0; i < blocknumbers - 1; i++)
	{
		XORblock(src + blocksize * i, bufblock, bufblock, blocksize);
		r = diffuse(bufblock, bufblock, blocksize);
		if (r < 0)
			goto out;
	}
	XORblock(src + blocksize * i, bufblock, dst, blocksize);
	r = 0;
out:
	free(bufblock);
	return r;
}


/* Size of final split data including sector alignment */
size_t AF_split_sectors(size_t blocksize, unsigned int blocknumbers)
{
	size_t af_size;

	/* data material * stripes */
	af_size = blocksize * blocknumbers;

	/* round up to sector */
	af_size = (af_size + (SECTOR_SIZE - 1)) / SECTOR_SIZE;

	return af_size;
}
