#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/types.h>


#define NULL_CIPHER_KEY_SIZE   16
#define NULL_CIPHER_BLOCK_SIZE 16

struct nullCipher_ctx
{
	u8 key[NULL_CIPHER_KEY_SIZE];
};

int nullCipher_setkey(struct crypto_tfm *tfm, const u8 *key, unsigned int len)
{
	//struct nullCipher_ctx * ctx = crypto_tfm_ctx(tfm);
	return 0;
}

static void nullCipher_crypt(struct crypto_tfm *tfm, u8 *out, const u8 *in)
{
	int i;
	for (i = 0; i < NULL_CIPHER_BLOCK_SIZE; i++)
	{
		out[i] = in[i];
	}
}


static struct crypto_alg nullCipher = {
	.cra_name = "nullCipher",
	.cra_driver_name = "nullCipher-generic",
	.cra_priority = 100,
	.cra_flags = CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize = NULL_CIPHER_BLOCK_SIZE,
	.cra_ctxsize = sizeof(struct nullCipher_ctx),
	.cra_module = THIS_MODULE,
	.cra_u = {
		.cipher = {
			.cia_min_keysize = NULL_CIPHER_KEY_SIZE,
			.cia_max_keysize = NULL_CIPHER_KEY_SIZE,
			.cia_setkey	= nullCipher_setkey,
			.cia_encrypt = nullCipher_crypt,
			.cia_decrypt = nullCipher_crypt
		}
	}
};



static int __init nullCipher_init(void)
{
	return crypto_register_alg(&nullCipher);
}

static void __exit nullCipher_exit(void)
{
	crypto_unregister_alg(&nullCipher);
}

module_init(nullCipher_init);
module_exit(nullCipher_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("nullCipher module");
MODULE_ALIAS_CRYPTO("nullCipher-generic");
