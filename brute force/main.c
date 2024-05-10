
#include <openssl/evp.h>
#include "af_SHA256.h"
#include "kuznyechik.h"
#include <time.h>

// gcc *.c -lcrypto -o main ; .\main

#define LUKS_MAGIC {'L', 'U', 'K', 'S', 0xba, 0xbe};
#define LUKS_MAGIC_L 6

#define LUKS_CIPHERNAME_L 32
#define LUKS_CIPHERMODE_L 32
#define LUKS_HASHSPEC_L 32
#define LUKS_DIGESTSIZE 20
#define LUKS_HMACSIZE 32
#define LUKS_SALTSIZE 32
#define LUKS_NUMKEYS 8
#define UUID_STRING_L 40

struct luks_phdr
{
    char magic[LUKS_MAGIC_L];
    uint16_t version;
    char cipherName[LUKS_CIPHERNAME_L];
    char cipherMode[LUKS_CIPHERMODE_L];
    char hashSpec[LUKS_HASHSPEC_L];
    uint32_t payloadOffset;
    uint32_t keyBytes;
    unsigned char mkDigest[LUKS_DIGESTSIZE];
    unsigned char mkDigestSalt[LUKS_SALTSIZE];
    uint32_t mkDigestIterations;
    char uuid[UUID_STRING_L];

    struct
    {
        uint32_t active;

        /* parameters used for password processing */
        uint32_t passwordIterations;
        unsigned char passwordSalt[LUKS_SALTSIZE];

        /* parameters used for AF store/load */
        uint32_t keyMaterialOffset;
        uint32_t stripes;
    } keyblock[LUKS_NUMKEYS];

    /* Align it to 512 sector size */
    char _padding[432];
};

void printPhdr(struct luks_phdr *phdr)
{
    // printf("magic: %s\n",phdr->magic);
    printf("Version :       %d\n", phdr->version);
    printf("Cipher name:    %s\n", phdr->cipherName);
    printf("Cipher mode:    %s\n", phdr->cipherMode);
    printf("Hash spec:      %s\n", phdr->hashSpec);
    printf("Payload offset: %d\n", phdr->payloadOffset);
    printf("MK bits:        %d\n", phdr->keyBytes * 8);
    printf("MK digest:      ");
    for (int i = 0; i < LUKS_DIGESTSIZE; i++)
    {
        printf("%02x ", phdr->mkDigest[i]);
    }
    printf("\nMK salt:        ");
    for (int i = 0; i < LUKS_SALTSIZE / 2; i++)
    {
        printf("%02x ", phdr->mkDigestSalt[i]);
    }
    printf("\n                ");
    for (int i = 0; i < LUKS_SALTSIZE / 2; i++)
    {
        printf("%02x ", phdr->mkDigestSalt[i + LUKS_SALTSIZE / 2]);
    }

    printf("\nMK iterations:  %d\n", phdr->mkDigestIterations);
    printf("UUID: %s\n\n", phdr->uuid);

    // key slot
    for (int i = 0; i < LUKS_NUMKEYS; i++)
    {
        printf("Key Slot %d: ", i);
        if (phdr->keyblock[i].active == 0x00AC71F3)
        {
            printf("ENABLED\n");
        }
        else if (phdr->keyblock[i].active == 0x0000DEAD)
        {
            printf("DISABLED\n");
            continue;
        }
        else
        {
            printf("error!\n");
            continue;
        }
        printf("     Iteration:           %d\n", phdr->keyblock[i].passwordIterations);
        printf("     Salt:                ");
        for (int j = 0; j < LUKS_SALTSIZE / 2; j++)
        {
            printf("%02x ", phdr->keyblock[i].passwordSalt[j]);
        }
        printf("\n                          ");
        for (int j = 0; j < LUKS_SALTSIZE / 2; j++)
        {
            printf("%02x ", phdr->keyblock[i].passwordSalt[j + LUKS_SALTSIZE / 2]);
        }

        printf("\n     Key material offset: %d\n", phdr->keyblock[i].keyMaterialOffset);
        printf("     AF stripes:          %d\n", phdr->keyblock[i].stripes);
    }
}

void getLUKS1phdr(char *filePath, struct luks_phdr *phdr)
{
    unsigned char img[592];
    uint16_t *buff16;
    uint32_t *buff32;
    FILE *file = fopen(filePath, "rb");
    for (int i = 0; i < 592; i++)
    {
        img[i] = fgetc(file);
    }
    fclose(file);

    memcpy(phdr->magic, img + 0, 6);
    buff16 = (uint16_t *)(img + 6);
    phdr->version = byteReverse16(*buff16);

    memcpy(phdr->cipherName, img + 8, 32);
    memcpy(phdr->cipherMode, img + 40, 32);
    memcpy(phdr->hashSpec, img + 72, 32);

    buff32 = (uint32_t *)(img + 104);
    phdr->payloadOffset = byteReverse32(*buff32);

    buff32 = (uint32_t *)(img + 108);
    phdr->keyBytes = byteReverse32(*buff32);

    memcpy(phdr->mkDigest, img + 112, 20);
    memcpy(phdr->mkDigestSalt, img + 132, 32);

    buff32 = (uint32_t *)(img + 164);
    phdr->mkDigestIterations = byteReverse32(*buff32);

    memcpy(phdr->uuid, img + 168, 40);

    for (int i = 0; i < LUKS_NUMKEYS; i++)
    {
        buff32 = (uint32_t *)(img + 208 + 48 * i);
        phdr->keyblock[i].active = byteReverse32(*buff32);

        buff32 = (uint32_t *)(img + 208 + 48 * i + 4);
        phdr->keyblock[i].passwordIterations = byteReverse32(*buff32);

        memcpy(phdr->keyblock[i].passwordSalt, img + 208 + 48 * i + 8, 32);

        buff32 = (uint32_t *)(img + 208 + 48 * i + 40);
        phdr->keyblock[i].keyMaterialOffset = byteReverse32(*buff32);

        buff32 = (uint32_t *)(img + 208 + 48 * i + 44);
        phdr->keyblock[i].stripes = byteReverse32(*buff32);
    }

    printPhdr(phdr);
}

void getAF_EK(char *filePath, struct luks_phdr *phdr, int num_key, uint8_t *AFKey, size_t AF_EKSize)
{
    char buff;
    FILE *file = fopen(filePath, "rb");
    for (int i = 0; i < (phdr->keyblock[num_key].keyMaterialOffset * SECTOR_SIZE); i++)
    {
        buff = fgetc(file);
    }
    for (int i = 0; i < AF_EKSize; i++)
    {
        AFKey[i] = fgetc(file);
    }
    fclose(file);
}

int checkPass(char *pass, struct luks_phdr *phdr, int keySlot, uint8_t *AFKey, size_t AF_EKSize)
{
    uint8_t *key = (uint8_t *)malloc(phdr->keyBytes * sizeof(uint8_t));
    PKCS5_PBKDF2_HMAC(pass, strlen(pass), phdr->keyblock[keySlot].passwordSalt, LUKS_SALTSIZE, phdr->keyblock[keySlot].passwordIterations, EVP_get_digestbyname(phdr->hashSpec), phdr->keyBytes, key);
    
    struct kuznyechik_ctx ctx;
    kuznyechik_set_key(&ctx, key, phdr->keyBytes);
    for (int i = 0; i < (AF_EKSize / 16); i++)
    {
        kuznyechik_decrypt(&ctx, AFKey + i * 16, AFKey + 16 * i);
    }

    unsigned char masterKey[32];
    AF_merge(AFKey, masterKey, 32, 4000);

    uint8_t digestMk[LUKS_DIGESTSIZE];
    PKCS5_PBKDF2_HMAC(masterKey, phdr->keyBytes, phdr->mkDigestSalt, LUKS_SALTSIZE, phdr->mkDigestIterations, EVP_get_digestbyname(phdr->hashSpec), LUKS_DIGESTSIZE, digestMk);

    // check digest master key
    if (!CRYPTO_memcmp(digestMk, phdr->mkDigest, LUKS_DIGESTSIZE))
    {
        printf("success\n");

        printf("master key:\n");
        for (int i = 0; i < 32; i++)
        {
            printf("%02x ", masterKey[i]);
        }
        printf("\n");

        printf("password is : \"%s\"\n", pass);
        return 0;
    }
    return 1;
}

int main()
{
    ////////////////////////////// file img header
    char filePath[] = "kuz_ecb.img";
    // get phdr
    struct luks_phdr phdr;
    getLUKS1phdr(filePath, &phdr);

    ////////////////////////////// check password key slot 0
    int keySlot = 0;
    // check pass
    char *pass = "a";

    // get key material
    size_t AF_EKSize = AF_split_sectors(phdr.keyBytes, phdr.keyblock[keySlot].stripes) * SECTOR_SIZE;
    uint8_t *AFKey = (uint8_t *)malloc(AF_EKSize);
    getAF_EK(filePath, &phdr, keySlot, AFKey, AF_EKSize);

    
    printf("check key slot %d, password : \"%s\" \n...\n", keySlot, pass);
    clock_t begin = clock();

    if (checkPass(pass, &phdr, keySlot, AFKey, AF_EKSize))
    {
        printf("wrong password\n");
    }
    clock_t end = clock();
    printf("Time run: %f",(float)(end-begin)/CLOCKS_PER_SEC);
    return 0;
}
