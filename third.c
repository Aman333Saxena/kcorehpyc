#include <stdbool.h>
#include <string.h>
#include "address.h"
#include "aes/aes.h"
#include "base58.h"
#include "bignum.h"
#include "bip32.h"
#include "bip39.h"
#include "curves.h"
#include "ecdsa.h"
#include "ed25519-donna/ed25519-sha3.h"
#include "ed25519-donna/ed25519.h"
#include "hmac.h"
#include "nist256p1.h"
#include "secp256k1.h"
#include "sha2.h"
#include "sha3.h"
#include "ed25519-donna/ed25519-keccak.h"
#include "nem.h"
#include "pbkdf2.h"
#include "memzero.h"

typedef struct
{
    uint32_t depth;
    uint32_t child_num;
    uint8_t chain_code[32];

    uint8_t private_key[32];
    uint8_t private_key_extension[32];

    uint8_t public_key[33];
    const curve_info *curve;
} HDNode;

const curve_info curve25519_info = {
    .bip32_name = "curve25519 seed",
    .params = NULL,
    .hasher_base58 = HASHER_SHA2D,
    .hasher_sign = HASHER_SHA2D,
    .hasher_pubkey = HASHER_SHA2_RIPEMD,
    .hasher_script = HASHER_SHA2,
};

void mnemonic_to_seed(const char *mnemonic, const char *passphrase,
                      uint8_t seed[512 / 8],
                      void (*progress_callback)(uint32_t current,
                                                uint32_t total))
{
    int mnemoniclen = strlen(mnemonic);
    int passphraselen = strnlen(passphrase, 256);
#if USE_BIP39_CACHE
    // check cache
    if (mnemoniclen < 256 && passphraselen < 64)
    {
        for (int i = 0; i < BIP39_CACHE_SIZE; i++)
        {
            if (!bip39_cache[i].set)
                continue;
            if (strcmp(bip39_cache[i].mnemonic, mnemonic) != 0)
                continue;
            if (strcmp(bip39_cache[i].passphrase, passphrase) != 0)
                continue;
            // found the correct entry
            memcpy(seed, bip39_cache[i].seed, 512 / 8);
            return;
        }
    }
#endif
    uint8_t salt[8 + 256] = {0};
    memcpy(salt, "mnemonic", 8);
    memcpy(salt + 8, passphrase, passphraselen);
    static CONFIDENTIAL PBKDF2_HMAC_SHA512_CTX pctx;
    pbkdf2_hmac_sha512_Init(&pctx, (const uint8_t *)mnemonic, mnemoniclen, salt,
                            passphraselen + 8, 1);
    if (progress_callback)
    {
        progress_callback(0, BIP39_PBKDF2_ROUNDS);
    }
    for (int i = 0; i < 16; i++)
    {
        pbkdf2_hmac_sha512_Update(&pctx, BIP39_PBKDF2_ROUNDS / 16);
        if (progress_callback)
        {
            progress_callback((i + 1) * BIP39_PBKDF2_ROUNDS / 16,
                              BIP39_PBKDF2_ROUNDS);
        }
    }
    pbkdf2_hmac_sha512_Final(&pctx, seed);
    memzero(salt, sizeof(salt));
#if USE_BIP39_CACHE
    // store to cache
    if (mnemoniclen < 256 && passphraselen < 64)
    {
        bip39_cache[bip39_cache_index].set = true;
        strcpy(bip39_cache[bip39_cache_index].mnemonic, mnemonic);
        strcpy(bip39_cache[bip39_cache_index].passphrase, passphrase);
        memcpy(bip39_cache[bip39_cache_index].seed, seed, 512 / 8);
        bip39_cache_index = (bip39_cache_index + 1) % BIP39_CACHE_SIZE;
    }
#endif
}

int hdnode_from_seed(const uint8_t *seed, int seed_len, const char *curve,
                     HDNode *out)
{
    static CONFIDENTIAL uint8_t I[32 + 32];
    memzero(out, sizeof(HDNode));
    out->depth = 0;
    out->child_num = 0;
    out->curve = get_curve_by_name(curve);
    if (out->curve == 0)
    {
        return 0;
    }
    static CONFIDENTIAL HMAC_SHA512_CTX ctx;
    hmac_sha512_Init(&ctx, (const uint8_t *)out->curve->bip32_name,
                     strlen(out->curve->bip32_name));
    hmac_sha512_Update(&ctx, seed, seed_len);
    hmac_sha512_Final(&ctx, I);

    if (out->curve->params)
    {
        bignum256 a = {0};
        while (true)
        {
            bn_read_be(I, &a);
            if (!bn_is_zero(&a) // != 0
                && bn_is_less(&a, &out->curve->params->order))
            { // < order
                break;
            }
            hmac_sha512_Init(&ctx, (const uint8_t *)out->curve->bip32_name,
                             strlen(out->curve->bip32_name));
            hmac_sha512_Update(&ctx, I, sizeof(I));
            hmac_sha512_Final(&ctx, I);
        }
        memzero(&a, sizeof(a));
    }
    memcpy(out->private_key, I, 32);
    memcpy(out->chain_code, I + 32, 32);
    memzero(out->public_key, sizeof(out->public_key));
    memzero(I, sizeof(I));
    return 1;
}

int hdnode_private_ckd(HDNode *inout, uint32_t i)
{
    static CONFIDENTIAL uint8_t data[1 + 32 + 4];
    static CONFIDENTIAL uint8_t I[32 + 32];
    static CONFIDENTIAL bignum256 a, b;

    if (i & 0x80000000)
    { // private derivation
        data[0] = 0;
        memcpy(data + 1, inout->private_key, 32);
    }
    else
    { // public derivation
        if (!inout->curve->params)
        {
            return 0;
        }
        hdnode_fill_public_key(inout);
        memcpy(data, inout->public_key, 33);
    }
    write_be(data + 33, i);

    bn_read_be(inout->private_key, &a);

    static CONFIDENTIAL HMAC_SHA512_CTX ctx;
    hmac_sha512_Init(&ctx, inout->chain_code, 32);
    hmac_sha512_Update(&ctx, data, sizeof(data));
    hmac_sha512_Final(&ctx, I);

    if (inout->curve->params)
    {
        while (true)
        {
            bool failed = false;
            bn_read_be(I, &b);
            if (!bn_is_less(&b, &inout->curve->params->order))
            { // >= order
                failed = true;
            }
            else
            {
                bn_add(&b, &a);
                bn_mod(&b, &inout->curve->params->order);
                if (bn_is_zero(&b))
                {
                    failed = true;
                }
            }

            if (!failed)
            {
                bn_write_be(&b, inout->private_key);
                break;
            }

            data[0] = 1;
            memcpy(data + 1, I + 32, 32);
            hmac_sha512_Init(&ctx, inout->chain_code, 32);
            hmac_sha512_Update(&ctx, data, sizeof(data));
            hmac_sha512_Final(&ctx, I);
        }
    }
    else
    {
        memcpy(inout->private_key, I, 32);
    }

    memcpy(inout->chain_code, I + 32, 32);
    inout->depth++;
    inout->child_num = i;
    memzero(inout->public_key, sizeof(inout->public_key));

    // making sure to wipe our memory
    memzero(&a, sizeof(a));
    memzero(&b, sizeof(b));
    memzero(I, sizeof(I));
    memzero(data, sizeof(data));
    return 1;
}

int hdnode_public_ckd(HDNode *inout, uint32_t i)
{
    curve_point parent = {0}, child = {0};

    if (!ecdsa_read_pubkey(inout->curve->params, inout->public_key, &parent))
    {
        return 0;
    }
    if (!hdnode_public_ckd_cp(inout->curve->params, &parent, inout->chain_code, i,
                              &child, inout->chain_code))
    {
        return 0;
    }
    memzero(inout->private_key, 32);
    inout->depth++;
    inout->child_num = i;
    inout->public_key[0] = 0x02 | (child.y.val[0] & 0x01);
    bn_write_be(&child.x, inout->public_key + 1);

    // Wipe all stack data.
    memzero(&parent, sizeof(parent));
    memzero(&child, sizeof(child));

    return 1;
}

int hdnode_sign_digest(HDNode *node, const uint8_t *digest, uint8_t *sig,
                       uint8_t *pby,
                       int (*is_canonical)(uint8_t by, uint8_t sig[64])) {
  if (node->curve->params) {
    return ecdsa_sign_digest(node->curve->params, node->private_key, digest,
                             sig, pby, is_canonical);
  } else if (node->curve == &curve25519_info) {
    return 1;  // signatures are not supported
  } else {
    return hdnode_sign(node, digest, 32, 0, sig, pby, is_canonical);
  }
}

void hdnode_get_address(HDNode *node, uint32_t version, char *addr,
                        int addrsize)
{
    hdnode_fill_public_key(node);
    ecdsa_get_address(node->public_key, version, node->curve->hasher_pubkey,
                      node->curve->hasher_base58, addr, addrsize);
}

uint32_t hdnode_fingerprint(HDNode *node) {
  uint8_t digest[32] = {0};
  uint32_t fingerprint = 0;

  hdnode_fill_public_key(node);
  hasher_Raw(node->curve->hasher_pubkey, node->public_key, 33, digest);
  fingerprint = ((uint32_t)digest[0] << 24) + (digest[1] << 16) +
                (digest[2] << 8) + digest[3];
  memzero(digest, sizeof(digest));
  return fingerprint;
}

void hdnode_fill_public_key(HDNode *node)
{
    if (node->public_key[0] != 0)
        return;

#if USE_BIP32_25519_CURVES
    if (node->curve->params)
    {
        ecdsa_get_public_key33(node->curve->params, node->private_key,
                               node->public_key);
    }
    else
    {
        node->public_key[0] = 1;
        if (node->curve == &ed25519_info)
        {
            ed25519_publickey(node->private_key, node->public_key + 1);
        }
        else if (node->curve == &ed25519_sha3_info)
        {
            ed25519_publickey_sha3(node->private_key, node->public_key + 1);
#if USE_KECCAK
        }
        else if (node->curve == &ed25519_keccak_info)
        {
            ed25519_publickey_keccak(node->private_key, node->public_key + 1);
#endif
        }
        else if (node->curve == &curve25519_info)
        {
            curve25519_scalarmult_basepoint(node->public_key + 1, node->private_key);
#if USE_CARDANO
        }
        else if (node->curve == &ed25519_cardano_info)
        {
            ed25519_publickey_ext(node->private_key, node->private_key_extension,
                                  node->public_key + 1);
#endif
        }
    }
#else

    ecdsa_get_public_key33(node->curve->params, node->private_key,
                           node->public_key);
#endif
}

uint32_t print_hd_node (HDNode *node)
{
    printf("%d%d", node->depth, node->child_num);
    for (uint32_t i = 0; i < 32; i++)
    {
        printf("%02hhx", node->chain_code[i]);
    }
    for (uint32_t i = 0; i < 32; i++)
    {
        printf("%02hhx", node->private_key[i]);
    }
    for (uint32_t i = 0; i < 32; i++)
    {
        printf("%02hhx", node->private_key_extension[i]);
    }
    for (uint32_t i = 0; i < 33; i++)
    {
        printf("%02hhx", node->public_key[i]);
    }
    printf("%s", node->curve);
    return 1;
}

int main()
{
    const char mnemonic = "garden reject beauty inch scissors rifle amazing couch bacon multiply swim poverty impose spray ugly term stamp prevent nothing mutual awful project wrist movie";
    char passphrase = "";
    int seed_len = 512 / 8;
    uint8_t seed[seed_len], by, pby[64];
    mnemonic_to_seed(mnemonic, passphrase, seed, progress_callback(0, 0)); // Derived bip39 seed from mnemonics using bip39 library
    for (uint32_t i = 0; i < seed_len; i++)
    {
        printf("%02hhx", seed[i]);
    }

    char curve = "CURVE25519_NAME";
    HDNode inout;
    int make_HDnode = hdnode_from_seed(seed, seed_len, curve, inout); // Derived master node from bip39 seeds (index = 00000000 in hex)

    uint32_t print_master_node = print_hd_node(inout);

    uint32_t fingerprint = hdnode_fingerprint(inout);
    uint8_t digest[32], sig[64];
    uint32_t signd = fingerprinthdnode_sign_digest(inout, digest, sig, pby);

    uint32_t purpose_node_index = 44;
    uint32_t get_purpose_node = hdnode_private_ckd(inout, purpose_node_index); // Derived purpose nodes(index = 8000002c in hex) from master node.
    uint32_t print_purpose_node = print_hd_node(inout);
    // m/44’

    uint32_t coin_node_index = 1;
    uint32_t get_coin_node = hdnode_private_ckd(inout, coin_node_index); // Derived coin node from purpose node (index = 80000001 in hex)
    uint32_t print_coin_node = print_hd_node(inout);
    // m/44’/1’

    uint32_t account_node_index = 0;
    uint32_t get_account_node = hdnode_private_ckd(inout, account_node_index); // Derived account node from coin node (index = 80000000 in hex)
    uint32_t print_account_node = print_hd_node(inout);
    // m/44’/1’/0’

    uint32_t change_node_index = 1;
    uint32_t get_change_node = hdnode_public_ckd(inout, change_node_index); // Derived change node from account node (index = 00000000 or index = 00000001 in hex)
    uint32_t print_change_node = print_hd_node(inout);
    // m/44’/1’/0’/1

    uint32_t address_node_index = 0;
    uint32_t get_address_node = hdnode_public_ckd(inout, address_node_index); 
    uint8_t version, addrsize  = 4;                             // from address node
    char address;                                                           // from external node
    hdnode_get_address(inout, version, address, addrsize);                  // Derived address node from change node (index = 00000000 to FFFFFFFE in hex)
    uint32_t print_address_node = print_hd_node(inout);
    // m/44’/1’/0’/1/0

    uint32_t get_private_keys = hdnode_private_ckd(inout, address_node_index); //Derived private keys from address node (index = 00000000 in hex)
    for (uint32_t i = 0; i < 32; i++)
    {
        printf("%02hhx", inout->private_key[i]);
    }
    
    return 0;
}
