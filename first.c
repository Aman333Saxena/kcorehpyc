#ifndef BTC_HEADER
#define BTC_HEADER


#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "../crypto/bip39.h"
#include "../crypto/bip32.h"
#include "../crypto/curves.h"
#include "../crypto/secp256k1.h"
#include "../crypto/sha2.h"
#include "../crypto/ecdsa.h"
#include "../crypto/ripemd160.h"
#include "../crypto/base58.h"

//#include "bip39.h"
//#include "bip32.h"
//#include "curves.h"
//#include "secp256k1.h"
//#include "sha2.h"
//#include "ecdsa.h"
//#include "ripemd160.h"
//#include "base58.h"

#define BYTE_ARRAY_TO_UINT32(x) x[0]<<24|x[1]<<16|x[2]<<8|x[3]

typedef struct 
{
    uint8_t previous_txn_hash[32];
    uint8_t previous_output_index[4];
    uint8_t script_length[1];
    uint8_t script_public_key[25];
    uint8_t sequence[4];
}unsigned_txn_input;

typedef struct 
{
    uint8_t previous_txn_hash[32];
    uint8_t previous_output_index[4];
    uint8_t script_length[1];
    uint8_t script_sig[128];
    uint8_t sequence[4];
}signed_txn_input;

typedef struct 
{
    uint8_t value[8];
    uint8_t script_length[1];
    uint8_t script_public_key[25];
}txn_output;


typedef struct                           // received_unsigned_txn_string position
{
    uint8_t network_version[4];          // 0-7     
    uint8_t input_count[1];              // 8-9
    unsigned_txn_input *input;           // 10-141 (66*2*input_count) here input_count = 1
    uint8_t output_count[1];             // 142-143
    txn_output *output;                  // 144-279 (34*2*output_count) here output_count = 2
    uint8_t locktime[4];                 // 280-287
    uint8_t sighash[4];                  // 288-295                     

}unsigned_txn;

typedef struct 
{
    uint8_t network_version[4];          
    uint8_t input_count[1];
    signed_txn_input *input;             
    uint8_t output_count[1];             
    txn_output *output;                 
    uint8_t locktime[4];
}signed_txn;


typedef struct 
{
    uint8_t chain_index[4];
    uint8_t address_index[4];
}address_type; 

typedef struct 
{
    uint8_t wallet_index[1];
    uint8_t purpose_index[4];
    uint8_t coin_index[4];
    uint8_t account_index[4];
    
    uint8_t input_count[1];
    address_type *input;
    
    uint8_t output_count[1];
    address_type *output;
    
    uint8_t change_count[1];
    address_type *change;

}txn_metadata; 




// uint8_t hex_to_dec(uint8_t *hex);

// void hex_string_to_byte_array(const char *hex_string, uint32_t string_length, uint8_t *byte_array);

// void byte_array_to_unsigned_txn(uint8_t *btc_unsigned_txn_byte_array, unsigned_txn *unsigned_txn_ptr);

// void byte_array_to_txn_metadata(uint8_t *btc_txn_metadata_byte_array, txn_metadata *txn_metadata_ptr);

// void serialize_unsigned_txn_to_sign(unsigned_txn *unsigned_txn_ptr, uint8_t input_index, uint8_t *btc_serialized_unsigned_txn);

// uint32_t unsigned_txn_to_signed_txn(unsigned_txn *unsigned_txn_ptr, txn_metadata *txn_metadata_ptr, const char *mnemonic, const char *passphrase, signed_txn *signed_txn_ptr);

// void signed_txn_to_byte_array(signed_txn *signed_txn_ptr, uint8_t *generated_signed_txn_byte_array);

// #endif

unsigned int hashMap(char c)
{
    switch(c)
    {
        case '0': return 0; case '1': return 1;
        case '2': return 2; case '3': return 3;
        case '4': return 4; case '5': return 5;
        case '6': return 6; case '7': return 7;
        case '8': return 8; case '9': return 9;
        case 'a': return 10; case 'b': return 11;
        case 'c': return 12; case 'd': return 13;
        case 'e': return 14; case 'f': return 15;
    }
    return -1;
}

void hex_string_to_byte_array(const char* hex_string, uint32_t string_length, uint8_t *byte_array)
{
    uint32_t byte_i = 0, byte0 = 0, byte1 = 0, byte_value = 0;
    for (uint32_t i = 0; i < (string_length);) 
    {
        byte1 = hashMap(hex_string[i++]);
        byte0 = hashMap(hex_string[i++]);
        byte_value = (byte1 << 4) | byte0;
        byte_array[byte_i++] = byte_value;
    }
}

void byte_array_to_unsigned_txn(uint8_t *btc_unsigned_txn_byte_array, unsigned_txn *unsigned_txn_ptr)
{
    uint32_t network_version_size = sizeof(unsigned_txn_ptr->network_version)/sizeof(unsigned_txn_ptr->network_version[0]);
    uint32_t byte_i = 0, i = 0;
    for (i = 0; i < network_version_size; i++)
    {
        unsigned_txn_ptr->network_version[i] = btc_unsigned_txn_byte_array[byte_i++];
    }
    unsigned_txn_ptr->input_count[0] = btc_unsigned_txn_byte_array[byte_i++];
    for (uint32_t k = 0; k < unsigned_txn_ptr->input_count[0]; k++)
    {       
        uint32_t previous_txn_hash_size = sizeof(unsigned_txn_ptr->input->previous_txn_hash)/sizeof(unsigned_txn_ptr->input->previous_txn_hash[0]);
        for (i = 0; i < previous_txn_hash_size; i++)
        {
            unsigned_txn_ptr->input->previous_txn_hash[i] = btc_unsigned_txn_byte_array[byte_i++];
        }
        
        uint32_t previous_output_index_size = sizeof(unsigned_txn_ptr->input->previous_output_index)/sizeof(unsigned_txn_ptr->input->previous_output_index[0]);
        for (i = 0; i < previous_output_index_size; i++)
        {
            unsigned_txn_ptr->input->previous_output_index[i] = btc_unsigned_txn_byte_array[byte_i++];
        }
        
        unsigned_txn_ptr->input->script_length[0] = btc_unsigned_txn_byte_array[byte_i++];
        
        uint32_t script_public_key_size = sizeof(unsigned_txn_ptr->input->script_public_key)/sizeof(unsigned_txn_ptr->input->script_public_key[0]);
        for (i = 0; i < script_public_key_size; i++)
        {
            unsigned_txn_ptr->input->script_public_key[i] = btc_unsigned_txn_byte_array[byte_i++];
        } 

        uint32_t sequence_size = sizeof(unsigned_txn_ptr->input->sequence)/sizeof(unsigned_txn_ptr->input->sequence[0]);
        for (i = 0; i < sequence_size; i++)
        {
            unsigned_txn_ptr->input->sequence[i] = btc_unsigned_txn_byte_array[byte_i++];
        }
    }

    unsigned_txn_ptr->output_count[0] = btc_unsigned_txn_byte_array[byte_i++];
    for (uint32_t k = 0; k < unsigned_txn_ptr->output_count[0]; k++)
    {       
        uint32_t value_size = sizeof(unsigned_txn_ptr->output->value)/sizeof(unsigned_txn_ptr->output->value[0]);
        for (i = 0; i < value_size; i++)
        {
            unsigned_txn_ptr->output->value[i] = btc_unsigned_txn_byte_array[byte_i++];
        }
        
        unsigned_txn_ptr->input->script_length[0] = btc_unsigned_txn_byte_array[byte_i++];
        
        uint32_t script_public_key_size = sizeof(unsigned_txn_ptr->input->script_public_key)/sizeof(unsigned_txn_ptr->input->script_public_key[0]);
        for (i = 0; i < script_public_key_size; i++)
        {
            unsigned_txn_ptr->input->script_public_key[i] = btc_unsigned_txn_byte_array[byte_i++];
        } 
    }

    uint32_t locktime_size = sizeof(unsigned_txn_ptr->locktime)/sizeof(unsigned_txn_ptr->locktime[0]);
    for (i = 0; i < locktime_size; i++)
    {
        unsigned_txn_ptr->locktime[i] = btc_unsigned_txn_byte_array[byte_i++];
    }

    uint32_t sighash_size = sizeof(unsigned_txn_ptr->sighash)/sizeof(unsigned_txn_ptr->sighash[0]);
    for (i = 0; i < sighash_size; i++)
    {
        unsigned_txn_ptr->sighash[i] = btc_unsigned_txn_byte_array[byte_i++];
    }
}

int main()
{
	const char *received_unsigned_txn_string = "0200000001748dccb662fd73e8f0d8435132b8528dd3739f55388a15795c7e7afe4f555f9f010000001976a9140ce400ffe51ab038f6134beeb14ef56c683ce00088acfdffffff02204e0000000000001976a914d46d05e6ac27683aa5d63a6efc44969798acf13688ac28b30000000000001976a914dacc24d8b195ce046a40caedd5e2e649beee4e3388ac49211a0001000000";
	uint32_t string_length = strlen(received_unsigned_txn_string);
	uint8_t byte_array[string_length/2]; 
	hex_string_to_byte_array(received_unsigned_txn_string, string_length, byte_array);
	unsigned_txn unsigned_txn_ptr;
	byte_array_to_unsigned_txn(byte_array, unsigned_txn_ptr);
    return 0;	
}
