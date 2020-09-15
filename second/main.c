#ifndef BTC_HEADER
#define BTC_HEADER


#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>


#include "bip39.h"
#include "bip39_english.h"
#include "hmac.h"
#include "memzero.h"
#include "options.h"
#include "pbkdf2.h"
#include "rand.h"
#include "sha2.h"

uint32_t mnemonic_to_entropy(const char *mnemonic, uint8_t *entropy_array)
{
    if (!mnemonic) {
        return 0;                                   // if there is no phrases return 0
    }

    uint32_t i = 0, total_words = 0;

    while (mnemonic[i]) {
        if (mnemonic[i] == ' ') {
            total_words++;                          // Counting total number of words in mnemonic
        i++;
    }
    total_words++;

    if (total_words != 12 && total_words != 18 && total_words != 24) {
        return 0;                                   // if total number of words is not a multiple of 6 return 0 
    }

    char phrase[10] = {0};
    uint32_t j = 0, k = 0, group = 0, entropy_i = 0;
    i = 0;

    while (mnemonic[i]) {
        j = 0;
        while (mnemonic[i] != ' ' && mnemonic[i] != 0) {
            if (j >= sizeof(phrase) - 1) {
                return 0;
            }
            phrase[j] = mnemonic[i];                // making current phrase from the mnemonic
            i++;
            j++;
        }
        phrase[j] = 0;
        if (mnemonic[i] != 0) {
            i++;
        }
        k = 0;                                      // find if the particular phrase exists in the wordlist or not
        for (;;) {
            if (!wordlist[k]) {                     // phrase not found in the wordlist
                return 0;
            }
            if (strcmp(phrase, wordlist[k]) == 0) {  
                for (group = 0; group < 11; group++) {
                    if (k & (1 << (10 - group))) {     // phrase found on index k in the wordlist
                        entropy_array[entropy_i / 8] |= 1 << (7 - (entropy_i % 8));   // converting the index position into byte array
                    }
                    entropy_i++;
                }
                break;
            }
            k++;
        }
    }

    return total_words*11;                          // Multiply by 11 as the mnemonic is splitted into groups of 11 bits

}


int32_t main()
{
	const char *mnemonic = "garden reject beauty inch scissors rifle amazing couch bacon multiply swim poverty impose spray ugly term stamp prevent nothing mutual awful project wrist movie";
	uint32_t string_length = strlen(mnemonic);
	uint8_t entropy_array[64 + 1] = {0};                     // for 256 bits as mnemonic has 24 phrases
	uint32_t entropy = mnemonic_to_entropy(mnemonic, entropy_array);
        printf("%d\n", entropy);
        for(uint32_t i = 0; i < 64; i++)
        {
            printf("%d ", i, entropy_array[i]);
        }
	
        return 0;	
}
