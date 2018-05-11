#include <iostream>
#include <string>
#include <random>
#include <algorithm>

#include "cryptopp/cryptlib.h"
#include "cryptopp/base64.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"

const unsigned int BLOCK_SIZE = 16;

std::string xor_strings(std::string &a, std::string &b) {
    std::string output;
    output.reserve(a.size());

    for (auto i = 0U; i < a.size(); ++i) {
        output += (a[i] ^ b[i]);
    }

    return output;
}

std::string ctr_cipher(std::string &input, CryptoPP::byte *key, unsigned long long nonce) {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKey(key, 16);

    unsigned long long counter = 0;
    unsigned int num_blocks = (input.size() / BLOCK_SIZE) + (input.size() % BLOCK_SIZE != 0);
    std::string keystream;
    std::string output;

    for (auto i = 0U; i < num_blocks; ++i) {
        std::string curr_block = input.substr(i*BLOCK_SIZE, BLOCK_SIZE);
        // Build the strings to be encrypted
        std::string input_stream (reinterpret_cast<char *>(&nonce), sizeof nonce);
        input_stream.append(reinterpret_cast<char *>(&counter), sizeof counter);
        CryptoPP::StringSource ss1(input_stream, true,
                new CryptoPP::StreamTransformationFilter(e,
                    new CryptoPP::StringSink(keystream),
                    CryptoPP::BlockPaddingSchemeDef::NO_PADDING)
        );
        output += xor_strings(curr_block, keystream);
        // Clear the keystream string and advance the counter
        keystream.clear();
        ++counter;
    }

    return output;
}

int main(void) {
    std::string ciphertext {"L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="};
    CryptoPP::byte key[16] = {'Y','E','L','L','O','W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    std::string decoded_ciphertext;

    CryptoPP::StringSource ss(ciphertext, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decoded_ciphertext)
            )
    );


    std::string plaintext = ctr_cipher(decoded_ciphertext, key, 0);

    std::cout << "The deciphered text is:\n" << plaintext << "\n";
}
