#include <iostream>
#include <string>
#include <random>
#include <algorithm>
#include <cassert>

#include "cryptopp/cryptlib.h"
#include "cryptopp/base64.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"

const unsigned int BLOCK_SIZE = 16;

bool generated_key = false;
unsigned long long nonce;
CryptoPP::SecByteBlock key(16);

const std::string prefix {"comment1=cooking%20MCs;userdata="};
const std::string suffix {";comment2=%20like%20a%20pound%20of%20bacon"};

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

std::string sanitise_input(std::string &input) {
    std::string output = input;

    // Replace all ';' with '%3B'
    while (true) {
        auto pos = output.find(';');
        if (pos == std::string::npos) {
            break;
        }
        output.replace(pos, 1, "%3B");
    }

    // Replace all '=' with '%3D'
    while (true) {
        auto pos = output.find('=');
        if (pos == std::string::npos) {
            break;
        }
        output.replace(pos, 1, "%3D");
    }

    return output;
}

std::string account_oracle(std::string &input) {
    std::string sanitised_input = sanitise_input(input);
    std::string prepared_input = {(prefix + input + suffix)};

    // Generate the key and nonce
    if (!generated_key) {
        auto seed = std::random_device()();
        std::mt19937_64 rng(seed);
        nonce = rng();    
        CryptoPP::AutoSeededRandomPool prng;
        prng.GenerateBlock(key, key.size());
        generated_key = true;
    }

    return ctr_cipher(prepared_input, key, nonce);
}

bool check_admin(std::string &input) {
    assert(generated_key);
    // Decrypt the string
    std::string decrypted_string = ctr_cipher(input, key, nonce);

    // Check if the string ";admin=true;" is located in the decrypted string
    return (decrypted_string.find(";admin=true;") != std::string::npos);
}

std::string ctr_bitflip(std::string &crafted_input) {
    // Prefix takes up first two blocks
    unsigned int offset = 32;
    std::string ciphertext = account_oracle(crafted_input);
    // Modify the first byte of the ciphertext to give us ';'
    ciphertext[offset + 0] ^= crafted_input[0] ^ ';';
    // Modify the seventh byte to give us '='
    ciphertext[offset + 6] ^= crafted_input[6] ^ '=';

    return ciphertext;
}

int main(void) {
    std::string input {"aadminatrue"};
    std::string modified_ciphertext = ctr_bitflip(input);
    if (check_admin(modified_ciphertext)) {
        std::cout << "successfully cracked\n";
    } else {
        std::cout << "failed\n";
    }
}
