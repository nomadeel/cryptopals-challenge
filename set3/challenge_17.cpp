#include <iostream>
#include <string>
#include <random>
#include <algorithm>
#include <utility>
#include <cassert>
#include <vector>

#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"

CryptoPP::SecByteBlock key(16);
bool generated_key = false;
const std::vector<std::string> plaintext_vec {
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
};

std::string xor_strings(std::string &a, std::string &b) {
    std::string output;
    output.reserve(a.size());

    for (auto i = 0U; i < a.size(); ++i) {
        output += (a[i] ^ b[i]);
    }

    return output;
}

std::string pkcs7_pad(std::string &input, unsigned int block_size) {
    std::string copy = input;

    unsigned int num_chars = block_size - (input.size() % block_size);
    
    copy.insert(copy.end(), num_chars, (char) num_chars);

    return copy;
}

std::string pkcs7_padding_validation(std::string &input, unsigned int block_size) {
    if (input.length() % block_size != 0) {
        throw std::runtime_error{"invalid pkcs7 padding"};
    }
    unsigned int num_blocks = input.length() / block_size;

    // Grab the last block
    std::string last_block = input.substr((num_blocks - 1) * block_size, block_size);

    // Validate the padding
    unsigned char last = last_block[block_size - 1];

    std::string suffix((unsigned int) last, last);

    if (suffix != last_block.substr(block_size - (unsigned int) last, (unsigned int) last)) {
        throw std::runtime_error{"invalid pkcs7 padding"};
    }

    return input.substr(0, input.length() - suffix.length());
}

std::string generate_iv(void) {
    std::string output;
    output.reserve(16);

    auto seed = std::random_device()();
    std::mt19937 rng(seed);
   
    for (auto i = 0U; i < 16; ++i) {
        output += rng() % 256;
    }

    return output;
}

std::string cbc_encrypt(std::string &input, CryptoPP::byte *key, std::string &iv) {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKey(key, 16);

    unsigned int num_blocks = (input.size() / 16) + (input.size() % 16 != 0);

    std::string prev_block = iv;
    std::string output;

    std::string working_copy = pkcs7_pad(input, 16);

    for (auto i = 0U; i < num_blocks; ++i) {
        std::string curr_block = working_copy.substr(i*16, 16);
        curr_block = xor_strings(curr_block, prev_block);
        CryptoPP::StringSource ss1(curr_block, true,
                new CryptoPP::StreamTransformationFilter(e,
                    new CryptoPP::StringSink(output),
                    CryptoPP::BlockPaddingSchemeDef::NO_PADDING)
        );
        prev_block = output.substr(i*16, 16);
    }

    return output;
}

std::string cbc_decrypt(std::string &input, CryptoPP::byte *key, std::string &iv) {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKey(key, 16);

    unsigned int num_blocks = (input.size() / 16) + (input.size() % 16 != 0);

    std::string prev_block = iv;
    std::string output;
    std::string temp;

    for (auto i = 0U; i < num_blocks; ++i) {
        std::string curr_block = input.substr(i*16, 16);
        CryptoPP::StringSource ss1(curr_block, true,
                new CryptoPP::StreamTransformationFilter(d,
                    new CryptoPP::StringSink(temp),
                    CryptoPP::BlockPaddingSchemeDef::NO_PADDING)
        );
        output += xor_strings(temp, prev_block);
        temp.clear();
        prev_block = input.substr(i*16, 16);
    }

    try {
        return pkcs7_padding_validation(output, 16);
    } catch (const std::exception &e) {
        throw e;
    }
}

std::pair<std::string, std::string> get_random_ciphertext(void) {
    if (generated_key) {
        CryptoPP::AutoSeededRandomPool prng;
        // Generate the consistent key and base64 decode the unknown string
        prng.GenerateBlock(key, key.size());
        generated_key = true;
    }

    // Pick a random string out of the 10 strings
    auto seed = std::random_device()();
    std::mt19937 rng(seed);
    std::string plaintext = plaintext_vec[rng() % plaintext_vec.size()];

    // Generate a random IV
    std::string iv = generate_iv();

    std::string ciphertext = cbc_encrypt(plaintext, key, iv);

    return std::make_pair(ciphertext, iv);
}

bool padding_oracle(std::string &input, std::string &iv) {
    std::string plaintext;
    try {
        plaintext = cbc_decrypt(input, key, iv);
        return true; 
    } catch (const std::exception &e) {
        return false;
    }
}

int main (void) {
    auto p = get_random_ciphertext();
    if (padding_oracle(p.first, p.second)) {
        std::cout << "passes\n";
    } else {
        std::cout << "fails\n";
    }
}
