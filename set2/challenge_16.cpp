#include <iostream>
#include <string>
#include <random>
#include <algorithm>
#include <cassert>

#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"

std::string iv;
CryptoPP::SecByteBlock key(16);
bool generated_key = false;

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

std::string pkcs7_pad(std::string &input, unsigned int block_size) {
    std::string copy = input;

    unsigned int num_chars = block_size - (input.size() % block_size);
    
    copy.insert(copy.end(), num_chars, (char) num_chars);

    return copy;
}

std::string pkcs7_strip(std::string &input) {
    unsigned char last = input[input.length() - 1];
    return input.substr(0, input.length() - (unsigned int) last);
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

    return pkcs7_strip(output);
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

    // Generate the one off key and IV
    if (!generated_key) {
        CryptoPP::AutoSeededRandomPool prng;
        // Generate the consistent key and base64 decode the unknown string
        prng.GenerateBlock(key, key.size());
        iv = generate_iv();
        generated_key = true;
    }

    return cbc_encrypt(prepared_input, key, iv);
}

bool check_admin(std::string &input) {
    assert(generated_key);
    // Decrypt the string
    std::string decrypted_string = cbc_decrypt(input, key, iv);

    // Check if the string ";admin=true;" is located in the decrypted string
    return (decrypted_string.find(";admin=true;") != std::string::npos);
}

std::string cbc_bitflip(std::string &crafted_input) {
    // Prefix takes up first two blocks
    unsigned int offset = 32;
    std::string ciphertext = account_oracle(crafted_input);
    // Modify the first byte of the ciphertext to give us ';'
    ciphertext[offset + 0] ^= crafted_input[0] ^ ';';
    // Modify the seventh byte to give us '='
    ciphertext[offset + 6] ^= crafted_input[6] ^ '=';
    // Modify the twelveth byte to give us ';'
    ciphertext[offset + 11] ^= crafted_input[11] ^ ';';

    return ciphertext;
}

int main (void) {
    std::string input {"aaaaaaaaaaaaaaaaaadminatruea"};
    std::string modified_ciphertext = cbc_bitflip(input);
    if (check_admin(modified_ciphertext)) {
        std::cout << "successfully cracked\n";
    } else {
        std::cout << "failed\n";
    }
}
