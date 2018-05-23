#include <iostream>
#include <string>
#include <random>
#include <algorithm>
#include <utility>
#include <cassert>

#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"

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

std::string cbc_encrypt_modified(std::string &input, std::string &iv) {
    CryptoPP::byte key[16];
    std::copy(iv.begin(), iv.end(), key);
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKey(key, 16);

    std::string prev_block = iv;
    std::string output;

    std::string working_copy = pkcs7_pad(input, 16);
    
    unsigned int num_blocks = working_copy.length() / 16;

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

std::string cbc_decrypt_modified(std::string &input, std::string &iv, bool strip_padding) {
    CryptoPP::byte key[16];
    std::copy(iv.begin(), iv.end(), key);
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

    if (strip_padding) {
        return pkcs7_strip(output);
    } else {
        return output;
    }
}

std::pair<bool, std::string> check_ascii_compliance(std::string &input, std::string &iv) {
    // Decrypt the ciphertext
    std::string deciphered_ciphertext = cbc_decrypt_modified(input, iv, false);

    // Check if the plaintext has bad ASCII values
    for (unsigned char c : deciphered_ciphertext) {
        if (c > 126) {
            return std::make_pair(false, deciphered_ciphertext);
        }
    }

    return std::make_pair(true, deciphered_ciphertext);
}

std::string recover_key(std::string &input) {
    std::string first_block = input.substr(0, 16);
    std::string third_block = input.substr(32, 16);
    assert(first_block.length() == 16 && third_block.length() == 16);
    std::string key = xor_strings(first_block, third_block);
    return key;
}

int main(void) {
    std::string input(47, 'a');

    std::string iv = generate_iv();

    std::string ciphertext = cbc_encrypt_modified(input, iv);

    std::string null_string(16, '\x00');

    std::string modified_ciphertext = ciphertext.substr(0, 16) + null_string + ciphertext.substr(0, 16);

    auto p = check_ascii_compliance(modified_ciphertext, iv);

    std::string key = recover_key(p.second);

    if (input == cbc_decrypt_modified(ciphertext, key, true)) {
        std::cout << "Sucessfully recovered key\n";
    } else {
        std::cout << "Failed to recover key\n";
    }
}
