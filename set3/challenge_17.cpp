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
#include "cryptopp/base64.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"

CryptoPP::SecByteBlock key(16);
std::string picked_string;

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

    if (last == 0) {
        throw std::runtime_error{"invalid pkcs7 padding"};
    }

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

    std::string decoded_plaintext = "";

    CryptoPP::StringSource ss(plaintext, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(decoded_plaintext)
            )
    );

    picked_string = decoded_plaintext;

    // Generate a random IV
    std::string iv = generate_iv();

    std::string ciphertext = cbc_encrypt(decoded_plaintext, key, iv);

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

std::string padding_oracle_attack(std::string &input, std::string &iv) {
    std::string output = "";
    int num_blocks = input.length() / 16;
    for (int i = num_blocks; i > 0; --i) {
        // Perform the attack
        std::string uncovered_block = "";
        for (auto j = 16; j > 0; --j) {
            std::string working_copy = input.substr(0, i * 16);
            std::string iv_copy = iv.substr(0, 16);
            // Set the correct padding bits
            unsigned char padding_char = (16 - (j - 1));
            for (auto k = uncovered_block.length(); k > 0; --k) {
                if (i > 1) {
                    unsigned int offset = (i - 2) * 16 + (16 - (uncovered_block.length() - k) - 1);
                    working_copy[offset] ^= uncovered_block[(k - 1)] ^ padding_char;
                } else {
                    unsigned int offset = (16 - (uncovered_block.length() - k) - 1);
                    iv_copy[offset] ^= uncovered_block[(k - 1)] ^ padding_char;
                }
            }
            // Brute force all characters until the padding is legitimate
            for (unsigned int c = 0; c < 256; ++c) {
                if (i > 1) {
                    working_copy[(i - 2) * 16 + (j - 1)] = (unsigned char) c;
                } else {
                    iv_copy[j - 1] = (unsigned char) c;
                }
                if (padding_oracle(working_copy, iv_copy)) {
                    char uncovered_char;
                    if (i > 1) {
                        uncovered_char = input[(i - 2) * 16 + (j - 1)] ^ (unsigned char) c ^ padding_char;
                    } else {
                        uncovered_char = iv[j - 1] ^ (unsigned char) c ^ padding_char;
                    }
                    uncovered_block.insert(0, 1, uncovered_char);
                    break;
                }
            }
        }
        output.insert(0, uncovered_block);
    }

    return output;
}

int main (void) {
    auto p = get_random_ciphertext();
    if (padding_oracle(p.first, p.second)) {
        std::cout << "passes\n";
    } else {
        std::cout << "fails\n";
    }

    std::string padded_plaintext = padding_oracle_attack(p.first, p.second);

    try {
        std::string plaintext = pkcs7_padding_validation(padded_plaintext, 16);
        if (plaintext == picked_string) {
            std::cout << "Matches, the deciphered string is:\n" << plaintext << "\n";
        } else {
            std::cout << "Does not match, the original string is:\n" << picked_string << "\nThe deciphered string is:\n"
                << plaintext << "\n";
        }
    } catch (const std::exception &e) {
        std::cout << "Failed to perform padding oracle attack.\n";
    }
}
