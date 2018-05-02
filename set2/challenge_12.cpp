#include <fstream>
#include <iostream>
#include <string>
#include <cassert>

#include "cryptopp/cryptlib.h"
#include "cryptopp/base64.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"

CryptoPP::SecByteBlock key(16);
bool generated_key = false;
std::string unknown_string;

std::string decode_unknown_string(void) {
    std::ifstream in;    
    in.open("12.txt");

    std::string s;

    std::string input;

    while (in >> s) {
        input += s;
    }

    std::string hexstring;

    CryptoPP::StringSource ss(input, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(hexstring)
            )
    );

    return hexstring;
}

std::string pkcs7_pad(std::string &input, unsigned int block_size) {
    std::string copy = input;

    unsigned int num_chars = block_size - (input.size() % block_size);
    
    copy.insert(copy.end(), num_chars, (char) num_chars);

    return copy;
}

std::string ecb_encrypt(std::string &input, CryptoPP::byte *key) {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKey(key, 16);

    std::string output;

    std::string working_copy = pkcs7_pad(input, 16);

    CryptoPP::StringSource ss1(working_copy, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(output))
    );

    return output;
}

std::string encryption_oracle(std::string &input) {
    if (!generated_key) {
        CryptoPP::AutoSeededRandomPool prng;
        // Generate the consistent key and base64 decode the unknown string
        prng.GenerateBlock(key, key.size());
        unknown_string = decode_unknown_string();
        generated_key = true;
    }

    std::string working_copy {(input + unknown_string)};

    std::string output;

    output = ecb_encrypt(working_copy, key);

    return output;
}

bool check_ecb(std::string &input) {
    unsigned int size = input.size();
    for (auto i = 0; i < size; ++i) {
        for (auto j = i; j <= (size - 32); j += 16) {
            for (auto k = j+16; k <= (size - 16); k += 16) {
                if (input.compare(j, 16, input, k, 16) == 0) {
                    return true;
                }
            }
        }
    }
    return false;
}

unsigned int find_block_size(void) {
    // Start off with one 'A'
    std::string input {"A"};
    std::string ciphertext = encryption_oracle(input);
    unsigned int len = ciphertext.length();
    while (true) {
        // Append an "A" and encrypt again
        input += "A";
        ciphertext = encryption_oracle(input);
        // Check if we generated another block ontop of the original
        if (ciphertext.length() > len) {
            // Difference is the size of a single block
            return ciphertext.length() - len;
        }
    }
}

std::string decrypt_unknown_string(unsigned int block_size) {
    std::string decrypted_string {""};
    unsigned int curr_block = 0;
    
    for (auto i = 0U; i < unknown_string.length(); ++i) {
        if ((i / block_size) != curr_block) {
            ++curr_block;
        }
        unsigned int num_chars = block_size - (i % block_size) - 1; 
        // Obtain the encrypted block we want to decrypt
        std::string crafted_input(num_chars, 'A');
        std::string encrypted_string = encryption_oracle(crafted_input);
        std::string block_to_compare = encrypted_string.substr((curr_block * block_size), block_size);
        // Craft the prefix string
        unsigned int prefix_string_len = (block_size - 1) - (i % block_size);
        std::string prefix_string {""};
        if (curr_block == 0) {
            prefix_string.append(prefix_string_len, 'A');
            // Append bits of the decrypted string if we need to pad, i.e. prefix_string isn't block_size - 1 bytes long
            if (prefix_string_len < (block_size - 1)) {
                prefix_string += decrypted_string.substr(curr_block * block_size, block_size - 1 - prefix_string_len);
            }
        } else {
            // We have enough decrypted characters to make our own prefix string
            prefix_string = decrypted_string.substr(i - (block_size - 1), block_size - 1);
        }
        // Brute force the last char
        for (unsigned char j = 0; j < 256; ++j) {
            std::string curr_input = prefix_string;
            curr_input += j;
            std::string curr_output = encryption_oracle(curr_input).substr(0, block_size);
            if (block_to_compare == curr_output) {
                decrypted_string += j;
                break;
            }
        }
    }

    return decrypted_string;
}

int main(void) {
    unsigned int block_size = find_block_size();

    std::string crafted_input(64, 'A');
    std::string random_ciphertext = encryption_oracle(crafted_input);
    bool is_ecb = check_ecb(random_ciphertext);
    assert(is_ecb);

    std::string decrypted_string = decrypt_unknown_string(block_size);

    std::cout << "The decrypted string is:\n";

    std::cout << decrypted_string << "\n";
}
