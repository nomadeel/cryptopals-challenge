#include <iostream>
#include <string>
#include <random>
#include <algorithm>
#include <cassert>
#include <fstream>

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

std::string decrypt_ecb_string(void) {
    CryptoPP::byte key[16] = {'Y','E','L','L','O','W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKey(key, 16);

    std::string hexstring, s;
    std::string input;

    std::ifstream in;
    in.open("25.txt");

    while (in >> s) {
        input += s;
    }

    CryptoPP::StringSource ss1(input, true,
            new CryptoPP::Base64Decoder(
                new CryptoPP::StringSink(hexstring)
            )
    );

    std::string deciphered;

    CryptoPP::StringSource ss2(hexstring, true,
        new CryptoPP::StreamTransformationFilter(d,
            new CryptoPP::StringSink(deciphered)
        )
    );

    return deciphered;
}

std::string setup_exercise(std::string &input) {
    // Generate the key and nonce
    if (!generated_key) {
        auto seed = std::random_device()();
        std::mt19937_64 rng(seed);
        nonce = rng();    
        CryptoPP::AutoSeededRandomPool prng;
        prng.GenerateBlock(key, key.size());
        generated_key = true;
    }

    return ctr_cipher(input, key, nonce);
}

std::string edit(std::string &ciphertext, unsigned int offset, unsigned char new_character) {
    std::string deciphered = ctr_cipher(ciphertext, key, nonce);
    // Modify the 'offset' character with new_character
    deciphered[offset] = new_character;
    // Encrypt again
    return ctr_cipher(deciphered, key, nonce);
}

std::string crack_random_access_ctr(std::string &input) {
    std::string recovered_characters;
    for (auto i = 0U; i < input.length(); ++i) {
        for (unsigned int j = 0; j < 256; ++j) {
            if (input == edit(input, i, j)) {
                if ((i + 1) % 10 == 0) {
                    std::cout << "Found the " << i + 1 << "'th character!\n";
                }
                recovered_characters += (unsigned char) j;
                break;
            }
        }
    }
    return recovered_characters;
}

int main(void) {
    std::string input_string = decrypt_ecb_string();
    std::string encrypted_string = setup_exercise(input_string);
    std::string recovered_string = crack_random_access_ctr(encrypted_string);

    if (input_string == recovered_string) {
        std::cout << "Was able to recover the plaintext, the plaintext is:\n" << recovered_string << "\n";
    } else {
        std::cout << "Failed to recover the plaintext\n";
    }
}
