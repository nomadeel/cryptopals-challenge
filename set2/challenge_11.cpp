#include <fstream>
#include <iostream>
#include <string>
#include <random>

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
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(16);
    prng.GenerateBlock(key, key.size());

    // Initialise a random number generator
    auto seed = std::random_device()();
    std::mt19937 rng(seed);

    std::string working_copy {input};

    // Prepend 5 to 10 random bytes
    unsigned int num_rand = (rng() % 6) + 5;
    for (auto i = 0U; i < num_rand; ++i) {
        char random_char = rng() % 256;
        working_copy.insert(0, 1, random_char);
    }

    // Append 5 to 10 random bytes
    num_rand = (rng() % 6) + 5;
    for (auto i = 0U; i < num_rand; ++i) {
        char random_char = rng() % 256;
        working_copy += random_char;
    }

    bool ecb = (rng() % 2 == 0);
    std::string output;

    if (ecb) {
        output = ecb_encrypt(working_copy, key);
    } else {
        std::string iv = generate_iv();
        output  = cbc_encrypt(working_copy, key, iv);
    }
    
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

int main(void) {
    std::string input {"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"};
    std::vector<int> histogram(2);

    for (auto i = 0U; i < 100; ++i) {
        std::string output = encryption_oracle(input);
        if (check_ecb(output)) {
            ++histogram[0];
        } else {
            ++histogram[1];
        }
    }

    std::cout << "Statistics, ECB: " << histogram[0] << " CBC:" << histogram[1] << "\n";
}
