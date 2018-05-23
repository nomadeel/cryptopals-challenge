#include <iostream>
#include <string>
#include <random>
#include <cassert>
#include <algorithm>
#include <openssl/sha.h>

#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/sha.h"
#include "cryptopp/hex.h"

std::string key;

bool validate_mac(std::string &input, std::string &key, std::string &mac) {
    std::string key_prefixed_message = key + input;
    std::string hash;

    CryptoPP::SHA1 sha1;
    CryptoPP::StringSource ss1(key_prefixed_message, true,
            new CryptoPP::HashFilter(sha1,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(hash)
                )
            )
    );

    return (mac == hash) ? true : false;
}

std::string md_pad(std::string &input) {
    if (input.length() % 64 == 0) {
        return input;
    }

    unsigned int num_full_blocks = input.length() / 64;
    unsigned int remaining_bytes = input.length() - (num_full_blocks * 64);

    std::string last_block = input.substr(num_full_blocks * 64, remaining_bytes);

    unsigned int num_zeroes = ((64 - (((last_block.length() + 1 + 8) % 64))) % 64);

    // Append a character that has a '1' in the MSB
    last_block += '\x80';

    // Append the zeroes
    last_block.append(num_zeroes, '\x00');

    unsigned long long length = remaining_bytes * 8;

    // Append the size of the message, THIS ONLY WORKS ON LITTLE ENDIAN MACHINES
    std::string length_string = "";
    length_string.append(reinterpret_cast<char*>(&length), sizeof(length));
    std::reverse(length_string.begin(), length_string.end());
    last_block += length_string;

    std::string output = input.substr(0, num_full_blocks * 64) + last_block;

    return output;
}

void generate_key(std::string &input) {
    auto seed = std::random_device()();
    std::mt19937 rng(seed);
    
    key = input.substr(0, (rng() % input.length()));
}

std::string sha1_hash(std::string &input, std::string &key) {
    std::string key_mac;

    CryptoPP::SHA1 sha1;
    CryptoPP::StringSource ss1(key + input, true,
            new CryptoPP::HashFilter(sha1,
                new CryptoPP::HexEncoder(
                    new CryptoPP::StringSink(key_mac)
                )
            )
    );

    return key_mac;
}

void sha1_length_extension_attack(std::string &mac, std::string &message, std::string &extension) {

}

int main(void) {
    std::string original_message {"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"};
    generate_key(original_message);
    std::string message_mac = sha1_hash(original_message, key);
    std::string extension = ";admin=true";
    sha1_length_extension_attack(message_mac, original_message, extension);
}
