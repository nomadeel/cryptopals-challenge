#include <iostream>
#include <string>
#include <cassert>
#include <vector>
#include <map>
#include <algorithm>

#include "cryptopp/cryptlib.h"
#include "cryptopp/base64.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"

#define TEST 0

CryptoPP::SecByteBlock key(16);
bool generated_key = false;
std::string unknown_string;

std::string pkcs7_pad(std::string &input, unsigned int block_size) {
    std::string copy = input;

    if (block_size <= input.size())
        return copy;

    unsigned int difference = block_size - input.size();
    
    copy.insert(copy.end(), difference, (char) difference);

    return copy;
}

std::string ecb_encrypt(std::string &input, CryptoPP::byte *key) {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKey(key, 16);

    unsigned int num_blocks = (input.size() / 16) + (input.size() % 16 != 0);

    std::string output;

    for (auto i = 0U; i < num_blocks; ++i) {
        std::string curr_block = input.substr(i*16, 16);
        if (curr_block.size() != 16) {
            curr_block = pkcs7_pad(curr_block, 16);
        }
        CryptoPP::StringSource ss1(curr_block, true,
                new CryptoPP::StreamTransformationFilter(e,
                    new CryptoPP::StringSink(output),
                    CryptoPP::BlockPaddingSchemeDef::NO_PADDING)
        );
    }

    return output;
}

// Only works for correct input
std::map<std::string, std::string> parse_encoded_profile(std::string &input) {
    std::map<std::string, std::string> output_map;
    std::vector<std::string> splitted_input(3);
    for (auto i = 0U; i < 2; ++i) {
        // Find the ampersand
        auto n = input.find('&');
        splitted_input[i] = input.substr(0, n);
        input = input.substr(n+1);
    }
    splitted_input[2] = input;
    // Split the strings out into key value pairs
    for (const auto &s : splitted_input) {
        auto n = s.find('=');
        std::string key = s.substr(0, n);
        std::string value = s.substr(n+1);
        output_map.emplace(std::make_pair(key, value));
    }

    return output_map;
}

std::string profile_for(std::string input) {
    // Sanitize the input
    input.erase(std::remove_if(input.begin(), input.end(), [] (auto c) { return c == '=' || c == '&'; }), input.end());

    return "email=" + input + "&uid=10&role=user";
}

std::string encrypt_encoded_profile(std::string &input) {
    if (!generated_key) {
        CryptoPP::AutoSeededRandomPool prng;
        // Generate a key
        prng.GenerateBlock(key, key.size());
        generated_key = true;
    }

    return ecb_encrypt(input, key);
}

std::map<std::string, std::string> decrypt_encoded_profile(std::string &input) {
    if (!generated_key) {
        CryptoPP::AutoSeededRandomPool prng;
        // Generate a key
        prng.GenerateBlock(key, key.size());
        generated_key = true;
    }

    std::string output;

    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKey(key, 16);

    CryptoPP::StringSource ss2(input, true,
        new CryptoPP::StreamTransformationFilter(d,
            new CryptoPP::StringSink(output)
        )
    );

    return parse_encoded_profile(output);
}

int main(void) {
#if TEST
    std::string input {"foo=bar&baz=qux&zap=zazzle"};
    auto map = parse_encoded_profile(input);

    for (const auto &m : map) {
        std::cout << m.first << ": " << m.second << "\n";
    }

    std::cout << profile_for("foo@bar.com") << "\n";
    std::cout << profile_for("foo@bar.com&role=admin") << "\n";
#endif

    std::string crafted_email {"aaaaaaaaaaadmin"};
    crafted_email.append(11, '\x0b');
    std::string profile_string_1 = profile_for(crafted_email);
    std::string encrypted_profile_1 = encrypt_encoded_profile(profile_string_1);
    assert(encrypted_profile_1.length() == 64);

    std::string profile_string_2 = profile_for("aaaaaaaaaaaaa");
    std::string encrypted_profile_2 = encrypt_encoded_profile(profile_string_2);
    assert(encrypted_profile_2.length() == 48);

    std::string crafted_profile = encrypted_profile_2.substr(0, 32) + encrypted_profile_1.substr(16, 16);

    for (const auto &m : decrypt_encoded_profile(crafted_profile)) {
        std::cout << m.first << ": " << m.second << "\n";
    }
}
