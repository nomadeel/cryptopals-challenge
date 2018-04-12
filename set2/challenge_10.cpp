#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "cryptopp/cryptlib.h"
#include "cryptopp/base64.h"
#include "cryptopp/hex.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"

#define TEST_CBC 0

std::string xor_strings(std::string &a, std::string &b) {
    std::string output;
    output.reserve(a.size());

    for (auto i = 0U; i < a.size(); ++i) {
        output += (a[i] ^ b[i]);
    }

    return output;
}

std::string cbc_encrypt_block(std::string &input, CryptoPP::byte *key, std::string &previous_block) {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption e;
    e.SetKey(key, 16);

    std::string xored_input = xor_strings(input, previous_block);

    std::string output;

    CryptoPP::StringSource ss1(xored_input, true,
            new CryptoPP::StreamTransformationFilter(e,
                new CryptoPP::StringSink(output),
                CryptoPP::BlockPaddingSchemeDef::NO_PADDING)
    );

    std::cout << output.size() << "\n";

    return output;
}

std::string cbc_decrypt_block(std::string &input, CryptoPP::byte *key, std::string &previous_block) {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption d;
    d.SetKey(key, 16);

    std::string output;

    CryptoPP::StringSource ss1(input, true,
            new CryptoPP::StreamTransformationFilter(d,
                new CryptoPP::StringSink(output),
                CryptoPP::BlockPaddingSchemeDef::NO_PADDING)
    );

    std::string xored_output = xor_strings(output, previous_block);

    return xored_output;
}

void test_cbc(void) {
    std::string plaintext {"YELLOW SUBMARINE WHITE SUBMARINE"};

    CryptoPP::byte key[16] = {'Y','E','L','L','O','W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    std::string iv(16, '\0');

    std::string ciphertext;
    ciphertext.reserve(32);

    std::string deciphered_ciphertext;
    deciphered_ciphertext.reserve(32);

    for (auto i = 0U; i < 32; i += 16) {
        std::string current_block = plaintext.substr(i, 16);
        if (i == 0) {
            ciphertext += cbc_encrypt_block(current_block, key, iv);
        } else {
            std::string previous_block = ciphertext.substr(i-16, 16);
            ciphertext += cbc_encrypt_block(current_block, key, previous_block);
        }
    }


    for (auto i = 0U; i < 32; i += 16) {
        std::string current_block = ciphertext.substr(i, 16);
        if (i == 0) {
            deciphered_ciphertext = cbc_decrypt_block(current_block, key, iv);
        } else {
            std::string previous_block = ciphertext.substr(i-16, 16);
            deciphered_ciphertext += cbc_decrypt_block(current_block, key, previous_block);
        }
    }

    if (plaintext == deciphered_ciphertext) {
        std::cout << "matches\n";
    } else {
        std::cout << "does not match\n";
    }
}

int main(void) {
#if TEST_CBC
    test_cbc();
#endif
    std::ifstream in;    
    in.open("10.txt");

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

    CryptoPP::byte key[16] = {'Y','E','L','L','O','W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    std::string iv(16, '\0');

    std::string plaintext;

    for (auto i = 0U; i < hexstring.size(); i += 16) {
        std::string current_block = hexstring.substr(i, 16);
        if (i == 0) {
            plaintext += cbc_decrypt_block(current_block, key, iv);
        } else {
            std::string previous_block = hexstring.substr(i-16, 16);
            plaintext += cbc_decrypt_block(current_block, key, previous_block);
        }
    }

    std::cout << "The deciphered text is:\n" << plaintext << "\n";
}
