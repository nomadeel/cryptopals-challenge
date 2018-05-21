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

    return pkcs7_strip(output);
}

void test_cbc(void) {
    std::string plaintext {"YELLOW SUBMARINE WHITE SUBMARINE"};

    CryptoPP::byte key[16] = {'Y','E','L','L','O','W', ' ', 'S', 'U', 'B', 'M', 'A', 'R', 'I', 'N', 'E'};
    std::string iv(16, '\0');

    std::string ciphertext;
    ciphertext.reserve(32);

    std::string deciphered_ciphertext;
    deciphered_ciphertext.reserve(32);

    ciphertext = cbc_encrypt(plaintext, key, iv);

    deciphered_ciphertext = cbc_decrypt(ciphertext, key, iv);

    if (plaintext == deciphered_ciphertext) {
        std::cout << "matches\n";
    } else {
        std::cout << "does not match\n";
        std::cout << "deciphered ciphertext is:\n" << deciphered_ciphertext << "\n";
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
            plaintext += cbc_decrypt(current_block, key, iv);
        } else {
            std::string previous_block = hexstring.substr(i-16, 16);
            plaintext += cbc_decrypt(current_block, key, previous_block);
        }
    }

    std::cout << "The deciphered text is:\n" << plaintext << "\n";
}
