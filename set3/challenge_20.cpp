#include <string>
#include <algorithm>
#include <vector>
#include <fstream>
#include <utility>
#include <cassert>
#include <numeric>
#include <iostream>

#include "cryptopp/cryptlib.h"
#include "cryptopp/base64.h"
#include "cryptopp/filters.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"
#include "cryptopp/osrng.h"

const unsigned int BLOCK_SIZE = 16;

std::map<char, double> freq_map = { {'a', 0.0651738},
                                      {'b', 0.0124248},
                                      {'c', 0.0217339},
                                      {'d', 0.0349835},
                                      {'e', 0.1041442},
                                      {'f', 0.0197881},
                                      {'g', 0.0158610},
                                      {'h', 0.0492888},
                                      {'i', 0.0558094},
                                      {'j', 0.0009033},
                                      {'k', 0.0050529},
                                      {'l', 0.0331490},
                                      {'m', 0.0202124},
                                      {'n', 0.0564513},
                                      {'o', 0.0596302},
                                      {'p', 0.0137645},
                                      {'q', 0.0008606},
                                      {'r', 0.0497563},
                                      {'s', 0.0515760},
                                      {'t', 0.0729357},
                                      {'u', 0.0225134},
                                      {'v', 0.0082903},
                                      {'w', 0.0171272},
                                      {'x', 0.0013692},
                                      {'y', 0.0145984},
                                      {'z', 0.0007836},
                                      {' ', 0.1918182} };

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

std::pair<std::vector<std::string>, unsigned int> parse_file(void) {
    std::vector<std::string> ciphertext_vector;

    std::ifstream in {"20.txt"};

    std::string s;

    unsigned int smallest_size = 0;

    // Generate the key
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(16);
    // Generate the consistent key and base64 decode the unknown string
    prng.GenerateBlock(key, key.size());

    // Base64 decode each string in the file, encrypt it and put it into the vector
    while (in >> s) {
        std::string decoded_string {""};

        CryptoPP::StringSource ss(s, true,
                new CryptoPP::Base64Decoder(
                    new CryptoPP::StringSink(decoded_string)
                    )
        );

        std::string ciphertext = ctr_cipher(decoded_string, key, 0);

        ciphertext_vector.emplace_back(ciphertext);

        if (smallest_size == 0) {
            smallest_size = ciphertext.length();
        } else if (decoded_string.length() < smallest_size) {
            smallest_size = ciphertext.length();
        }
    }

    return std::make_pair(ciphertext_vector, smallest_size);
}

std::vector<std::string> create_blocks(std::vector<std::string> ciphertext_vector, unsigned int smallest_size) {
    // Create n blocks of text by taking the nth character in each ciphertext
    std::vector<std::string> output_vector(smallest_size, "");

    for (const auto &c : ciphertext_vector) {
        for (auto i = 0U; i < c.length(); ++i) {
            if (i == smallest_size) {
                break;
            }
            output_vector[i].push_back(c[i]);
        }
    }

    return output_vector;
}

double calc_score(const std::string &input, char c) {
    double score = 0;
    for (char i : input) {
        i = tolower(i);
        if (freq_map.find(i) != freq_map.end()) {
            score += freq_map[i];
        } else if (i == '^' || i == '~' || i == '|') {
            score -= 1;
        }
    }
    return score;
}

std::string xor_string(char c, std::string &input) {
    std::string buffer {};
    buffer.reserve(input.size());

    for (char i : input) {
        buffer += (char) (i ^ c);     
    }
    
    return buffer;
}

char solve_xor_cipher(const std::string &input) {
    std::string copy = input;
    double best_score = 0;
    int best_key = 0;

    for (int i = 0; i < 256; i++) { 
        std::string result_string = "";
        double result;
        result_string = xor_string((char) i, copy);
        result = calc_score(result_string, i);
        if (result > best_score) {
            best_score = result;
            best_key = i;
        }
    }

    return (char) best_key;
}

std::string find_repeating_key(std::vector<std::string> &block_vec, int keysize) {
    std::string key {};
    key.reserve(keysize);
    for (auto i = 0U; i < block_vec.size(); i++) {
        key += solve_xor_cipher(block_vec[i]);
    }
    return key;
}

int main(void) {
    auto p = parse_file();
    std::vector<std::string> ciphertext_vector = p.first;
    unsigned int smallest_size = p.second;
    std::vector<std::string> block_vec = create_blocks(ciphertext_vector, smallest_size);
    std::string key = find_repeating_key(block_vec, smallest_size);

    std::cout << "The decryptable parts of the string are:\n";
    for (auto &s : ciphertext_vector) {
        std::cout << xor_strings(key, s) << "\n";
    }
}
