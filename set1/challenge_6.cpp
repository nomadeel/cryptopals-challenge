#include <vector>
#include <string>
#include <iostream>
#include <ios>
#include <sstream>
#include <fstream>
#include <map>

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

std::string base64_decode(std::string &input) {
    const std::string base64 {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};
    std::string result;
    result.reserve(input.size() / 4 * 3);
    char temp[4];
    std::stringstream ss;

    for (auto i = 0U; i < input.size(); i += 4) {
        temp[0] = (base64.find(input[i]) != std::string::npos) ? base64.find(input[i]) : 0;
        temp[1] = (base64.find(input[i+1]) != std::string::npos) ? base64.find(input[i+1]) : 0;
        temp[2] = (base64.find(input[i+2]) != std::string::npos) ? base64.find(input[i+2]) : 0;
        temp[3] = (base64.find(input[i+3]) != std::string::npos) ? base64.find(input[i+3]) : 0;
        result += (char) (temp[0] << 2 | temp[1] >> 4);
        result += (char) (temp[1] << 4 | temp[2] >> 2);
        result += (char) (temp[2] << 6 | temp[3]);
    }

    return result;
}

int calc_hamming(const std::string &a, const std::string &b) {
    int distance = 0;
    for (auto i = 0U; i < a.size(); ++i) {
        char mask = 1;
        for (auto j = 0U; j < 8; ++j) {
            if ((a[i] & mask) != (b[i] & mask)) {
                ++distance;
            }
            mask <<= 1;
        }
    }
    return distance;
}

int find_keysize(const std::string &input) {
    int best_keysize = 0;
    double best_normalised = 0;
    bool first = true;
    for (int i = 2; i <= 40; ++i) {
        int hamming_distance = 0;
        // Take averages of 10 trials
        for (int j = 0; j < 10; ++j) {
            hamming_distance += calc_hamming(input.substr(j * i, i), input.substr((j + 1) * i, i));
        }
        double normalised = (double) hamming_distance / 10.0 / (double) i;
        if (first) {
            best_normalised = normalised;
            best_keysize = i;
            first = false;
        } else if (normalised < best_normalised) {
            best_normalised = normalised;
            best_keysize = i;
        }
    }
    return best_keysize;
}

double calc_score(const std::string &input, char c) {
    double score = 0;
    for (char i : input) {
        i = tolower(i);
        score += freq_map[i];
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
        std::string result_string;
        double result;
        result_string = xor_string(i, copy);
        result = calc_score(result_string, i);
        if (result > best_score) {
            best_score = result;
            best_key = i;
        }
    }

    return (char) best_key;
}

std::string find_key(const std::string &input, int keysize) {
    std::vector<std::string> block_vec(keysize);
    // Reserve memory
    for (auto i = 0; i < keysize; ++i) {
        block_vec[i].reserve((input.size() / keysize) + (input.size() % keysize != 0));
    }
    // Get each byte and put it into the corresponding block
    for (auto i = 0U; i < input.size(); ++i) {
        block_vec[i % keysize] += input[i];
    }
    std::string key {};
    key.reserve(keysize);
    for (auto i = 0U; i < block_vec.size(); i++) {
        key += solve_xor_cipher(block_vec[i]);
    }
    return key;
}

std::string repeating_xor(std::string &input, std::string &key) {
    std::string output;
    int key_pos = 0;
    for (char c : input) {
        char b = key[(key_pos++ % key.size())];
        std::stringstream ss;
        ss << (char) (c ^ b);
        output += ss.str();
    }
    
    return output;
}

int main(void) {
    std::ifstream in;
    in.open("6.txt");

    std::string input;
    
    std::string s;

    while (in >> s) {
        input += s;
    }

    std::string hex_string = base64_decode(input);

    int keysize = find_keysize(hex_string);
    
    std::cout << keysize << "\n";

    std::string key = find_key(hex_string, keysize);

    std::string deciphered_string = repeating_xor(hex_string, key);

    std::cout << key << "\n";

    std::cout << "The deciphered string is: " << deciphered_string << "\n";
}
