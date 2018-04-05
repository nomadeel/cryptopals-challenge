#include <algorithm>
#include <fstream>
#include <iostream>
#include <ios>
#include <sstream>
#include <string>
#include <map>
#include <vector>

std::map<char, double> letter_map = { {'a', 0.0651738},
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

double calc_score(const std::string &input, char c) {
    double score = 0;
    for (char i : input) {
        i = tolower(i);
        score += letter_map[i];
    }
    return score;
}

std::string xor_string(int c, std::string &input) {
    std::string buffer {};
    buffer.reserve(input.size());

    for (unsigned int i = 0; i < input.size(); i += 2) {
        int a;
        std::istringstream{input.substr(i, 2)} >> std::hex >> a;
        std::stringstream ss;
        ss << (char) (a ^ c);
        buffer += ss.str();
    }
    
    return buffer;
}

int main(void) {
    std::ifstream in;
    in.open("4.txt");

    std::string s;
    int best_key = 0;
    double best_score = 0;
    std::string best_string;
    std::string best_xor_string;

    std::map<std::string, double> max_map;

    while (in >> s) {
        std::string copy = s;

        for (int i = 0; i < 256; i++) { 
            std::string result_string;
            double result;
            result_string = xor_string(i, s);
            result = calc_score(result_string, i);
            if (result > best_score) {
                best_score = result;
                best_xor_string = result_string;
                best_string = copy;
                best_key = i;
            }
        }
    }

    std::cout << "The hex string that has been encrypted with a single-character XOR is " << best_string
        << " with a decrypted string " << best_xor_string << "using key " << (char) best_key << "\n";
}
