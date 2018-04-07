#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"

std::string find_ecb(std::vector<std::string> &hexstring_vec) {
    std::string best_string;
    int best_score = 0;
    for (const auto &h : hexstring_vec) {
        int score = 0;
        for (auto i = 0U; i < h.size() - 16; i += 16) {
            std::string first_sixteen = h.substr(i, 16);
            for (auto j = i; j < h.size(); j += 16) {
                std::string second_sixteen = h.substr(j, 16);
                if (first_sixteen == second_sixteen) {
                    ++score;
                }
            }
        }
        if (score > best_score) {
            best_string = h;
            best_score = score;
        }
    }

    return best_string;
}

int main(void) {
    std::ifstream in;
    in.open("8.txt");

    std::string s;
    std::vector<std::string> hexstring_vec;

    while (in >> s) {
        std::string t;
        CryptoPP::StringSource ss1(s, true,
                new CryptoPP::HexDecoder(
                    new CryptoPP::StringSink(t)
                    )
                );
        hexstring_vec.insert(hexstring_vec.end(), t);
    }

    std::string candidate = find_ecb(hexstring_vec);
    std::string encoded_candidate;

    CryptoPP::StringSource ss1(candidate, true,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(encoded_candidate),
                false
                )
            );


    std::cout << "The string that's been ECB encrypted is:\n" << encoded_candidate << "\n";
}
