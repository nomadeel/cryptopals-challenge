#include <string>
#include <iostream>
#include <sstream>
#include <ios>

const std::string base64 {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"};

std::string hex_to_base64(std::string &input) {
    std::string output {};
    output.reserve(input.size() / 3 * 2);

    auto i = 0U;
    for (; i < input.size(); i += 3) {
        uint32_t n {0};
        std::istringstream{input.substr(i, 3)} >> std::hex >> n;
        char c;
        c = base64[(n >> 6) & (0x3F)];
        output.push_back(c);
        c = base64[n & (0x3F)];
        output.push_back(c);
    }

    output.insert(output.cend(), input.size() % 3, '=');

    return output;
}

int main(int argc, char *argv[]) {
    std::string s {"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"};

    std::string base64_s {"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"};

    std::string converted_s = hex_to_base64(s);

    if (base64_s == converted_s) {
        std::cout << "Matches" << "\n";
    } else {
        std::cout << "No match, result: " << converted_s << "\n";
    }

    return 0;
}
