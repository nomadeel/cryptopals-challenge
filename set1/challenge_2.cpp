#include <iostream>
#include <string>
#include <sstream>
#include <ios>

int main(void) {
    std::string buffer {"1c0111001f010100061a024b53535009181c"};

    std::string input {"686974207468652062756c6c277320657965"};

    std::string output {};
    output.reserve(input.size());

    std::string expected {"746865206b696420646f6e277420706c6179"};

    for (auto i = 0U; i < buffer.size(); i += 2) {
        int a, b;
        std::istringstream{buffer.substr(i, 2)} >> std::hex >> a;
        std::istringstream{input.substr(i, 2)} >> std::hex >> b;
        std::stringstream ss;
        ss << std::hex << (a ^ b);
        output += ss.str();
    }

    if (output == expected) {
        std::cout << "matches" << "\n";
    } else {
        std::cout << "no match, output: " << output << "\n";
    }
}
