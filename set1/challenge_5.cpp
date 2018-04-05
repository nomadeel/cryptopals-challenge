#include <sstream>
#include <ios>
#include <string>
#include <iostream>
#include <iomanip>

std::string repeating_xor(std::string &input, std::string &key, int &key_pos) {
    std::string output;
    for (char c : input) {
        char b = key[(key_pos++ % 3)];
        std::stringstream ss;
        ss << std::setfill('0') << std::setw(2) << std::hex << (c ^ b);
        output += ss.str();
    }
    
    return output;
}

int main(void) {
    std::string input = {"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"};

    std::string expected = {"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272"
                            "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"};

    std::string key = {"ICE"};

    std::string output;
    std::string output2;
    
    int pos = 0;

    output = repeating_xor(input, key, pos);

    if (output == expected) {
        std::cout << "matches\n";
    } else {
        std::cout << "does not match\n";
    }
}
