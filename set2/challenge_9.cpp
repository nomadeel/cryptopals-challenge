#include <string>
#include <iostream>

std::string pkcs7_pad(std::string &input, unsigned int block_size) {
    std::string copy = input;

    if (block_size <= input.size())
        return copy;

    unsigned int difference = block_size - input.size();
    
    copy.insert(copy.end(), difference, (char) difference);

    return copy;
}

int main(void) {
    std::string input {"YELLOW SUBMARINE"};

    std::string output = pkcs7_pad(input, 20);

    if (output == "YELLOW SUBMARINE\x04\x04\x04\x04") {
        std::cout << "matches\n";
    } else {
        std::cout << "does not match\n";
    }
}
