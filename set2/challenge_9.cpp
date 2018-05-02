#include <string>
#include <iostream>

std::string pkcs7_pad(std::string &input, unsigned int block_size) {
    std::string copy = input;

    unsigned int num_chars = block_size - (input.size() % block_size);
    
    copy.insert(copy.end(), num_chars, (char) num_chars);

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

    std::string output2 = pkcs7_pad(input, 16);

    if (output2 == "YELLOW SUBMARINE"
                  "\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10") {
        std::cout << "matches\n";
    } else {
        std::cout << "does not match\n";
    }
}
