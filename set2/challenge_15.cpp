#include <string>
#include <iostream>
#include <cassert>

std::string pkcs7_padding_validation(std::string &input, unsigned int block_size) {
    if (input.length() % block_size != 0) {
        throw std::runtime_error{"invalid pkcs7 padding"};
    }
    unsigned int num_blocks = input.length() / block_size;

    // Grab the last block
    std::string last_block = input.substr((num_blocks - 1) * block_size, block_size);

    // Validate the padding
    unsigned char last = last_block[block_size - 1];

    std::string suffix((unsigned int) last, last);

    if (suffix != last_block.substr(block_size - (unsigned int) last, (unsigned int) last)) {
        throw std::runtime_error{"invalid pkcs7 padding"};
    }

    return input.substr(0, input.length() - suffix.length());
}

int main(void) {
    std::string input1 {"YELLOW SUBMARINE"};
    input1.append(16, '\x10');

    std::string input2 {"ICE ICE BABY\x04\x04\x04\x04"};

    std::string input3 {"YELLOW SUBMARINEICE ICE BABY\x04\x04\x04\x04"};

    std::string input4 {"ICE ICE BABY\x01\x02\x03\x04"};

    assert(pkcs7_padding_validation(input1, 16) == "YELLOW SUBMARINE");

    assert(pkcs7_padding_validation(input2, 16) == "ICE ICE BABY");

    assert(pkcs7_padding_validation(input3, 16) == "YELLOW SUBMARINEICE ICE BABY");

    try {
        assert(pkcs7_padding_validation(input4, 16) != "ICE ICE BABY");
    } catch (const std::exception& e) {
        std::cout << "All tests passed.\n";
    }
}
