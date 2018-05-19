#include <iostream>
#include <random>
#include <ctime>
#include <cassert>

#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"

#include "mersenne_twister.h"

#define TEST 0

const auto TIME_DELTA = 100;

std::uint16_t original_key;

std::string mt_cipher(std::string &input, std::uint16_t key, unsigned int skip_steps) {
    MT::MersenneTwister mt(key);

    for (auto i = 0U; i < skip_steps; ++i) {
        mt();
    }

    std::string output;

    for (const auto c : input) {
        output += c ^ mt();
    }

    return output;
}

std::string generate_random_prefix(void) {
    // Initialise a random number generator
    auto seed = std::random_device()();
    std::mt19937 rng(seed);

    std::string output;
    
    // Generate random noise
    auto num_noise = rng() % 50;
    for (auto i = 0U; i < num_noise; ++i) {
        output += rng() % 256;
    }
    return output;
}

std::string mt_encryption_oracle(std::string &input) {
    // Generate some noise
    std::string noise = generate_random_prefix();

    // Prefix the input with noise
    std::string encryption_input = noise + input;

    // Generate a random 16 bit key
    auto seed = std::random_device()();
    std::mt19937 rng(seed);
    auto temp = rng();
    std::uint16_t key = ((temp >> 16) ^ (temp & 0xFFFF) & 0xFFFF);
    original_key = key;

    return mt_cipher(encryption_input, key, 0);
}

std::string generate_random_token(std::time_t seed) {
    // Get the current time if a seed wasn't provided
    std::time_t curr_time = (seed == 0) ? std::time(nullptr) : seed;

    MT::MersenneTwister mt(curr_time);

    std::string output;

    // Generate random characters
    for (auto i = 0; i < 16; ++i) {
        unsigned char c = mt() % 256;
        output += c;
    }

    return output;
}

void check_random_token(std::string &token) {
    // Get the current time 
    std::time_t curr_time = std::time(nullptr);

    std::time_t lower_bound = curr_time - TIME_DELTA;

    std::time_t upper_bound = curr_time + TIME_DELTA;

    for (auto i = lower_bound; i < upper_bound; ++i) {
        if (token == generate_random_token(i)) {
            std::cout << "Token is generated using a MT PRNG, the seed used is: " << i << "\n";
            break;
        }
    }
}

#if TEST
void test(void) {
    std::cout << "Testing if the mersenne twister cipher works...\n";

    std::string plaintext = "hello world";

    std::string ciphertext = mt_cipher(plaintext, 42, 0);

    std::string pretty_output;

    CryptoPP::StringSource ss1(ciphertext, true,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(pretty_output),
                false // lowercase printing
            )
    );

    std::cout << "Encrypting 'hello world', result: " << pretty_output << "\n";

    assert(plaintext == mt_cipher(ciphertext, 42, 0));

    std::cout << "Works!\n";
}
#endif

void crack_mt_encryption(std::string &ciphertext, std::string &input, unsigned input_size) {
    auto noise_size = ciphertext.length() - input_size;
    // Get our the corresponding input ciphertext substring from the ciphertext
    std::string input_ciphertext = ciphertext.substr(noise_size, input_size);

    // Bruteforce the key
    for (std::uint32_t i = 0; i < 0x10000; ++i) {
        std::string output = mt_cipher(input, i, noise_size);
        if (output == input_ciphertext) {
            std::cout << "Found the key, it's: " << i << " and the original key is: " << original_key << "\n";
            break;
        }
    }
}

int main(void) {
#if TEST
    test();
#endif
    std::string input(14, 'A');

    std::string ciphertext = mt_encryption_oracle(input);

    crack_mt_encryption(ciphertext, input, input.length());

    std::string token = generate_random_token(0);

    check_random_token(token);
}
