#include <iostream>
#include <ctime>
#include <random>
#include <vector>

#include "mersenne_twister.h"

const auto NUM_STATE = 624;

std::uint32_t untemper_right_shifts(std::uint32_t input, unsigned int shift_amount) {
    for (auto i = shift_amount; i < 32; i += shift_amount) {
        // Generate a bitmask for the given part
        std::uint32_t part_mask = (0xFFFFFFFF << (32 - shift_amount)) >> (i - shift_amount);
        // Uncover the next shift_amount bits
        input ^= (input & part_mask) >> shift_amount;
    }
    return input;
}

std::uint32_t untemper_left_shifts(std::uint32_t input, unsigned int shift_amount, std::uint32_t mask) {
    for (auto i = shift_amount; i < 32; i += shift_amount) {
        // Generate a bitmask for the given part
        std::uint32_t part_mask = (0xFFFFFFFF >> (32 - shift_amount)) << (i - shift_amount);
        // Uncover the shift_amount bits
        input ^= (((input & part_mask) << shift_amount) & mask);
    }
    return input;
}

std::uint32_t untemper(std::uint32_t input) {
    std::uint32_t output;
    output = untemper_right_shifts(input, 18);
    output = untemper_left_shifts(output, 15, 0xEFC60000);
    output = untemper_left_shifts(output, 7, 0x9D2C5680);
    output = untemper_right_shifts(output, 11);
    return output;
}

std::vector<std::uint32_t> clone_mt_state(MT::MersenneTwister &mt) {
    std::vector<std::uint32_t> output;
    
    for (auto i = 0U; i < NUM_STATE; ++i) {
        output.push_back(untemper(mt())); 
    }

    return output;
}

int main(void) {
    std::time_t seed = std::time(nullptr);
    MT::MersenneTwister mt(seed);
    auto cloned_state = clone_mt_state(mt);
    std::cout << "Cloned the state. Now verifying it...\n";
    MT::MersenneTwister mt1(cloned_state);
    MT::MersenneTwister mt2(seed);
    // Verify the replicated MT
    for (auto i = 0; i < 1000; ++i) {
        assert(mt1() == mt2());
    }
    std::cout << "Passed.\n";
}
