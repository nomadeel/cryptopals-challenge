#include <iostream>
#include <ctime>
#include <random>
#include <vector>

#include "mersenne_twister.h"

const auto NUM_STATE = 624;

std::uint32_t untemper_right_shifts(std::uint32_t input, unsigned int shift_amount) {
    std::uint32_t output = 0;
    for (auto i = 0; i < 32; i += shift_amount) {
        std::uint32_t part_mask = (0xFFFFFFFF << (32 - shift_amount)) >> i;
        std::uint32_t curr_part = input & part_mask;
        input ^= curr_part >> shift_amount;
        output |= curr_part;
    }
    return output;
}

std::uint32_t untemper_left_shifts(std::uint32_t input, unsigned int shift_amount, std::uint32_t mask) {
    std::uint32_t output = 0;
    for (auto i = 0; i < 32; i += shift_amount) {
        std::uint32_t part_mask = (0xFFFFFFFF >> (32 - shift_amount)) << i;
        std::uint32_t curr_part = input & part_mask;
        input ^= ((curr_part << shift_amount) & mask);
        output |= curr_part;
    }
    return output;
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
