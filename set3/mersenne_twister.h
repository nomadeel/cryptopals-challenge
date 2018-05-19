#pragma once

#include <vector>
#include <cstdint>
#include <iostream>
#include <cassert>
#include <algorithm>

namespace MT {
    // Magic numbers for MT
    static const auto W_ = 32U;
    static const auto N_ = 624U;
    static const auto M_ = 397U;
    static const auto R_ = 31U;
    static const auto F_ = 1812433253UL;
    static const auto A_ = 0x9908B0DFUL;
    static const auto U_ = 11U;
    static const auto D_ = 0xFFFFFFFFUL;
    static const auto S_ = 7U;
    static const auto B_ = 0x9D2C5680UL;
    static const auto T_ = 15U;
    static const auto C_ = 0xEFC60000UL;
    static const auto L_ = 18U;

    class MersenneTwister {
    public:
        MersenneTwister(std::uint32_t);
        MersenneTwister(const std::vector<std::uint32_t> &);

        std::uint32_t operator()(void) {
            assert(sizeof(std::uint32_t) == 4);
            // Pass the state through twist function if we've used all numbers to generate
            if (state_counter_ == N_) {
                twist();
                state_counter_ = 0;
            }
            // Pass the current integer through temper function
            std::uint32_t result = 0UL;
            result = state_[state_counter_] ^ (state_[state_counter_] >> U_);
            result ^= (result << S_) & B_;
            result ^= (result << T_) & C_;
            result ^= (result >> L_);

            ++state_counter_;

            return result;
        }
        std::vector<std::uint32_t> state_;
    private:
        void twist(void);

        unsigned int state_counter_;
    };
}
