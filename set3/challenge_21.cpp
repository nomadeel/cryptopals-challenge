#include <iostream>
#include <random>
#include <algorithm>
#include <cassert>

#include "mersenne_twister.h"

int main (void) {
    for (auto i = 0U; i < 100; ++i) {
        std::mt19937 rng(i);
        MT::MersenneTwister mt(i);
        for (auto j = 0U; j < 624; ++j) {
            assert(rng() == mt());
        }
        if ((i+1) % 10 == 0) {
            std::cout << "- " << i+1 << "'th test passed.\n";
        }
    }

    std::cout << "All tests passed.\n";
}
