#include <iostream>
#include <ctime>
// TODO Fix
#include <unistd.h>
#include <random>

#include "mersenne_twister.h"

const auto SEED_DELTA = 1500;
const auto VERIFICATION_TRIALS = 100;
std::time_t original_seed;

void sleep_rand_seconds(void) {
    auto seed = std::random_device()();
    std::mt19937 rng(seed);
    // Generate between 40 to 1000 seconds to sleep for
    auto time_to_sleep = rng() % 1000;
    if (time_to_sleep < 0) {
        time_to_sleep += 40;
    }
    std::cout << "Sleeping for " << time_to_sleep << " seconds...\n";
    sleep(time_to_sleep);
}

std::uint32_t generate_rng(void) {
    sleep_rand_seconds();
    std::time_t curr_time = std::time(nullptr);
    // Set the original seed to validate the results later
    original_seed = curr_time;
    // Seed the RNG with the current time
    MT::MersenneTwister mt(curr_time);
    sleep_rand_seconds();
    return mt();
}

std::time_t crack_mt_seed(std::uint32_t first_value) {
    // Get the current time
    std::time_t curr_time = std::time(nullptr);
    // Get the lower bound to brute force from
    auto lower_bound = curr_time - SEED_DELTA;
    auto num_trials_done = 0U;
    std::cout << "Trying to crack the seed...\n";

    for (auto i = lower_bound; i < curr_time; ++i) {
        if (num_trials_done != 0 && (num_trials_done + 1) % 100 == 0) {
            std::cout << (num_trials_done + 1) << " trials done.\n";
        }
        MT::MersenneTwister mt(i);
        // Check if we've found a match
        if (mt() == first_value) {
            return i;
        }
        ++num_trials_done;
    }

    // Failed to find a match
    return 0;
}

int main(void) {
    auto v = generate_rng();
    auto cracked_seed = crack_mt_seed(v);
    if (cracked_seed != 0) {
        std::cout << "Found a seed, now trying to validate...\n";
    } else {
        std::cout << "Could not find a seed.\n";
    }
    // Validate the results
    MT::MersenneTwister mt1(original_seed);  
    MT::MersenneTwister mt2(cracked_seed);  
    for (auto i = 0U; i < VERIFICATION_TRIALS; ++i) {
        assert(mt1() == mt2());
    }
    std::cout << "Validation passed, seed is: " << cracked_seed << "\n";
}
