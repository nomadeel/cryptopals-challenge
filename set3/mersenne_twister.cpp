#include "mersenne_twister.h"

namespace MT {
    MersenneTwister::MersenneTwister(std::uint32_t seed): state_(N_), state_counter_{0U} {
        // Init the state
        state_[0] = seed;
        for (auto i = 1U; i < N_; ++i) {
            state_[i] = F_ * (state_[i-1] ^ (state_[i-1] >> (W_ - 2))) + i;
        }

        twist();
    }
        
    MersenneTwister::MersenneTwister(const std::vector<std::uint32_t> &state): state_{}, state_counter_{0U} {
        assert(state.size() == N_);
        state_.reserve(N_);
        std::copy(state.begin(), state.end(), state_.begin());
    }

    void MersenneTwister::twist(void) {
        const auto first_half = N_ - M_;
        for (auto i = 0U; i < first_half; ++i) {
            auto temp = (state_[i] & 0x80000000) | (state_[i+1] & 0x7FFFFFFF);
            state_[i] = state_[i + M_] ^ (temp >> 1);
            if (temp & 1) {
                state_[i] ^= A_;
            }
        }

        for (auto i = first_half; i < N_ - 1; ++i) {
            auto temp = (state_[i] & 0x80000000) | (state_[i+1] & 0x7FFFFFFF);
            state_[i] = state_[i - first_half] ^ (temp >> 1);
            if (temp & 1) {
                state_[i] ^= A_;
            }
        }

        auto temp = (state_[N_ - 1] << (W_ - 1)) | (state_[0] >> 1);
        temp = (state_[N_ - 1] & 0x80000000) | (state_[0] & 0x7FFFFFFF);
        state_[N_ - 1] = state_[M_ - 1] ^ (temp >> 1);
        if (temp & 1) {
            state_[N_ - 1] ^= A_;
        }
    }
}
