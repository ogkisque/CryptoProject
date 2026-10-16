#pragma once
// Эмуляция warp'а из 32 lane'ов на CPU для проверки индексной математики shuffle'ов из kernels/keccak_warp.cuh:
// те же функции warp_*/keccak_pi_source/..., что использует device-код, но обмен — обращением к массиву.

#include <algorithm>
#include <cstdint>

#include "kernels/keccak.cuh"
#include "kernels/keccak_warp.cuh"
#include "vault/common/bytes.hpp"

namespace vault::gpu_test {

namespace k = vault::gpu::kernels;

inline void keccak_f1600_warp_emulated(std::uint64_t a[32]) {
    for (unsigned round = 0; round < k::kKeccakRounds; ++round) {
        std::uint64_t th[32], rot[32], b[32], next[32];
        for (unsigned lane = 0; lane < 32; ++lane) {
            std::uint64_t ca = 0, cb = 0;
            for (unsigned i = 0; i < 5; ++i) {
                ca ^= a[k::warp_theta_col_a(lane) + 5 * i];
                cb ^= a[k::warp_theta_col_b(lane) + 5 * i];
            }
            th[lane] = a[lane] ^ ca ^ k::rotl64(cb, 1);
        }
        for (unsigned lane = 0; lane < 32; ++lane) rot[lane] = k::rotl64(th[lane], lane < 25 ? k::keccak_rho_offset(lane) : 0u);
        for (unsigned lane = 0; lane < 32; ++lane) b[lane] = rot[lane < 25 ? k::keccak_pi_source(lane) : lane];
        for (unsigned lane = 0; lane < 32; ++lane) {
            std::uint64_t b1 = b[lane < 25 ? k::warp_chi_a(lane) : lane], b2 = b[lane < 25 ? k::warp_chi_b(lane) : lane];
            next[lane] = b[lane] ^ (~b1 & b2);
        }
        next[0] ^= k::keccak_round_constant(round);
        std::copy(next, next + 32, a);
    }
}

inline Hash256 sha3_warp_emulated(int domain, ByteView data) {
    const std::size_t total = (domain >= 0 ? 1 : 0) + data.size();
    std::uint64_t a[32] = {};
    for (std::size_t blk = 0; blk < k::sha3_block_count(total); ++blk) {
        for (unsigned lane = 0; lane < k::kSha3Rate / 8; ++lane) {
            std::uint64_t w = 0;
            for (unsigned i = 0; i < 8; ++i)
                w |= static_cast<std::uint64_t>(k::sha3_padded_byte(domain, data.data(), data.size(), blk * k::kSha3Rate + 8 * lane + i)) << (8 * i);
            a[lane] ^= w;
        }
        keccak_f1600_warp_emulated(a);
    }
    Hash256 h;
    for (unsigned lane = 0; lane < 4; ++lane) k::store_le64(h.data() + 8 * lane, a[lane]);
    return h;
}



}  // namespace vault::gpu_test
