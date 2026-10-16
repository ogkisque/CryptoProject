#pragma once
// Вариант «warp на объект»: 25 лейнов состояния Keccak распределены по 25 lane'ам warp'а
// (lane i держит A[i], i = x + 5y), обмен — __shfl_sync. Lane'ы 25..31 простаивают, но участвуют в shuffle.
//
// Индексная математика (откуда читает каждый lane) вынесена в VAULT_HD-функции, и проверяется на CPU
// эмуляцией warp'а в tests/unit/kernel_host_test.cpp. Сам device-код (shuffle) под g++ не собирается.

#include <cstddef>
#include <cstdint>

#include "kernels/keccak.cuh"

namespace vault::gpu::kernels {

// theta: lane i с x = i % 5 нужны столбцы C[(x+4)%5] и C[(x+1)%5]; столбец c состоит из lane'ов c, c+5, ..., c+20.
VAULT_HD constexpr unsigned warp_theta_col_a(unsigned lane) { return (lane % 5u + 4u) % 5u; }
VAULT_HD constexpr unsigned warp_theta_col_b(unsigned lane) { return (lane % 5u + 1u) % 5u; }
// rho+pi: lane-назначение dst забирает (уже повёрнутое rho) значение из lane keccak_pi_source(dst).
// chi: lane (x, y) читает lane'ы (x+1)%5 + 5y и (x+2)%5 + 5y.
VAULT_HD constexpr unsigned warp_chi_a(unsigned lane) { return (lane % 5u + 1u) % 5u + 5u * (lane / 5u); }
VAULT_HD constexpr unsigned warp_chi_b(unsigned lane) { return (lane % 5u + 2u) % 5u + 5u * (lane / 5u); }

// rho без switch по номеру lane'а: в warp-варианте индекс у каждого lane'а свой, и switch развёл бы warp по
// 25 веткам. Смещения (по 6 бит) упакованы в три 64-битные константы, выбор — арифметикой (SEL, без ветвлений).
VAULT_HD constexpr std::uint64_t keccak_rho_pack(unsigned base) {
    std::uint64_t v = 0;
    for (unsigned k = 0; k < 10 && base + k < 25; ++k) v |= static_cast<std::uint64_t>(keccak_rho_offset(base + k)) << (6u * k);
    return v;
}
VAULT_HD inline unsigned keccak_rho_offset_branchless(unsigned i) {
    constexpr std::uint64_t p0 = keccak_rho_pack(0), p1 = keccak_rho_pack(10), p2 = keccak_rho_pack(20);
    const std::uint64_t p = i < 10u ? p0 : (i < 20u ? p1 : p2);
    return static_cast<unsigned>((p >> (6u * (i % 10u))) & 63u);
}

#if defined(__CUDACC__)
// Keccak-f[1600] на warp'е: a — слово текущего lane'а (для lane >= 25 игнорируется). Вызывается всем warp'ом.
__device__ inline std::uint64_t keccak_f1600_warp(std::uint64_t a, unsigned lane) {
    const unsigned mask = 0xffffffffu;
    const unsigned x = lane % 5u;
    for (unsigned round = 0; round < kKeccakRounds; ++round) {
        // theta
        std::uint64_t ca = 0, cb = 0;
        const unsigned col_a = warp_theta_col_a(lane), col_b = warp_theta_col_b(lane);
        for (unsigned k = 0; k < 5; ++k) {
            ca ^= __shfl_sync(mask, a, col_a + 5u * k);
            cb ^= __shfl_sync(mask, a, col_b + 5u * k);
        }
        (void)x;
        a ^= ca ^ rotl64(cb, 1);
        // rho + pi: каждый lane вращает своё значение на смещение ИСТОЧНИКА, поэтому вращение — до shuffle
        std::uint64_t rotated = rotl64(a, lane < 25 ? keccak_rho_offset_branchless(lane) : 0u);
        std::uint64_t b = __shfl_sync(mask, rotated, lane < 25 ? keccak_pi_source(lane) : lane);
        // chi
        std::uint64_t b1 = __shfl_sync(mask, b, lane < 25 ? warp_chi_a(lane) : lane);
        std::uint64_t b2 = __shfl_sync(mask, b, lane < 25 ? warp_chi_b(lane) : lane);
        a = b ^ (~b1 & b2);
        if (lane == 0) a ^= keccak_round_constant(round);
    }
    return a;
}

// SHA3-256(domain || data) силами одного warp'а. Результат (32 байта) пишет lane 0..3 в out.
__device__ inline void sha3_256_domain_warp(int domain, const std::uint8_t* data, std::size_t len,
                                            std::uint8_t* out, unsigned lane) {
    const Sha3PadGeometry g = sha3_pad_geometry(domain, len);
    std::uint64_t a = 0;
    for (std::size_t base = 0; base < g.padded; base += kSha3Rate) {
        if (lane < kSha3Rate / 8)  // lane'ы 0..16 поглощают по 8 байт блока
            a ^= sha3_padded_lane(g, domain, data, base + 8u * lane);
        a = keccak_f1600_warp(a, lane);
    }
    if (lane < 4) store_le64(out + 8 * lane, a);
}
#endif  // __CUDACC__

}  // namespace vault::gpu::kernels
