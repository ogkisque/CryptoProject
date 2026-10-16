#pragma once
// Keccak-f[1600] и SHA3-256 (FIPS 202): sponge с rate = 136 байт, padding 0x06 ... 0x80.
// Domain-префикс (§16) подаётся как первый байт сообщения без копирования данных.
//
// Код общий для устройства и CPU (VAULT_HD). Таблиц нет: round constants и смещения rho/pi
// заданы constexpr-функциями со switch, поэтому на device они превращаются в константы
// инструкций (при развёртке цикла), и не нужен ни __constant__, ни доступ к глобальной памяти.

#include <cstddef>
#include <cstdint>

#include "kernels/hd.hpp"

namespace vault::gpu::kernels {

inline constexpr unsigned kSha3Rate = 136;  // 1088 бит
inline constexpr unsigned kKeccakRounds = 24;

// UNVERIFIED(perf): при развёртке цикла nvcc должен свернуть switch в константы. Если этого не произойдёт,
// switch по runtime-индексу будет заметно медленнее таблицы в __constant__ — смотреть в profile на GPU-машине.
VAULT_HD constexpr std::uint64_t rotl64(std::uint64_t x, unsigned n) {
    return n == 0 ? x : (x << n) | (x >> (64u - n));
}

VAULT_HD constexpr std::uint64_t keccak_round_constant(unsigned i) {
    switch (i) {
        case 0: return 0x0000000000000001ULL;  case 1: return 0x0000000000008082ULL;
        case 2: return 0x800000000000808aULL;  case 3: return 0x8000000080008000ULL;
        case 4: return 0x000000000000808bULL;  case 5: return 0x0000000080000001ULL;
        case 6: return 0x8000000080008081ULL;  case 7: return 0x8000000000008009ULL;
        case 8: return 0x000000000000008aULL;  case 9: return 0x0000000000000088ULL;
        case 10: return 0x0000000080008009ULL; case 11: return 0x000000008000000aULL;
        case 12: return 0x000000008000808bULL; case 13: return 0x800000000000008bULL;
        case 14: return 0x8000000000008089ULL; case 15: return 0x8000000000008003ULL;
        case 16: return 0x8000000000008002ULL; case 17: return 0x8000000000000080ULL;
        case 18: return 0x000000000000800aULL; case 19: return 0x800000008000000aULL;
        case 20: return 0x8000000080008081ULL; case 21: return 0x8000000000008080ULL;
        case 22: return 0x0000000080000001ULL; default: return 0x8000000080008008ULL;
    }
}

// Смещение циклического сдвига (rho) лейна с линейным индексом i = x + 5y.
VAULT_HD constexpr unsigned keccak_rho_offset(unsigned i) {
    switch (i) {
        case 0: return 0;   case 1: return 1;   case 2: return 62;  case 3: return 28;  case 4: return 27;
        case 5: return 36;  case 6: return 44;  case 7: return 6;   case 8: return 55;  case 9: return 20;
        case 10: return 3;  case 11: return 10; case 12: return 43; case 13: return 25; case 14: return 39;
        case 15: return 41; case 16: return 45; case 17: return 15; case 18: return 21; case 19: return 8;
        case 20: return 18; case 21: return 2;  case 22: return 61; case 23: return 56; default: return 14;
    }
}

// pi: лейн (x, y) переходит в позицию (y, 2x + 3y mod 5). Источник для позиции назначения dst = X + 5Y:
// y = X, x = (3Y + X) mod 5  (так как 2^-1 = 3 mod 5), т.е. src = ((3Y + X) % 5) + 5X.
VAULT_HD constexpr unsigned keccak_pi_source(unsigned dst) {
    return ((3u * (dst / 5u) + (dst % 5u)) % 5u) + 5u * (dst % 5u);
}

VAULT_HD inline void keccak_f1600(std::uint64_t a[25]) {
    for (unsigned round = 0; round < kKeccakRounds; ++round) {
        // theta
        std::uint64_t c[5], d[5];
        VAULT_UNROLL
        for (unsigned x = 0; x < 5; ++x) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        VAULT_UNROLL
        for (unsigned x = 0; x < 5; ++x) d[x] = c[(x + 4) % 5] ^ rotl64(c[(x + 1) % 5], 1);
        VAULT_UNROLL
        for (unsigned i = 0; i < 25; ++i) a[i] ^= d[i % 5];
        // rho + pi
        std::uint64_t b[25];
        VAULT_UNROLL
        for (unsigned dst = 0; dst < 25; ++dst) {
            unsigned src = keccak_pi_source(dst);
            b[dst] = rotl64(a[src], keccak_rho_offset(src));
        }
        // chi
        VAULT_UNROLL
        for (unsigned y = 0; y < 5; ++y) {
            VAULT_UNROLL
            for (unsigned x = 0; x < 5; ++x)
                a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
        }
        // iota
        a[0] ^= keccak_round_constant(round);
    }
}

VAULT_HD inline std::uint64_t load_le64(const std::uint8_t* p) {
    std::uint64_t v = 0;
    VAULT_UNROLL
    for (unsigned i = 0; i < 8; ++i) v |= static_cast<std::uint64_t>(p[i]) << (8u * i);
    return v;
}

VAULT_HD inline void store_le64(std::uint8_t* p, std::uint64_t v) {
    VAULT_UNROLL
    for (unsigned i = 0; i < 8; ++i) p[i] = static_cast<std::uint8_t>(v >> (8u * i));
}

// Потоковый sponge SHA3-256: байты XOR-ятся прямо в состояние, промежуточного буфера блока нет.
struct Sha3_256State {
    std::uint64_t s[25];
    unsigned pos;  // 0 .. rate-1: позиция записи в текущем блоке
};

VAULT_HD inline void sha3_init(Sha3_256State& st) {
    for (unsigned i = 0; i < 25; ++i) st.s[i] = 0;
    st.pos = 0;
}

VAULT_HD inline void sha3_absorb_byte(Sha3_256State& st, std::uint8_t b) {
    st.s[st.pos >> 3] ^= static_cast<std::uint64_t>(b) << (8u * (st.pos & 7u));
    if (++st.pos == kSha3Rate) {
        keccak_f1600(st.s);
        st.pos = 0;
    }
}

VAULT_HD inline void sha3_absorb(Sha3_256State& st, const std::uint8_t* p, std::size_t n) {
    // голова: добить до границы лейна
    while (n > 0 && (st.pos & 7u) != 0) {
        sha3_absorb_byte(st, *p++);
        --n;
    }
    // середина: целые 8-байтовые лейны (rate кратен 8, поэтому блок всегда заканчивается на границе лейна)
    while (n >= 8) {
        st.s[st.pos >> 3] ^= load_le64(p);
        st.pos += 8;
        if (st.pos == kSha3Rate) {
            keccak_f1600(st.s);
            st.pos = 0;
        }
        p += 8;
        n -= 8;
    }
    while (n > 0) {
        sha3_absorb_byte(st, *p++);
        --n;
    }
}

VAULT_HD inline void sha3_finalize(Sha3_256State& st, std::uint8_t out[32]) {
    st.s[st.pos >> 3] ^= static_cast<std::uint64_t>(0x06) << (8u * (st.pos & 7u));  // суффикс SHA3 + начало pad10*1
    st.s[(kSha3Rate - 1) >> 3] ^= static_cast<std::uint64_t>(0x80) << (8u * ((kSha3Rate - 1) & 7u));
    keccak_f1600(st.s);
    for (unsigned i = 0; i < 4; ++i) store_le64(out + 8 * i, st.s[i]);
}

// Число блоков sponge для сообщения из total_len байт: padding всегда добавляет блок (или дополняет последний).
VAULT_HD constexpr std::size_t sha3_block_count(std::size_t total_len) { return total_len / kSha3Rate + 1; }

// Геометрия виртуального сообщения "domain || data || pad": считается ОДИН раз на объект
// (деление на rate — дорогая 64-битная операция на GPU, её нельзя делать на каждый байт).
struct Sha3PadGeometry {
    std::size_t prefix;  // 1, если есть domain-байт
    std::size_t total;   // prefix + len
    std::size_t padded;  // кратно kSha3Rate
};

VAULT_HD inline Sha3PadGeometry sha3_pad_geometry(int domain, std::size_t data_len) {
    Sha3PadGeometry g{};
    g.prefix = domain >= 0 ? 1 : 0;
    g.total = g.prefix + data_len;
    g.padded = sha3_block_count(g.total) * kSha3Rate;
    return g;
}

// Байт idx виртуального сообщения с уже применённым padding'ом SHA3 (0x06 ... 0x80).
VAULT_HD inline std::uint8_t sha3_padded_byte(const Sha3PadGeometry& g, int domain, const std::uint8_t* data,
                                              std::size_t idx) {
    std::uint8_t b = 0;
    if (idx < g.total) b = (g.prefix && idx == 0) ? static_cast<std::uint8_t>(domain) : data[idx - g.prefix];
    if (idx == g.total) b |= 0x06;
    if (idx == g.padded - 1) b |= 0x80;
    return b;
}

// 8 байт (лейн) виртуального сообщения, начиная с byte_index (кратно 8). Быстрый путь — лейн целиком в данных.
VAULT_HD inline std::uint64_t sha3_padded_lane(const Sha3PadGeometry& g, int domain, const std::uint8_t* data,
                                               std::size_t byte_index) {
    if (byte_index >= g.prefix && byte_index + 8 <= g.total) return load_le64(data + (byte_index - g.prefix));
    std::uint64_t w = 0;
    for (unsigned k = 0; k < 8; ++k) w |= static_cast<std::uint64_t>(sha3_padded_byte(g, domain, data, byte_index + k)) << (8u * k);
    return w;
}

// SHA3-256(domain || data) поглощением целыми блоками — вариант для kernel'ов.
// Все индексы состояния после развёртки — константы, поэтому s[25] остаётся в регистрах. В потоковом
// sha3_absorb индекс s[pos >> 3] динамический, и на GPU всё состояние ушло бы в local memory.
VAULT_HD inline void sha3_256_domain_blockwise(int domain, const std::uint8_t* data, std::size_t len,
                                               std::uint8_t out[32]) {
    const Sha3PadGeometry g = sha3_pad_geometry(domain, len);
    std::uint64_t s[25];
    VAULT_UNROLL
    for (unsigned i = 0; i < 25; ++i) s[i] = 0;
    for (std::size_t base = 0; base < g.padded; base += kSha3Rate) {
        VAULT_UNROLL
        for (unsigned k = 0; k < kSha3Rate / 8; ++k) s[k] ^= sha3_padded_lane(g, domain, data, base + 8u * k);
        keccak_f1600(s);
    }
    VAULT_UNROLL
    for (unsigned i = 0; i < 4; ++i) store_le64(out + 8 * i, s[i]);
}

// SHA3-256(domain || data); domain < 0 -> без префикса (сырой SHA3-256). Потоковый вариант (CPU, host_hash).
VAULT_HD inline void sha3_256_domain(int domain, const std::uint8_t* data, std::size_t len, std::uint8_t out[32]) {
    Sha3_256State st;
    sha3_init(st);
    if (domain >= 0) sha3_absorb_byte(st, static_cast<std::uint8_t>(domain));
    sha3_absorb(st, data, len);
    sha3_finalize(st, out);
}

}  // namespace vault::gpu::kernels
