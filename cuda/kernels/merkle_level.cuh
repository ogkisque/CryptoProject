#pragma once
// Операции Merkle-дерева (docs/format_v1.md §6) поверх kernels/keccak.cuh — для kernel'ов и CPU-тестов.
// Все хеши — 32-байтовые элементы непрерывных буферов (без padding), как в Hash256[].

#include <cstddef>
#include <cstdint>

#include "kernels/keccak.cuh"

namespace vault::gpu::kernels {

inline constexpr int kDomMerkleLeaf = 0x00;
inline constexpr int kDomMerkleParent = 0x01;
inline constexpr int kDomMerkleUnpaired = 0x02;
inline constexpr int kDomMerkleEmpty = 0x03;

// Совпадает с merkle::ProofStep::Kind по числовым значениям (проверяется в тесте).
inline constexpr std::uint8_t kProofSiblingLeft = 0;
inline constexpr std::uint8_t kProofSiblingRight = 1;
inline constexpr std::uint8_t kProofUnpaired = 2;

// SHA3(0x01 || L || R): L, R — по 32 байта. Блочное поглощение (состояние в регистрах, см. keccak.cuh);
// 0x01 || L || R = 65 байт — один блок sponge.
VAULT_HD inline void merkle_parent(const std::uint8_t* left, const std::uint8_t* right, std::uint8_t out[32]) {
    std::uint8_t lr[64];
    VAULT_UNROLL
    for (unsigned i = 0; i < 32; ++i) {
        lr[i] = left[i];
        lr[32 + i] = right[i];
    }
    sha3_256_domain_blockwise(kDomMerkleParent, lr, 64, out);
}

// SHA3(0x02 || x)
VAULT_HD inline void merkle_unpaired(const std::uint8_t* x, std::uint8_t out[32]) {
    sha3_256_domain_blockwise(kDomMerkleUnpaired, x, 32, out);
}

// Узел parent_idx следующего уровня по текущему уровню из n узлов: 2p и 2p+1, а при нечётном n
// последний узел без пары поднимается через unpaired (не дублируется).
VAULT_HD inline void merkle_level_node(const std::uint8_t* level, std::size_t n, std::size_t parent_idx,
                                       std::uint8_t out[32]) {
    std::size_t i = 2 * parent_idx;
    if (i + 1 < n)
        merkle_parent(level + 32 * i, level + 32 * (i + 1), out);
    else
        merkle_unpaired(level + 32 * i, out);
}

// Строгая проверка proof (то же, что merkle::verify_proof): форма пути выводится из
// (leaf_index, leaf_count); kinds[k] — вид k-го шага, siblings + 32*k — сосед (для Unpaired не читается).
VAULT_HD inline bool merkle_verify_proof(const std::uint8_t leaf[32], std::uint64_t leaf_index,
                                         std::uint64_t leaf_count, const std::uint8_t* kinds,
                                         const std::uint8_t* siblings, std::uint32_t step_count,
                                         const std::uint8_t root[32]) {
    if (leaf_count == 0 || leaf_index >= leaf_count) return false;
    std::uint8_t cur[32], nxt[32];
    for (unsigned i = 0; i < 32; ++i) cur[i] = leaf[i];
    std::uint64_t idx = leaf_index, n = leaf_count;
    std::uint32_t step = 0;
    while (n > 1) {
        if (step >= step_count) return false;
        const std::uint8_t kind = kinds[step];
        const std::uint8_t* sib = siblings + 32u * step;
        ++step;
        if (idx % 2 == 1) {
            if (kind != kProofSiblingLeft) return false;
            merkle_parent(sib, cur, nxt);
        } else if (idx + 1 < n) {
            if (kind != kProofSiblingRight) return false;
            merkle_parent(cur, sib, nxt);
        } else {
            if (kind != kProofUnpaired) return false;
            merkle_unpaired(cur, nxt);
        }
        for (unsigned i = 0; i < 32; ++i) cur[i] = nxt[i];
        idx /= 2;
        n = (n + 1) / 2;
    }
    if (step != step_count) return false;
    std::uint8_t diff = 0;
    for (unsigned i = 0; i < 32; ++i) diff |= static_cast<std::uint8_t>(cur[i] ^ root[i]);
    return diff == 0;
}

}  // namespace vault::gpu::kernels
