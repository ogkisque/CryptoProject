#pragma once
// Domain-separated бинарное Merkle Tree (§17-§20).
//   leaf     = SHA3(0x00 || CanonicalEncode(obj)),  объекты отсортированы по file_id
//   parent   = SHA3(0x01 || L || R)
//   unpaired = SHA3(0x02 || last)        — последний узел НЕ дублируется
//   empty    = SHA3(0x03 || "edu-vault-empty-tree-v1")
// Уровень с одним непарным узлом: он заменяется на unpaired(last) и поднимается.
// Дерево из одного листа: root = leaf (уровень из 1 узла — это уже корень).
// См. docs/format_v1.md — там же зафиксированы эталонные векторы.

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>
#include <vector>

#include "vault/common/bytes.hpp"
#include "vault/common/timing.hpp"
#include "vault/crypto/hash_backend.hpp"

namespace vault::merkle {

struct MerkleTree {
    // levels[0] — листья, levels.back() — {root}. Для пустого дерева levels пуст.
    std::vector<std::vector<Hash256>> levels;
    Hash256 root{};
};

struct ProofStep {
    enum class Kind : std::uint8_t {
        SiblingLeft,   // parent = H(0x01 || sibling || cur)
        SiblingRight,  // parent = H(0x01 || cur || sibling)
        Unpaired,      // parent = H(0x02 || cur), sibling не используется
    };
    Kind kind;
    Hash256 sibling{};
};

struct MerkleProof {
    std::uint64_t leaf_index = 0;
    std::uint64_t leaf_count = 0;
    std::vector<ProofStep> steps;
};

class IMerkleBackend {
public:
    virtual ~IMerkleBackend() = default;
    virtual std::string_view name() const = 0;

    // Листья по уже канонически закодированным и ОТСОРТИРОВАННЫМ объектам.
    virtual void compute_leaves(std::span<const ByteView> encoded_objects_sorted,
                                std::span<Hash256> out_leaves, TimingBreakdown* timing) = 0;
    // Корень по готовым листьям.
    virtual Hash256 root_from_leaves(std::span<const Hash256> leaves,
                                     TimingBreakdown* timing) = 0;
    // Полное дерево (все уровни) — нужно для proof и для cache.
    virtual MerkleTree build_tree(std::span<const Hash256> leaves, TimingBreakdown* timing) = 0;
    // Пакетная проверка доказательств (benchmark "Merkle verification").
    // out_ok[i] = 1, если proofs[i] для leaves[i] ведёт к root.
    virtual void verify_proofs_batch(std::span<const Hash256> leaves,
                                     std::span<const MerkleProof> proofs, const Hash256& root,
                                     std::span<std::uint8_t> out_ok, TimingBreakdown* timing) = 0;
};

// Эталонная (reference) реализация поверх любого IHashBackend — CPU-спецификация,
// с которой сравниваются все backend'ы.
std::unique_ptr<IMerkleBackend> make_reference_merkle(std::shared_ptr<crypto::IHashBackend> hash);
// Многопоточный CPU-вариант: листья — через batch hash backend'а, уровни дерева с достаточным числом
// узлов считаются параллельно. Результат побайтно совпадает с reference. threads <= 1 -> reference.
std::unique_ptr<IMerkleBackend> make_parallel_merkle(std::shared_ptr<crypto::IHashBackend> hash, unsigned threads);

MerkleProof make_proof(const MerkleTree& tree, std::uint64_t leaf_index);
bool verify_proof(crypto::IHashBackend& hash, const Hash256& leaf, const MerkleProof& proof,
                  const Hash256& root);

}  // namespace vault::merkle
