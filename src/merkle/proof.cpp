// Merkle proof: построение по готовому дереву и строгая проверка.
#include "vault/common/error.hpp"
#include "vault/crypto/domain_hash.hpp"
#include "vault/merkle/merkle.hpp"

namespace vault::merkle {

MerkleProof make_proof(const MerkleTree& tree, std::uint64_t leaf_index) {
    if (tree.levels.empty() || leaf_index >= tree.levels[0].size())
        throw VaultError(ErrorCode::InvalidArgument, "merkle proof: leaf index out of range");
    MerkleProof p;
    p.leaf_index = leaf_index;
    p.leaf_count = tree.levels[0].size();
    std::uint64_t idx = leaf_index;
    for (std::size_t l = 0; l + 1 < tree.levels.size(); ++l) {
        const auto& level = tree.levels[l];
        ProofStep s{};
        if (idx % 2 == 1) {
            s.kind = ProofStep::Kind::SiblingLeft;
            s.sibling = level[idx - 1];
        } else if (idx + 1 < level.size()) {
            s.kind = ProofStep::Kind::SiblingRight;
            s.sibling = level[idx + 1];
        } else {
            s.kind = ProofStep::Kind::Unpaired;
        }
        p.steps.push_back(s);
        idx /= 2;
    }
    return p;
}

// Форма пути выводится из (leaf_index, leaf_count), поэтому proof с лишними,
// недостающими или «не теми» шагами отвергается независимо от значений хешей.
bool verify_proof(crypto::IHashBackend& hash, const Hash256& leaf, const MerkleProof& proof, const Hash256& root) {
    if (proof.leaf_count == 0 || proof.leaf_index >= proof.leaf_count) return false;
    Hash256 cur = leaf;
    std::uint64_t idx = proof.leaf_index, n = proof.leaf_count;
    std::size_t step = 0;
    while (n > 1) {
        if (step >= proof.steps.size()) return false;
        const ProofStep& s = proof.steps[step++];
        if (idx % 2 == 1) {
            if (s.kind != ProofStep::Kind::SiblingLeft) return false;
            cur = crypto::merkle_parent(hash, s.sibling, cur);
        } else if (idx + 1 < n) {
            if (s.kind != ProofStep::Kind::SiblingRight) return false;
            cur = crypto::merkle_parent(hash, cur, s.sibling);
        } else {
            if (s.kind != ProofStep::Kind::Unpaired) return false;
            cur = crypto::merkle_unpaired(hash, cur);
        }
        idx /= 2;
        n = (n + 1) / 2;
    }
    if (step != proof.steps.size()) return false;
    return constant_time_equal(as_view(cur), as_view(root));
}

}  // namespace vault::merkle
