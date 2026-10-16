// Эталонное Merkle Tree (docs/format_v1.md §6) поверх любого IHashBackend.
#include <chrono>

#include "vault/common/error.hpp"
#include "vault/crypto/domain_hash.hpp"
#include "vault/merkle/merkle.hpp"

namespace vault::merkle {

namespace {

using crypto::IHashBackend;

// Один шаг подъёма: уровень из n > 1 узлов -> уровень из ceil(n/2) узлов.
std::vector<Hash256> next_level(IHashBackend& h, const std::vector<Hash256>& cur) {
    std::vector<Hash256> next;
    next.reserve((cur.size() + 1) / 2);
    for (std::size_t i = 0; i < cur.size(); i += 2) {
        if (i + 1 < cur.size())
            next.push_back(crypto::merkle_parent(h, cur[i], cur[i + 1]));
        else
            next.push_back(crypto::merkle_unpaired(h, cur[i]));
    }
    return next;
}

class ReferenceMerkle final : public IMerkleBackend {
public:
    explicit ReferenceMerkle(std::shared_ptr<IHashBackend> hash) : hash_(std::move(hash)) {
        if (!hash_) throw VaultError(ErrorCode::InvalidArgument, "merkle: hash backend is null");
    }

    std::string_view name() const override { return "reference"; }

    void compute_leaves(std::span<const ByteView> objs, std::span<Hash256> out, TimingBreakdown* timing) override {
        hash_->domain_hash_batch(domain::kMerkleLeaf, objs, out, timing);
    }

    Hash256 root_from_leaves(std::span<const Hash256> leaves, TimingBreakdown* timing) override {
        Timer t(timing);
        if (leaves.empty()) return crypto::merkle_empty_root(*hash_);
        std::vector<Hash256> level(leaves.begin(), leaves.end());
        while (level.size() > 1) level = next_level(*hash_, level);
        return level[0];
    }

    MerkleTree build_tree(std::span<const Hash256> leaves, TimingBreakdown* timing) override {
        Timer t(timing);
        MerkleTree tree;
        if (leaves.empty()) {
            tree.root = crypto::merkle_empty_root(*hash_);
            return tree;
        }
        tree.levels.emplace_back(leaves.begin(), leaves.end());
        while (tree.levels.back().size() > 1) tree.levels.push_back(next_level(*hash_, tree.levels.back()));
        tree.root = tree.levels.back()[0];
        return tree;
    }

    void verify_proofs_batch(std::span<const Hash256> leaves, std::span<const MerkleProof> proofs,
                             const Hash256& root, std::span<std::uint8_t> out_ok, TimingBreakdown* timing) override {
        if (leaves.size() != proofs.size() || out_ok.size() != proofs.size())
            throw VaultError(ErrorCode::InvalidArgument, "merkle: batch size mismatch");
        Timer t(timing);
        for (std::size_t i = 0; i < proofs.size(); ++i)
            out_ok[i] = verify_proof(*hash_, leaves[i], proofs[i], root) ? 1 : 0;
    }

private:
    // CPU-реализация: всё время — "kernel" (см. TimingBreakdown).
    struct Timer {
        explicit Timer(TimingBreakdown* t) : t_(t), t0_(std::chrono::steady_clock::now()) {}
        ~Timer() {
            if (!t_) return;
            double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0_).count();
            t_->kernel_ms += ms;
            t_->total_ms += ms;
        }
        TimingBreakdown* t_;
        std::chrono::steady_clock::time_point t0_;
    };

    std::shared_ptr<IHashBackend> hash_;
};

}  // namespace

std::unique_ptr<IMerkleBackend> make_reference_merkle(std::shared_ptr<crypto::IHashBackend> hash) {
    return std::make_unique<ReferenceMerkle>(std::move(hash));
}

}  // namespace vault::merkle
