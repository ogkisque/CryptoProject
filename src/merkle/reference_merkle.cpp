// Эталонное Merkle Tree (docs/format_v1.md §6) поверх любого IHashBackend.
#include <algorithm>
#include <chrono>

#include "vault/common/error.hpp"
#include "vault/common/thread_pool.hpp"
#include "vault/crypto/domain_hash.hpp"
#include "vault/merkle/merkle.hpp"

namespace vault::merkle {

namespace {

using crypto::IHashBackend;

// Один шаг подъёма: уровень из n > 1 узлов -> уровень из ceil(n/2) узлов.
// Узлы уровня независимы, поэтому при pool != nullptr и достаточной ширине считаются параллельно.
constexpr std::size_t kParallelLevelThreshold = 2048;  // родителей на уровне

std::vector<Hash256> next_level(IHashBackend& h, const std::vector<Hash256>& cur, ThreadPool* pool) {
    const std::size_t parents = (cur.size() + 1) / 2;
    std::vector<Hash256> next(parents);
    auto one = [&](std::size_t p) {
        std::size_t i = 2 * p;
        next[p] = i + 1 < cur.size() ? crypto::merkle_parent(h, cur[i], cur[i + 1]) : crypto::merkle_unpaired(h, cur[i]);
    };
    if (pool && parents >= kParallelLevelThreshold) {
        std::size_t parts = std::size_t{pool->size()} * 4;
        pool->parallel_for(parts, [&](std::size_t k) {
            for (std::size_t p = parents * k / parts; p < parents * (k + 1) / parts; ++p) one(p);
        });
    } else {
        for (std::size_t p = 0; p < parents; ++p) one(p);
    }
    return next;
}

class ReferenceMerkle final : public IMerkleBackend {
public:
    ReferenceMerkle(std::shared_ptr<IHashBackend> hash, unsigned threads) : hash_(std::move(hash)) {
        if (threads > 1) pool_ = shared_thread_pool(threads);
        if (!hash_) throw VaultError(ErrorCode::InvalidArgument, "merkle: hash backend is null");
    }

    std::string_view name() const override { return pool_ ? "cpu-mt" : "reference"; }

    void compute_leaves(std::span<const ByteView> objs, std::span<Hash256> out, TimingBreakdown* timing) override {
        hash_->domain_hash_batch(domain::kMerkleLeaf, objs, out, timing);
    }

    Hash256 root_from_leaves(std::span<const Hash256> leaves, TimingBreakdown* timing) override {
        Timer t(timing);
        if (leaves.empty()) return crypto::merkle_empty_root(*hash_);
        std::vector<Hash256> level(leaves.begin(), leaves.end());
        while (level.size() > 1) level = next_level(*hash_, level, pool_.get());
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
        while (tree.levels.back().size() > 1) tree.levels.push_back(next_level(*hash_, tree.levels.back(), pool_.get()));
        tree.root = tree.levels.back()[0];
        return tree;
    }

    void verify_proofs_batch(std::span<const Hash256> leaves, std::span<const MerkleProof> proofs,
                             const Hash256& root, std::span<std::uint8_t> out_ok, TimingBreakdown* timing) override {
        if (leaves.size() != proofs.size() || out_ok.size() != proofs.size())
            throw VaultError(ErrorCode::InvalidArgument, "merkle: batch size mismatch");
        Timer t(timing);
        auto one = [&](std::size_t i) { out_ok[i] = verify_proof(*hash_, leaves[i], proofs[i], root) ? 1 : 0; };
        if (pool_ && proofs.size() > 1) {
            std::size_t n = proofs.size(), parts = std::min<std::size_t>(n, std::size_t{pool_->size()} * 4);
            pool_->parallel_for(parts, [&](std::size_t k) {
                for (std::size_t i = n * k / parts; i < n * (k + 1) / parts; ++i) one(i);
            });
        } else {
            for (std::size_t i = 0; i < proofs.size(); ++i) one(i);
        }
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
    std::shared_ptr<ThreadPool> pool_;
};

}  // namespace

std::unique_ptr<IMerkleBackend> make_reference_merkle(std::shared_ptr<crypto::IHashBackend> hash) {
    return std::make_unique<ReferenceMerkle>(std::move(hash), 1);
}

std::unique_ptr<IMerkleBackend> make_parallel_merkle(std::shared_ptr<crypto::IHashBackend> hash, unsigned threads) {
    return std::make_unique<ReferenceMerkle>(std::move(hash), threads);
}

}  // namespace vault::merkle
