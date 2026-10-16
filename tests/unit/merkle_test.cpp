// Merkle (этап 2.1-2.2): домены, EMPTY_ROOT, векторы из независимой Python-реализации, proofs.
#include <gtest/gtest.h>

#include <fstream>
#include <sstream>

#include "vault/common/error.hpp"
#include "vault/crypto/backends.hpp"
#include "vault/crypto/cpu_backends.hpp"
#include "vault/crypto/domain_hash.hpp"
#include "vault/merkle/merkle.hpp"

using namespace vault;
using namespace vault::merkle;

namespace {

std::shared_ptr<crypto::IHashBackend> hash_backend() {
    static auto h = crypto::make_cpu_hash_backend(1);
    return h;
}

std::vector<Bytes> make_objects(std::size_t n) {
    std::vector<Bytes> objs;
    for (std::size_t i = 0; i < n; ++i) objs.emplace_back(i + 1, static_cast<std::uint8_t>(i));
    return objs;
}

std::vector<Hash256> leaves_of(IMerkleBackend& m, const std::vector<Bytes>& objs) {
    std::vector<ByteView> views(objs.begin(), objs.end());
    std::vector<Hash256> leaves(objs.size());
    m.compute_leaves(views, leaves, nullptr);
    return leaves;
}

// Значение вычислено один раз независимой реализацией (tests/vectors/gen_merkle.py, N = 0).
constexpr const char* kEmptyRootHex = "79cca31da84d78069f9ac5c88123d441ff6ab399649b88f00612adcb7b181ba8";

}  // namespace

TEST(DomainHash, DistinctDomainsGiveDistinctResults) {
    auto h = hash_backend();
    Hash256 x{};
    x.fill(0x42);
    Bytes two(64, 0x42);
    std::vector<Hash256> r = {
        crypto::merkle_leaf(*h, two),         crypto::merkle_parent(*h, x, x),
        crypto::merkle_unpaired(*h, x),       crypto::merkle_empty_root(*h),
        crypto::kem_ct_hash(*h, x),           crypto::kem_key_id(*h, x),
        crypto::sig_key_id(*h, x),
    };
    for (std::size_t i = 0; i < r.size(); ++i)
        for (std::size_t j = i + 1; j < r.size(); ++j) EXPECT_NE(r[i], r[j]) << i << " vs " << j;
    // Parent и leaf над одними и теми же 64 байтами различаются только доменом.
    EXPECT_NE(crypto::merkle_leaf(*h, two), crypto::merkle_parent(*h, x, x));
}

TEST(DomainHash, ParentIsPrefixedConcatenation) {
    auto h = hash_backend();
    Hash256 l{}, r{};
    l.fill(1);
    r.fill(2);
    Bytes buf = {0x01};
    buf.insert(buf.end(), l.begin(), l.end());
    buf.insert(buf.end(), r.begin(), r.end());
    EXPECT_EQ(crypto::merkle_parent(*h, l, r), h->sha3_256(buf));
    EXPECT_NE(crypto::merkle_parent(*h, l, r), crypto::merkle_parent(*h, r, l));
}

TEST(Merkle, EmptyRootConstant) {
    auto m = make_reference_merkle(hash_backend());
    EXPECT_EQ(to_hex(as_view(crypto::merkle_empty_root(*hash_backend()))), kEmptyRootHex);
    EXPECT_EQ(to_hex(as_view(m->root_from_leaves({}, nullptr))), kEmptyRootHex);
    EXPECT_EQ(to_hex(as_view(m->build_tree({}, nullptr).root)), kEmptyRootHex);
}

TEST(Merkle, SingleLeafRootIsLeaf) {  // решение M-1
    auto m = make_reference_merkle(hash_backend());
    auto leaves = leaves_of(*m, make_objects(1));
    EXPECT_EQ(m->root_from_leaves(leaves, nullptr), leaves[0]);
}

TEST(Merkle, MatchesIndependentPythonImplementation) {
    std::ifstream in(std::string(VAULT_TEST_VECTORS_DIR) + "/merkle_vectors.txt");
    ASSERT_TRUE(in.good());
    auto m = make_reference_merkle(hash_backend());
    std::size_t n = 0, checked = 0;
    std::string hex;
    while (in >> n >> hex) {
        auto leaves = leaves_of(*m, make_objects(n));
        EXPECT_EQ(to_hex(as_view(m->root_from_leaves(leaves, nullptr))), hex) << "N=" << n;
        ++checked;
    }
    EXPECT_EQ(checked, 18u);
}

TEST(Merkle, RootFromLeavesEqualsBuildTree) {
    auto m = make_reference_merkle(hash_backend());
    for (std::size_t n = 0; n <= 17; ++n) {
        auto leaves = leaves_of(*m, make_objects(n));
        EXPECT_EQ(m->root_from_leaves(leaves, nullptr), m->build_tree(leaves, nullptr).root) << "N=" << n;
    }
}

TEST(Merkle, SwappingLeavesChangesRoot) {
    auto m = make_reference_merkle(hash_backend());
    for (std::size_t n = 2; n <= 9; ++n) {
        auto leaves = leaves_of(*m, make_objects(n));
        Hash256 root = m->root_from_leaves(leaves, nullptr);
        for (std::size_t i = 0; i + 1 < n; ++i) {
            auto sw = leaves;
            std::swap(sw[i], sw[i + 1]);
            EXPECT_NE(m->root_from_leaves(sw, nullptr), root) << "N=" << n << " i=" << i;
        }
    }
}

TEST(Merkle, ProofsVerifyForEveryLeaf) {
    auto m = make_reference_merkle(hash_backend());
    auto& h = *hash_backend();
    for (std::size_t n = 1; n <= 17; ++n) {
        auto leaves = leaves_of(*m, make_objects(n));
        MerkleTree tree = m->build_tree(leaves, nullptr);
        for (std::size_t i = 0; i < n; ++i) {
            MerkleProof p = make_proof(tree, i);
            EXPECT_TRUE(verify_proof(h, leaves[i], p, tree.root)) << "N=" << n << " i=" << i;
        }
    }
}

TEST(Merkle, ProofsBreakOnAnyCorruption) {
    auto m = make_reference_merkle(hash_backend());
    auto& h = *hash_backend();
    for (std::size_t n : {1u, 2u, 5u, 8u, 13u}) {
        auto leaves = leaves_of(*m, make_objects(n));
        MerkleTree tree = m->build_tree(leaves, nullptr);
        for (std::size_t i = 0; i < n; ++i) {
            MerkleProof p = make_proof(tree, i);
            // Чужой лист и чужой корень.
            Hash256 bad = leaves[i];
            bad[0] ^= 1;
            EXPECT_FALSE(verify_proof(h, bad, p, tree.root));
            Hash256 bad_root = tree.root;
            bad_root[31] ^= 1;
            EXPECT_FALSE(verify_proof(h, leaves[i], p, bad_root));
            // Порча каждого байта каждого соседа.
            for (std::size_t s = 0; s < p.steps.size(); ++s) {
                if (p.steps[s].kind == ProofStep::Kind::Unpaired) continue;
                for (std::size_t b = 0; b < kHashSize; ++b) {
                    MerkleProof q = p;
                    q.steps[s].sibling[b] ^= 0x01;
                    ASSERT_FALSE(verify_proof(h, leaves[i], q, tree.root)) << n << "/" << i << "/" << s << "/" << b;
                }
                // Неверный вид шага.
                MerkleProof q = p;
                q.steps[s].kind = q.steps[s].kind == ProofStep::Kind::SiblingLeft ? ProofStep::Kind::SiblingRight
                                                                                   : ProofStep::Kind::SiblingLeft;
                EXPECT_FALSE(verify_proof(h, leaves[i], q, tree.root));
            }
            // Лишний / недостающий шаг, неверные индекс и размер дерева.
            MerkleProof q = p;
            q.steps.push_back(ProofStep{ProofStep::Kind::Unpaired, {}});
            EXPECT_FALSE(verify_proof(h, leaves[i], q, tree.root));
            if (!p.steps.empty()) {
                q = p;
                q.steps.pop_back();
                EXPECT_FALSE(verify_proof(h, leaves[i], q, tree.root));
            }
            q = p;
            q.leaf_count = 2 * n + 2;  // другая глубина дерева -> другая форма пути
            EXPECT_FALSE(verify_proof(h, leaves[i], q, tree.root));
            q = p;
            q.leaf_index = n;  // вне диапазона
            EXPECT_FALSE(verify_proof(h, leaves[i], q, tree.root));
        }
    }
}

TEST(Merkle, BatchProofVerification) {
    auto m = make_reference_merkle(hash_backend());
    auto leaves = leaves_of(*m, make_objects(7));
    MerkleTree tree = m->build_tree(leaves, nullptr);
    std::vector<MerkleProof> proofs;
    for (std::size_t i = 0; i < 7; ++i) proofs.push_back(make_proof(tree, i));
    proofs[3].steps[0].sibling[0] ^= 1;
    std::vector<std::uint8_t> ok(7);
    m->verify_proofs_batch(leaves, proofs, tree.root, ok, nullptr);
    for (std::size_t i = 0; i < 7; ++i) EXPECT_EQ(ok[i], i == 3 ? 0 : 1);
}

TEST(Merkle, MakeProofRejectsBadIndex) {
    auto m = make_reference_merkle(hash_backend());
    MerkleTree tree = m->build_tree(leaves_of(*m, make_objects(3)), nullptr);
    EXPECT_THROW(make_proof(tree, 3), VaultError);
    EXPECT_THROW(make_proof(m->build_tree({}, nullptr), 0), VaultError);
}
