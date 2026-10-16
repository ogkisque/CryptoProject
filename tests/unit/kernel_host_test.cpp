// Kernel-логика GPU (этап 5.A1), исполняемая на CPU: тот же исходный текст, что компилируется nvcc
// (cuda/kernels/*.cuh, макрос VAULT_HD). Результат сверяется с OpenSSL и reference Merkle.
#include <gtest/gtest.h>

#include <algorithm>
#include <random>

#include "host/launch_plan.hpp"
#include "kernels/keccak.cuh"
#include "kernels/keccak_warp.cuh"
#include "kernels/merkle_level.cuh"
#include "warp_emulation.hpp"
#include "vault/crypto/backends.hpp"
#include "vault/crypto/cpu_backends.hpp"
#include "vault/merkle/merkle.hpp"

using namespace vault;
namespace k = vault::gpu::kernels;

namespace {

Bytes rand_bytes(std::mt19937_64& g, std::size_t n) {
    Bytes b(n);
    for (auto& x : b) x = static_cast<std::uint8_t>(g());
    return b;
}

Hash256 kernel_hash(int domain, ByteView data) {
    Hash256 h;
    k::sha3_256_domain(domain, data.data(), data.size(), h.data());
    return h;
}

// Эталон: OpenSSL (через CPU backend).
Hash256 openssl_hash(int domain, ByteView data) {
    static auto h = crypto::make_cpu_hash_backend(1);
    return domain < 0 ? h->sha3_256(data) : h->domain_hash(static_cast<std::uint8_t>(domain), data);
}

}  // namespace

TEST(KernelKeccak, KnownAnswers) {
    EXPECT_EQ(to_hex(kernel_hash(-1, {})), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    EXPECT_EQ(to_hex(kernel_hash(-1, as_view("abc"))), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    // NIST example: SHA3-256 of 1600 bits of 0xA3
    Bytes a3(200, 0xA3);
    EXPECT_EQ(to_hex(kernel_hash(-1, a3)), "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787");
}

TEST(KernelKeccak, MatchesOpenSslForAllLengthsAndDomains) {
    std::mt19937_64 rng(1);
    Bytes buf = rand_bytes(rng, 10100);
    std::vector<std::size_t> lens;
    for (std::size_t n = 0; n <= 600; ++n) lens.push_back(n);
    for (std::size_t n : {1000u, 1359u, 1360u, 1361u, 2000u, 4095u, 4096u, 5000u, 10000u}) lens.push_back(n);
    for (std::size_t n : lens)
        for (int domain : {-1, 0x00, 0x01, 0x02, 0x03, 0x10, 0x11, 0x13}) {
            ByteView v(buf.data(), n);
            ASSERT_EQ(kernel_hash(domain, v), openssl_hash(domain, v)) << "len=" << n << " domain=" << domain;
        }
}

TEST(KernelKeccak, RateBoundaries) {
    // Границы rate = 136 с учётом префикса (длина сообщения = len + 1 при domain >= 0).
    std::mt19937_64 rng(2);
    Bytes buf = rand_bytes(rng, 700);
    for (std::size_t n : {134u, 135u, 136u, 137u, 270u, 271u, 272u, 273u, 407u, 408u, 409u})
        for (int domain : {-1, 0x00, 0x11}) {
            ByteView v(buf.data(), n);
            EXPECT_EQ(kernel_hash(domain, v), openssl_hash(domain, v)) << n << "/" << domain;
        }
}

TEST(KernelKeccak, UnalignedInputAndStreamingSplits) {
    std::mt19937_64 rng(3);
    Bytes buf = rand_bytes(rng, 3000);
    for (std::size_t shift = 0; shift < 8; ++shift) {  // начало данных не выровнено по 8
        ByteView v(buf.data() + shift, 1500 + shift);
        EXPECT_EQ(kernel_hash(0x00, v), openssl_hash(0x00, v)) << shift;
    }
    // Произвольное дробление absorb на куски (в т.ч. нулевой длины и по одному байту)
    for (int trial = 0; trial < 300; ++trial) {
        const std::size_t n = rng() % 2000;
        k::Sha3_256State st;
        k::sha3_init(st);
        for (std::size_t at = 0; at < n;) {
            const std::size_t piece = std::min<std::size_t>(n - at, rng() % 300);
            if (piece == 1) k::sha3_absorb_byte(st, buf[at]);
            else k::sha3_absorb(st, buf.data() + at, piece);
            at += piece;
        }
        Hash256 h;
        k::sha3_finalize(st, h.data());
        ASSERT_EQ(h, openssl_hash(-1, ByteView(buf.data(), n))) << "n=" << n;
    }
    // Детерминированное сравнение «по частям» против «целиком»
    for (std::size_t n : {0u, 1u, 7u, 8u, 9u, 135u, 136u, 137u, 1000u}) {
        for (std::size_t split = 0; split <= n; split += std::max<std::size_t>(1, n / 7)) {
            k::Sha3_256State st;
            k::sha3_init(st);
            k::sha3_absorb(st, buf.data(), split);
            k::sha3_absorb(st, buf.data() + split, n - split);
            Hash256 h;
            k::sha3_finalize(st, h.data());
            EXPECT_EQ(h, openssl_hash(-1, ByteView(buf.data(), n))) << n << "/" << split;
        }
    }
}

TEST(KernelKeccak, ConstantsMatchProjectDomains) {
    EXPECT_EQ(k::kDomMerkleLeaf, domain::kMerkleLeaf);
    EXPECT_EQ(k::kDomMerkleParent, domain::kMerkleParent);
    EXPECT_EQ(k::kDomMerkleUnpaired, domain::kMerkleUnpaired);
    using Kind = merkle::ProofStep::Kind;
    EXPECT_EQ(k::kProofSiblingLeft, static_cast<std::uint8_t>(Kind::SiblingLeft));
    EXPECT_EQ(k::kProofSiblingRight, static_cast<std::uint8_t>(Kind::SiblingRight));
    EXPECT_EQ(k::kProofUnpaired, static_cast<std::uint8_t>(Kind::Unpaired));
}

TEST(KernelWarp, PermutationEmulationEqualsScalarKeccak) {
    std::mt19937_64 rng(4);
    for (int trial = 0; trial < 50; ++trial) {
        std::uint64_t scalar[25], warp[32] = {};
        for (unsigned i = 0; i < 25; ++i) scalar[i] = warp[i] = rng();
        k::keccak_f1600(scalar);
        gpu_test::keccak_f1600_warp_emulated(warp);
        for (unsigned i = 0; i < 25; ++i) ASSERT_EQ(scalar[i], warp[i]) << "lane " << i;
    }
}

TEST(KernelWarp, PaddedMessageAndSpongeEmulationMatchOpenSsl) {
    std::mt19937_64 rng(5);
    Bytes buf = rand_bytes(rng, 1000);
    for (std::size_t n : {0u, 1u, 134u, 135u, 136u, 137u, 271u, 272u, 500u, 1000u})
        for (int domain : {-1, 0x00, 0x11}) {
            ByteView v(buf.data(), n);
            EXPECT_EQ(gpu_test::sha3_warp_emulated(domain, v), openssl_hash(domain, v)) << n << "/" << domain;
        }
}

// --- Merkle: kernel-логика против reference ---

namespace {

struct HostTree {
    std::vector<std::vector<Hash256>> levels;
};

HostTree kernel_tree(const std::vector<Hash256>& leaves) {
    HostTree t;
    if (leaves.empty()) return t;
    t.levels.push_back(leaves);
    while (t.levels.back().size() > 1) {
        const auto& cur = t.levels.back();
        std::vector<Hash256> next((cur.size() + 1) / 2);
        for (std::size_t p = 0; p < next.size(); ++p) k::merkle_level_node(cur[0].data(), cur.size(), p, next[p].data());
        t.levels.push_back(std::move(next));
    }
    return t;
}

}  // namespace

TEST(KernelMerkle, TreesMatchReferenceForN0To1000) {
    auto hash = crypto::make_cpu_hash_backend(1);
    auto ref = merkle::make_reference_merkle(hash);
    std::mt19937_64 rng(6);
    std::vector<Bytes> objs;
    for (std::size_t n = 0; n <= 1000; ++n) {
        if (n > 0) objs.push_back(rand_bytes(rng, 1 + rng() % 200));
        if (n > 40 && n % 7 != 0 && n != 1000) continue;  // выборочно после 40, но включая границы
        std::vector<Hash256> leaves;
        for (const auto& o : objs) leaves.push_back(kernel_hash(k::kDomMerkleLeaf, o));
        std::vector<ByteView> views(objs.begin(), objs.end());
        std::vector<Hash256> ref_leaves(n);
        ref->compute_leaves(views, ref_leaves, nullptr);
        ASSERT_EQ(leaves, ref_leaves) << "N=" << n;
        HostTree t = kernel_tree(leaves);
        merkle::MerkleTree rt = ref->build_tree(ref_leaves, nullptr);
        ASSERT_EQ(t.levels, rt.levels) << "N=" << n;
        if (n > 0) ASSERT_EQ(t.levels.back()[0], rt.root) << "N=" << n;
    }
}

TEST(KernelMerkle, EmptyRootConstant) {
    Hash256 h;
    const std::string_view label = vault::label::kEmptyTree;
    k::sha3_256_domain(0x03, reinterpret_cast<const std::uint8_t*>(label.data()), label.size(), h.data());
    auto ref = merkle::make_reference_merkle(crypto::make_cpu_hash_backend(1));
    EXPECT_EQ(h, ref->root_from_leaves({}, nullptr));
}

TEST(KernelMerkle, ProofVerificationAgreesWithReferenceIncludingMalformed) {
    auto hash = crypto::make_cpu_hash_backend(1);
    auto ref = merkle::make_reference_merkle(hash);
    std::mt19937_64 rng(7);
    for (std::size_t n : {1u, 2u, 3u, 5u, 8u, 13u, 100u}) {
        std::vector<Hash256> leaves(n);
        for (auto& l : leaves) {
            Bytes r = rand_bytes(rng, 32);
            std::copy(r.begin(), r.end(), l.begin());
        }
        merkle::MerkleTree tree = ref->build_tree(leaves, nullptr);
        for (std::size_t i = 0; i < n; ++i) {
            merkle::MerkleProof p = merkle::make_proof(tree, i);
            auto check = [&](const merkle::MerkleProof& q, const Hash256& leaf, const Hash256& root) {
                gpu::PackedProofs pk = gpu::pack_proofs(std::span<const merkle::MerkleProof>(&q, 1));
                bool kernel = k::merkle_verify_proof(leaf.data(), pk.headers[0].leaf_index, pk.headers[0].leaf_count,
                                                     pk.kinds.data(), pk.siblings.data(), pk.headers[0].step_count, root.data());
                EXPECT_EQ(kernel, merkle::verify_proof(*hash, leaf, q, root)) << "n=" << n << " i=" << i;
                return kernel;
            };
            EXPECT_TRUE(check(p, leaves[i], tree.root));
            Hash256 bad = tree.root;
            bad[3] ^= 1;
            EXPECT_FALSE(check(p, leaves[i], bad));
            if (!p.steps.empty()) {
                merkle::MerkleProof q = p;
                q.steps[0].sibling[0] ^= 1;
                if (q.steps[0].kind != merkle::ProofStep::Kind::Unpaired) EXPECT_FALSE(check(q, leaves[i], tree.root));
                q = p;
                q.steps[0].kind = q.steps[0].kind == merkle::ProofStep::Kind::SiblingLeft ? merkle::ProofStep::Kind::SiblingRight
                                                                                           : merkle::ProofStep::Kind::SiblingLeft;
                EXPECT_FALSE(check(q, leaves[i], tree.root));
                q = p;
                q.steps.pop_back();
                EXPECT_FALSE(check(q, leaves[i], tree.root));
            }
            merkle::MerkleProof extra = p;
            extra.steps.push_back({merkle::ProofStep::Kind::Unpaired, {}});
            EXPECT_FALSE(check(extra, leaves[i], tree.root));
            merkle::MerkleProof oob = p;
            oob.leaf_index = n;
            EXPECT_FALSE(check(oob, leaves[i], tree.root));
        }
    }
}
