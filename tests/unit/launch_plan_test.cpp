// Host-часть GPU backend'а (этап 5.A2): порционирование, grid/block, расписание Merkle, упаковка proof'ов.
#include <gtest/gtest.h>

#include <numeric>
#include <random>

#include "host/launch_plan.hpp"
#include "vault/common/error.hpp"
#include "vault/crypto/cpu_backends.hpp"
#include "vault/merkle/merkle.hpp"

using namespace vault;
using namespace vault::gpu;

namespace {
std::vector<std::uint64_t> offsets_of(const std::vector<std::uint64_t>& sizes) {
    std::vector<std::uint64_t> off{0};
    for (auto s : sizes) off.push_back(off.back() + s);
    return off;
}

// Инварианты любого плана: порции смежны, покрывают всё, не превышают лимит (кроме oversized).
void check_plan(const std::vector<std::uint64_t>& off, std::uint64_t max_bytes, const std::vector<HashChunk>& plan) {
    const std::size_t n = off.size() - 1;
    std::size_t next = 0;
    for (const HashChunk& c : plan) {
        ASSERT_EQ(c.first, next);
        ASSERT_GT(c.count, 0u);
        ASSERT_EQ(c.byte_begin, off[c.first]);
        ASSERT_EQ(c.byte_end, off[c.first + c.count]);
        std::uint64_t dev = chunk_device_bytes(c.count, c.byte_end - c.byte_begin);
        if (c.oversized) {
            ASSERT_EQ(c.count, 1u);
            ASSERT_GT(dev, max_bytes);
        } else {
            ASSERT_LE(dev, max_bytes);
        }
        next += c.count;
    }
    ASSERT_EQ(next, n);
}
}  // namespace

TEST(LaunchDims, GridCoversThreadsAndIsCapped) {
    EXPECT_EQ(launch_dims(0).grid, 1u);  // пустой запуск запрещён CUDA
    EXPECT_EQ(launch_dims(1).grid, 1u);
    EXPECT_EQ(launch_dims(128).grid, 1u);
    EXPECT_EQ(launch_dims(129).grid, 2u);
    EXPECT_EQ(launch_dims(1'000'000, 256).grid, 3907u);
    EXPECT_EQ(launch_dims(1'000'000, 256).block, 256u);
    EXPECT_EQ(launch_dims(1ULL << 50).grid, 0x7fffffffu);  // ограничение gridDim.x; kernel — grid-stride
    EXPECT_THROW(launch_dims(10, 0), VaultError);
}

TEST(LaunchDims, WarpPerObject) {
    EXPECT_EQ(launch_dims_warp_per_object(1, 128).grid, 1u);   // 32 потока
    EXPECT_EQ(launch_dims_warp_per_object(4, 128).grid, 1u);   // ровно 128 потоков
    EXPECT_EQ(launch_dims_warp_per_object(5, 128).grid, 2u);
    EXPECT_THROW(launch_dims_warp_per_object(5, 100), VaultError);
}

TEST(HashChunks, EmptyAndInvalid) {
    EXPECT_TRUE(plan_hash_chunks({}, 1000).empty());
    std::vector<std::uint64_t> one{0};
    EXPECT_TRUE(plan_hash_chunks(one, 1000).empty());  // 0 объектов
    std::vector<std::uint64_t> bad{0, 10, 5};
    EXPECT_THROW(plan_hash_chunks(bad, 1000), VaultError);
    EXPECT_THROW(plan_hash_chunks(one, 0), VaultError);
}

TEST(HashChunks, BoundarySizes) {
    // 3 объекта по 100 байт: порция из k объектов занимает 100k + 8(k+1) + 32k.
    auto off = offsets_of({100, 100, 100});
    EXPECT_EQ(chunk_device_bytes(3, 300), 300u + 32 + 96);
    auto all = plan_hash_chunks(off, chunk_device_bytes(3, 300));  // ровно впритык -> одна порция
    ASSERT_EQ(all.size(), 1u);
    EXPECT_EQ(all[0].count, 3u);
    auto split = plan_hash_chunks(off, chunk_device_bytes(3, 300) - 1);  // на байт меньше -> две порции
    ASSERT_EQ(split.size(), 2u);
    EXPECT_EQ(split[0].count, 2u);
    EXPECT_EQ(split[1].count, 1u);
    check_plan(off, chunk_device_bytes(3, 300) - 1, split);
}

TEST(HashChunks, ObjectLargerThanChunkGetsItsOwnChunk) {
    auto off = offsets_of({10, 10, 5000, 10, 10});
    const std::uint64_t limit = chunk_device_bytes(2, 20);
    auto plan = plan_hash_chunks(off, limit);
    check_plan(off, limit, plan);
    ASSERT_EQ(plan.size(), 3u);
    EXPECT_FALSE(plan[0].oversized);
    EXPECT_TRUE(plan[1].oversized);
    EXPECT_EQ(plan[1].first, 2u);
    EXPECT_EQ(plan[1].byte_end - plan[1].byte_begin, 5000u);
    EXPECT_FALSE(plan[2].oversized);
}

TEST(HashChunks, ZeroSizedObjectsAndSingleObject) {
    auto off = offsets_of({0, 0, 0});
    auto plan = plan_hash_chunks(off, 1 << 20);
    check_plan(off, 1 << 20, plan);
    EXPECT_EQ(plan.size(), 1u);
    auto single = offsets_of({7});
    check_plan(single, 1 << 20, plan_hash_chunks(single, 1 << 20));
}

TEST(HashChunks, HundredThousandObjectsAndRandomSizes) {
    std::mt19937_64 rng(1);
    std::vector<std::uint64_t> sizes(100000);
    for (auto& s : sizes) s = rng() % 3000;
    auto off = offsets_of(sizes);
    for (std::uint64_t limit : {std::uint64_t{1} << 16, std::uint64_t{1} << 20, std::uint64_t{1} << 28}) {
        auto plan = plan_hash_chunks(off, limit);
        check_plan(off, limit, plan);
        EXPECT_GE(plan.size(), 1u);
    }
    // тот же план для 100000 одинаковых объектов
    auto same = offsets_of(std::vector<std::uint64_t>(100000, 1024));
    check_plan(same, 1 << 20, plan_hash_chunks(same, 1 << 20));
}

TEST(HashChunks, RebaseOffsets) {
    auto off = offsets_of({10, 20, 30, 40});
    std::vector<HashChunk> plan = plan_hash_chunks(off, chunk_device_bytes(2, 50));
    ASSERT_GE(plan.size(), 2u);
    const HashChunk& c = plan[1];
    auto r = rebase_offsets(off, c);
    ASSERT_EQ(r.size(), c.count + 1);
    EXPECT_EQ(r.front(), 0u);
    EXPECT_EQ(r.back(), c.byte_end - c.byte_begin);
    for (std::size_t i = 0; i < c.count; ++i) EXPECT_EQ(r[i + 1] - r[i], off[c.first + i + 1] - off[c.first + i]);
    EXPECT_THROW(rebase_offsets(off, HashChunk{3, 5, 0, 0, false}), VaultError);
}

TEST(MerkleSchedule, LevelsAndCpuTail) {
    auto empty = plan_merkle_levels(0, 1024);
    EXPECT_TRUE(empty.gpu_steps.empty());
    EXPECT_EQ(plan_merkle_levels(1, 1024).cpu_start_nodes, 1u);
    EXPECT_TRUE(plan_merkle_levels(1, 1024).gpu_steps.empty());

    auto s = plan_merkle_levels(100000, 1024);
    ASSERT_FALSE(s.gpu_steps.empty());
    EXPECT_EQ(s.gpu_steps.front().nodes_in, 100000u);
    for (std::size_t i = 0; i < s.gpu_steps.size(); ++i) {
        EXPECT_EQ(s.gpu_steps[i].nodes_out, (s.gpu_steps[i].nodes_in + 1) / 2);
        EXPECT_GE(s.gpu_steps[i].nodes_out, 1024u);
        if (i > 0) EXPECT_EQ(s.gpu_steps[i].nodes_in, s.gpu_steps[i - 1].nodes_out);
    }
    EXPECT_EQ(s.cpu_start_nodes, s.gpu_steps.back().nodes_out);
    EXPECT_LT((s.cpu_start_nodes + 1) / 2, 1024u);  // следующий уровень уже узкий -> CPU

    // порог не достигнут уже на первом шаге -> всё на CPU
    auto small = plan_merkle_levels(1000, 1024);
    EXPECT_TRUE(small.gpu_steps.empty());
    EXPECT_EQ(small.cpu_start_nodes, 1000u);
    // порог 0/1: все уровни на GPU вплоть до корня
    for (std::size_t thr : {0u, 1u}) {
        auto all = plan_merkle_levels(37, thr);
        EXPECT_EQ(all.cpu_start_nodes, 1u);
        EXPECT_EQ(all.gpu_steps.size(), 6u);  // 37 -> 19 -> 10 -> 5 -> 3 -> 2 -> 1
    }
}

TEST(PackProofs, FlatLayoutRoundTrips) {
    auto ref = merkle::make_reference_merkle(crypto::make_cpu_hash_backend(1));
    std::vector<Hash256> leaves(13);
    for (std::size_t i = 0; i < leaves.size(); ++i) leaves[i].fill(static_cast<std::uint8_t>(i + 1));
    merkle::MerkleTree tree = ref->build_tree(leaves, nullptr);
    std::vector<merkle::MerkleProof> proofs;
    for (std::size_t i = 0; i < leaves.size(); ++i) proofs.push_back(merkle::make_proof(tree, i));

    PackedProofs p = pack_proofs(proofs);
    ASSERT_EQ(p.headers.size(), proofs.size());
    std::size_t total = 0;
    for (const auto& pr : proofs) total += pr.steps.size();
    EXPECT_EQ(p.kinds.size(), total);
    EXPECT_EQ(p.siblings.size(), total * 32);
    for (std::size_t i = 0; i < proofs.size(); ++i) {
        const ProofHeader& h = p.headers[i];
        EXPECT_EQ(h.leaf_index, proofs[i].leaf_index);
        EXPECT_EQ(h.leaf_count, proofs[i].leaf_count);
        ASSERT_EQ(h.step_count, proofs[i].steps.size());
        for (std::size_t s = 0; s < h.step_count; ++s) {
            EXPECT_EQ(p.kinds[h.steps_begin + s], static_cast<std::uint8_t>(proofs[i].steps[s].kind));
            Hash256 sib;
            std::copy_n(p.siblings.begin() + 32 * (h.steps_begin + s), 32, sib.begin());
            Hash256 expect{};
            if (proofs[i].steps[s].kind != merkle::ProofStep::Kind::Unpaired) expect = proofs[i].steps[s].sibling;
            EXPECT_EQ(sib, expect);
        }
    }
    EXPECT_TRUE(pack_proofs({}).headers.empty());
}
