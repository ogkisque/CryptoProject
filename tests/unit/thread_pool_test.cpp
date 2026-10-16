#include <gtest/gtest.h>

#include <atomic>
#include <numeric>
#include <thread>
#include <stdexcept>

#include "vault/common/thread_pool.hpp"
#include "vault/crypto/packed_batch.hpp"

using namespace vault;

TEST(ThreadPool, RunsEveryTaskExactlyOnce) {
    for (unsigned threads : {1u, 2u, 8u}) {
        ThreadPool pool(threads);
        for (std::size_t n : {0u, 1u, 5u, 1000u}) {
            std::vector<std::atomic<int>> hits(n);
            pool.parallel_for(n, [&](std::size_t i) { ++hits[i]; });
            for (std::size_t i = 0; i < n; ++i) ASSERT_EQ(hits[i].load(), 1) << threads << "/" << n << "/" << i;
        }
    }
}

TEST(ThreadPool, ManyConsecutiveAndConcurrentCalls) {
    ThreadPool pool(4);
    std::atomic<long> sum{0};
    for (int r = 0; r < 200; ++r) pool.parallel_for(50, [&](std::size_t i) { sum += static_cast<long>(i); });
    EXPECT_EQ(sum.load(), 200L * 49 * 50 / 2);
    // Вызовы из разных потоков сериализуются и не мешают друг другу.
    std::atomic<long> s2{0};
    std::vector<std::thread> ts;
    for (int t = 0; t < 4; ++t)
        ts.emplace_back([&] {
            for (int r = 0; r < 50; ++r) pool.parallel_for(20, [&](std::size_t) { ++s2; });
        });
    for (auto& t : ts) t.join();
    EXPECT_EQ(s2.load(), 4L * 50 * 20);
}

TEST(ThreadPool, ExceptionIsPropagatedAfterAllTasks) {
    ThreadPool pool(4);
    std::atomic<int> ran{0};
    EXPECT_THROW(pool.parallel_for(100, [&](std::size_t i) {
        ++ran;
        if (i == 13) throw std::runtime_error("boom");
    }), std::runtime_error);
    EXPECT_EQ(ran.load(), 100);
    pool.parallel_for(3, [&](std::size_t) {});  // пул пригоден после исключения
}

TEST(ThreadPool, SharedPoolIsReused) {
    auto a = shared_thread_pool(3), b = shared_thread_pool(3);
    EXPECT_EQ(a.get(), b.get());
    EXPECT_EQ(a->size(), 3u);
    EXPECT_GE(resolve_thread_count(0), 1u);
}

TEST(SplitByWeight, CoversRangeAndBalancesBytes) {
    std::vector<std::size_t> w = {1000, 1, 1, 1, 1, 1000, 1, 1, 1, 1000};
    auto b = split_by_weight(w.size(), 3, [&](std::size_t i) { return w[i]; });
    ASSERT_GE(b.size(), 2u);
    EXPECT_EQ(b.front(), 0u);
    EXPECT_EQ(b.back(), w.size());
    for (std::size_t k = 0; k + 1 < b.size(); ++k) EXPECT_LT(b[k], b[k + 1]);  // непустые диапазоны
    EXPECT_LE(b.size() - 1, 3u);
    // Тяжёлые элементы не слипаются в один диапазон: каждый диапазон весит не больше ~одного тяжёлого + хвост.
    for (std::size_t k = 0; k + 1 < b.size(); ++k) {
        std::size_t sum = std::accumulate(w.begin() + b[k], w.begin() + b[k + 1], std::size_t{0});
        EXPECT_LE(sum, 2100u);
    }
    EXPECT_EQ(split_by_weight(0, 4, [](std::size_t) { return 1; }), (std::vector<std::size_t>{0}));
    auto one = split_by_weight(5, 1, [](std::size_t) { return 1; });
    EXPECT_EQ(one, (std::vector<std::size_t>{0, 5}));
    auto more = split_by_weight(3, 10, [](std::size_t) { return 1; });  // диапазонов не больше элементов
    EXPECT_EQ(more.back(), 3u);
    EXPECT_LE(more.size() - 1, 3u);
}

TEST(PackedBatch, RoundTrip) {
    Bytes a = {1, 2, 3}, b, c = {9};
    std::vector<ByteView> in = {a, b, c};
    auto p = crypto::PackedBatch::pack(in);
    EXPECT_EQ(p.count(), 3u);
    EXPECT_EQ(p.data, (Bytes{1, 2, 3, 9}));
    EXPECT_EQ(p.offsets, (std::vector<std::uint64_t>{0, 3, 3, 4}));
    EXPECT_EQ(Bytes(p.element(0).begin(), p.element(0).end()), a);
    EXPECT_TRUE(p.element(1).empty());
    EXPECT_EQ(crypto::PackedBatch::pack({}).count(), 0u);
}
