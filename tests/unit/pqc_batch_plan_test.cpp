// Порционирование batch'а PQC (этап 6.A1).
#include <gtest/gtest.h>

#include "host/pqc_batch_plan.hpp"
#include "vault/common/error.hpp"

using namespace vault;
using namespace vault::gpu;

namespace {
void expect_cover(const std::vector<PqcChunk>& plan, std::size_t batch) {
    std::size_t next = 0;
    for (const auto& c : plan) {
        ASSERT_EQ(c.first, next);
        ASSERT_GT(c.count, 0u);
        next += c.count;
    }
    ASSERT_EQ(next, batch);
}
}  // namespace

TEST(PqcPlan, EmptyAndSingle) {
    EXPECT_TRUE(plan_pqc_chunks(0, 100, 1000).empty());
    auto one = plan_pqc_chunks(1, 100, 1000);
    ASSERT_EQ(one.size(), 1u);
    EXPECT_EQ(one[0].count, 1u);
}

TEST(PqcPlan, ChunksRespectByteLimitAndCoverBatch) {
    // 10 элементов в порции (1000 / 100); batch не кратен размеру порции
    for (std::size_t batch : {1u, 9u, 10u, 11u, 99u, 100u, 101u, 10000u}) {
        auto plan = plan_pqc_chunks(batch, 100, 1000);
        expect_cover(plan, batch);
        for (const auto& c : plan) EXPECT_LE(c.count, 10u);
        EXPECT_EQ(plan.size(), (batch + 9) / 10);
    }
}

TEST(PqcPlan, ItemLargerThanLimitStillMakesProgress) {
    auto plan = plan_pqc_chunks(5, 5000, 1000);
    expect_cover(plan, 5);
    EXPECT_EQ(plan.size(), 5u);
}

TEST(PqcPlan, ExactBoundary) {
    EXPECT_EQ(plan_pqc_chunks(10, 100, 1000).size(), 1u);  // ровно впритык
    EXPECT_EQ(plan_pqc_chunks(10, 100, 999).size(), 2u);   // на байт меньше -> 9 + 1
}

TEST(PqcPlan, GridLimitCapsChunk) {
    auto plan = plan_pqc_chunks(5'000'000'000ULL, 1, std::uint64_t{1} << 62);
    expect_cover(plan, 5'000'000'000ULL);
    for (const auto& c : plan) EXPECT_LE(c.count, 0x7fffffffu);
    EXPECT_EQ(plan.size(), 3u);
}

TEST(PqcPlan, InvalidArguments) {
    EXPECT_THROW(plan_pqc_chunks(5, 0, 1000), VaultError);
    EXPECT_THROW(plan_pqc_chunks(5, 100, 0), VaultError);
    static_assert(round_up_8(0) == 0 && round_up_8(1) == 8 && round_up_8(3309) == 3312 && round_up_8(3312) == 3312);
}
