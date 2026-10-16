// Конвейеры GPU-backend'ов (этап 5.A2) на эмулированном устройстве: cuda/host/hash_pipeline.hpp и
// cuda/host/merkle_levels.hpp — та самая логика, что вызывает CUDA-реализация.
//
// Эмулированное устройство ИСПОЛНЯЕТ ОТЛОЖЕННО: данные и «kernel» отрабатывают только в finish(), поэтому
// любая перезапись staging-буфера слота до finish (гонка, которую на GPU заметить трудно) даёт неверные хеши.
// Staging при prepare() заполняется «ядом», поэтому незаполненные части тоже ломают результат.
#include <gtest/gtest.h>

#include <random>
#include <stdexcept>

#include "host/hash_pipeline.hpp"
#include "host/merkle_levels.hpp"
#include "vault/common/error.hpp"
#include "vault/crypto/cpu_backends.hpp"
#include "vault/merkle/merkle.hpp"
#include "warp_emulation.hpp"

using namespace vault;
using namespace vault::gpu;
namespace k = vault::gpu::kernels;

namespace {

struct EmuHashDev {
    struct Slot {
        std::vector<std::uint8_t> data;
        std::vector<std::uint64_t> offs;
        bool in_flight = false;
        int domain = 0;
        std::size_t count = 0;
    };
    EmuHashDev(unsigned n, bool warp_kernel) : slots(n), warp(warp_kernel) {}

    unsigned slot_count() const { return static_cast<unsigned>(slots.size()); }

    Staging prepare(unsigned s, const HashChunk& c, TimingBreakdown&) {
        if (slots[s].in_flight) hazard = true;  // подготовка слота, который ещё в полёте
        const std::size_t bytes = static_cast<std::size_t>(c.byte_end - c.byte_begin);
        slots[s].data.assign(std::max<std::size_t>(bytes, 1), 0xEE);  // яд
        slots[s].offs.assign(c.count + 1, ~std::uint64_t{0});
        return {slots[s].data.data(), slots[s].offs.data()};
    }

    void launch(unsigned s, const HashChunk& c, int domain, Hash256*, double, TimingBreakdown&) {
        if (slots[s].in_flight) hazard = true;
        slots[s].in_flight = true;
        slots[s].domain = domain;
        slots[s].count = c.count;
        ++launches;
        max_in_flight = std::max(max_in_flight, ++cur_in_flight);
        launch_log.push_back(s);
        if (fail_on_launch >= 0 && static_cast<int>(launches) - 1 == fail_on_launch) throw std::runtime_error("launch failed");
    }

    void finish(unsigned s, const HashChunk& c, Hash256* out_dst, TimingBreakdown&) {
        if (!slots[s].in_flight) hazard = true;
        Slot& sl = slots[s];
        for (std::size_t i = 0; i < sl.count; ++i) {
            ByteView obj(sl.data.data() + sl.offs[i], static_cast<std::size_t>(sl.offs[i + 1] - sl.offs[i]));
            if (warp) out_dst[i] = gpu_test::sha3_warp_emulated(sl.domain, obj);
            else k::sha3_256_domain(sl.domain, obj.data(), obj.size(), out_dst[i].data());
        }
        (void)c;
        sl.in_flight = false;
        --cur_in_flight;
        ++finishes;
        finish_log.push_back(s);
    }

    void drain() noexcept {
        for (auto& sl : slots) sl.in_flight = false;
        cur_in_flight = 0;
        ++drains;
    }

    std::vector<Slot> slots;
    bool warp;
    bool hazard = false;
    int cur_in_flight = 0, max_in_flight = 0, fail_on_launch = -1;
    std::size_t launches = 0, finishes = 0, drains = 0;
    std::vector<unsigned> launch_log, finish_log;
};

Hash256 openssl_hash(int domain, ByteView data) {
    static auto h = crypto::make_cpu_hash_backend(1);
    return domain < 0 ? h->sha3_256(data) : h->domain_hash(static_cast<std::uint8_t>(domain), data);
}

}  // namespace

TEST(HashPipeline, MatchesOpenSslForAllConfigurations) {
    std::mt19937_64 rng(11);
    for (std::size_t n : {1u, 2u, 17u, 300u}) {
        std::vector<Bytes> objs;
        for (std::size_t i = 0; i < n; ++i) {
            Bytes b(rng() % 700);  // включая пустые
            for (auto& x : b) x = static_cast<std::uint8_t>(rng());
            objs.push_back(std::move(b));
        }
        if (n > 5) objs[n / 2].assign(9000, 0x5A);  // больше любой маленькой порции
        std::vector<ByteView> in(objs.begin(), objs.end());

        for (std::uint64_t limit : {chunk_device_bytes(1, 64), std::uint64_t{4096}, std::uint64_t{1} << 20})
            for (unsigned nslots : {1u, 2u, 3u})
                for (bool warp : {false, true})
                    for (int domain : {-1, 0x00, 0x11}) {
                        EmuHashDev dev(nslots, warp);
                        std::vector<Hash256> out(n);
                        TimingBreakdown tb;
                        run_hash_pipeline(dev, domain, in, out, limit, tb);
                        for (std::size_t i = 0; i < n; ++i)
                            ASSERT_EQ(out[i], openssl_hash(domain, in[i]))
                                << "n=" << n << " i=" << i << " len=" << in[i].size() << " limit=" << limit
                                << " slots=" << nslots << " warp=" << warp << " domain=" << domain;
                        EXPECT_FALSE(dev.hazard);
                        EXPECT_LE(dev.max_in_flight, static_cast<int>(nslots));
                        EXPECT_EQ(dev.launches, dev.finishes);
                        EXPECT_EQ(dev.cur_in_flight, 0);
                        // каждая порция идёт в слот c % nslots, в порядке запуска
                        for (std::size_t c = 0; c < dev.launch_log.size(); ++c) EXPECT_EQ(dev.launch_log[c], c % nslots);
                        EXPECT_EQ(dev.drains, 0u);
                    }
    }
}

TEST(HashPipeline, DoubleBufferingOverlapsAndSingleBufferDoesNot) {
    std::vector<Bytes> objs(40, Bytes(1000, 1));
    std::vector<ByteView> in(objs.begin(), objs.end());
    const std::uint64_t limit = chunk_device_bytes(4, 4000);  // ~10 порций
    std::vector<Hash256> out(in.size());
    TimingBreakdown tb;
    EmuHashDev single(1, false), dbl(2, false);
    run_hash_pipeline(single, 0, in, out, limit, tb);
    run_hash_pipeline(dbl, 0, in, out, limit, tb);
    EXPECT_GT(single.launches, 5u);
    EXPECT_EQ(single.max_in_flight, 1);
    EXPECT_EQ(dbl.max_in_flight, 2);
    EXPECT_FALSE(dbl.hazard);
}

TEST(HashPipeline, EmptyBatchTouchesNothing) {
    EmuHashDev dev(2, false);
    std::vector<Hash256> out;
    TimingBreakdown tb;
    run_hash_pipeline(dev, 0, {}, out, 1 << 20, tb);
    EXPECT_EQ(dev.launches, 0u);
    EXPECT_EQ(dev.drains, 0u);
}

TEST(HashPipeline, ErrorInLaunchDrainsAndPropagates) {
    std::vector<Bytes> objs(30, Bytes(500, 2));
    std::vector<ByteView> in(objs.begin(), objs.end());
    EmuHashDev dev(2, false);
    dev.fail_on_launch = 3;
    std::vector<Hash256> out(in.size());
    TimingBreakdown tb;
    EXPECT_THROW(run_hash_pipeline(dev, 0, in, out, chunk_device_bytes(2, 1000), tb), std::runtime_error);
    EXPECT_EQ(dev.drains, 1u);  // всё в полёте дождались до выхода
}

// --- Merkle: уровни на эмулированном устройстве ---

namespace {

struct EmuMerkleDev {
    void begin(std::size_t leaf_count, TimingBreakdown&) {
        ++begins;
        a.assign(leaf_count, poison());
        b.assign((leaf_count + 1) / 2, poison());
    }
    void upload_leaves(const Hash256* leaves, std::size_t n) { std::copy(leaves, leaves + n, a.begin()); }
    void level_step(bool from_a, std::size_t nin, std::size_t nout) {
        auto& src = from_a ? a : b;
        auto& dst = from_a ? b : a;
        if (src.size() < nin || dst.size() < nout) overflow = true;
        for (std::size_t i = 0; i < nin; ++i)
            if (src[i] == poison()) stale_read = true;  // шаг читает то, что не записано
        std::fill(dst.begin(), dst.end(), poison());
        for (std::size_t p = 0; p < nout; ++p) k::merkle_level_node(src[0].data(), nin, p, dst[p].data());
        ++steps;
    }
    void download(bool from_a, std::size_t nodes, Hash256* dst) {
        auto& src = from_a ? a : b;
        if (src.size() < nodes) overflow = true;
        for (std::size_t i = 0; i < nodes; ++i) dst[i] = src[i];
        ++downloads;
    }
    void end(TimingBreakdown&) noexcept { ++ends; }

    static Hash256 poison() {
        Hash256 h;
        h.fill(0xFF);
        return h;
    }
    std::vector<Hash256> a, b;
    bool overflow = false, stale_read = false;
    int begins = 0, ends = 0, steps = 0, downloads = 0;
};

}  // namespace

TEST(MerkleLevels, MatchReferenceForAllThresholdsAndSizes) {
    auto ref = merkle::make_reference_merkle(crypto::make_cpu_hash_backend(1));
    std::mt19937_64 rng(12);
    for (std::size_t n : {1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u, 9u, 16u, 17u, 31u, 100u, 255u, 257u, 1000u, 4097u}) {
        std::vector<Hash256> leaves(n);
        for (auto& l : leaves)
            for (auto& x : l) x = static_cast<std::uint8_t>(rng());
        merkle::MerkleTree rt = ref->build_tree(leaves, nullptr);
        for (std::size_t threshold : {0u, 1u, 2u, 5u, 64u, 1024u, 100000u}) {
            const MerkleSchedule sched = plan_merkle_levels(n, threshold);
            // с уровнями
            {
                EmuMerkleDev dev;
                std::vector<std::vector<Hash256>> levels{leaves};
                TimingBreakdown tb;
                std::vector<Hash256> top = run_merkle_levels(dev, leaves, sched, &levels, tb);
                ASSERT_EQ(top.size(), 1u);
                EXPECT_EQ(top[0], rt.root) << "n=" << n << " thr=" << threshold;
                EXPECT_EQ(levels, rt.levels) << "n=" << n << " thr=" << threshold;
                EXPECT_FALSE(dev.overflow);
                EXPECT_FALSE(dev.stale_read);
                EXPECT_EQ(dev.begins, sched.gpu_steps.empty() ? 0 : 1);
                EXPECT_EQ(dev.ends, dev.begins);
                EXPECT_EQ(dev.steps, static_cast<int>(sched.gpu_steps.size()));
            }
            // только корень: один download верхнего уровня
            {
                EmuMerkleDev dev;
                TimingBreakdown tb;
                std::vector<Hash256> top = run_merkle_levels(dev, leaves, sched, nullptr, tb);
                EXPECT_EQ(top[0], rt.root) << "n=" << n << " thr=" << threshold;
                EXPECT_EQ(dev.downloads, sched.gpu_steps.empty() ? 0 : 1);
                EXPECT_EQ(dev.ends, dev.begins);
            }
        }
    }
}

TEST(MerkleLevels, EmptyRootHelperMatchesReference) {
    auto ref = merkle::make_reference_merkle(crypto::make_cpu_hash_backend(1));
    EXPECT_EQ(host_empty_root(), ref->root_from_leaves({}, nullptr));
}

TEST(ProofRanges, CoverAllProofsAndRespectLimit) {
    auto ref = merkle::make_reference_merkle(crypto::make_cpu_hash_backend(1));
    std::vector<Hash256> leaves(1000);
    for (std::size_t i = 0; i < leaves.size(); ++i) leaves[i].fill(static_cast<std::uint8_t>(i));
    merkle::MerkleTree tree = ref->build_tree(leaves, nullptr);
    std::vector<merkle::MerkleProof> proofs;
    for (std::size_t i = 0; i < leaves.size(); ++i) proofs.push_back(merkle::make_proof(tree, i));

    EXPECT_TRUE(plan_proof_ranges({}, 1000).empty());
    EXPECT_THROW(plan_proof_ranges(proofs, 0), VaultError);
    for (std::uint64_t limit : {std::uint64_t{1}, std::uint64_t{1000}, std::uint64_t{100000}, std::uint64_t{1} << 30}) {
        auto ranges = plan_proof_ranges(proofs, limit);
        std::size_t next = 0;
        for (const auto& r : ranges) {
            ASSERT_EQ(r.first, next);
            ASSERT_GT(r.count, 0u);
            std::uint64_t bytes = 0;
            for (std::size_t i = r.first; i < r.first + r.count; ++i) bytes += 32 + sizeof(ProofHeader) + proofs[i].steps.size() * 33 + 1;
            if (r.count > 1) ASSERT_LE(bytes, limit);  // одиночный proof может превышать лимит
            next += r.count;
        }
        ASSERT_EQ(next, proofs.size());
        if (limit == (std::uint64_t{1} << 30)) EXPECT_EQ(ranges.size(), 1u);
        if (limit == 1) EXPECT_EQ(ranges.size(), proofs.size());
    }
}
