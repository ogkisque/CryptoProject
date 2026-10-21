// Benchmark framework (этап 4.5): статистика, конфиг, пропуски, CSV/JSON.
#include <gtest/gtest.h>

#include <filesystem>
#include <algorithm>
#include <fstream>
#include <set>
#include <random>
#include <sstream>

#include <nlohmann/json.hpp>

#include "vault/bench/benchmark.hpp"
#include "vault/common/error.hpp"

using namespace vault;
using namespace vault::bench;
namespace fs = std::filesystem;

namespace {
struct TmpDir {
    fs::path p = fs::temp_directory_path() / ("vault_bench_test_" + std::to_string(std::random_device{}()));
    TmpDir() { fs::create_directories(p); }
    ~TmpDir() { fs::remove_all(p); }
    fs::path write(const std::string& name, const std::string& content) const {
        std::ofstream(p / name) << content;
        return p / name;
    }
};
const char* kTinyConfig = R"({
  "_comment": "ignored",
  "ops": ["sha3", "merkle_build", "merkle_verify", "mlkem_keygen", "mlkem_encaps", "mlkem_decaps",
          "mldsa_keygen", "mldsa_sign", "mldsa_verify"],
  "backends": ["cpu", "cpu-mt", "gpu"],
  "cpu_threads": 3,
  "object_sizes": [256, 4096],
  "object_counts": [4, 50],
  "batch_sizes": [1, 8],
  "max_total_bytes": 100000,
  "warmup_runs": 1,
  "measured_runs": 3
})";
}  // namespace

TEST(Stats, SummarizeOddEvenAndSingle) {
    std::vector<double> odd = {5, 1, 3};
    Summary s = summarize(odd);
    EXPECT_EQ(s.n, 3u);
    EXPECT_DOUBLE_EQ(s.median, 3);
    EXPECT_DOUBLE_EQ(s.mean, 3);
    EXPECT_DOUBLE_EQ(s.min, 1);
    EXPECT_DOUBLE_EQ(s.max, 5);
    EXPECT_DOUBLE_EQ(s.stddev, 2);  // выборочное: sqrt((4+0+4)/2)

    std::vector<double> even = {4, 1, 2, 3};
    EXPECT_DOUBLE_EQ(summarize(even).median, 2.5);
    std::vector<double> one = {7};
    Summary o = summarize(one);
    EXPECT_DOUBLE_EQ(o.median, 7);
    EXPECT_DOUBLE_EQ(o.stddev, 0);
    EXPECT_EQ(summarize({}).n, 0u);
}

TEST(BenchConfig, LoadsShippedConfigs) {
    for (const char* name : {"quick.json", "full.json"}) {
        BenchConfig c = load_bench_config(fs::path(VAULT_SOURCE_DIR) / "bench" / "configs" / name);
        EXPECT_EQ(c.ops.size(), 9u) << name;
        EXPECT_EQ(c.backends.size(), 3u);
        EXPECT_GT(c.measured_runs, 0);
    }
}

TEST(BenchConfig, AllShippedConfigsLoadAndLabelsAreUnique) {
    std::size_t n = 0;
    for (const auto& e : fs::directory_iterator(fs::path(VAULT_SOURCE_DIR) / "bench" / "configs")) {
        if (e.path().extension() != ".json") continue;
        BenchConfig c = load_bench_config(e.path());
        EXPECT_EQ(c.backend_labels.size(), c.backends.size()) << e.path();
        std::set<std::string> uniq(c.backend_labels.begin(), c.backend_labels.end());
        EXPECT_EQ(uniq.size(), c.backends.size()) << e.path();
        ++n;
    }
    EXPECT_GE(n, 6u);  // quick, full и четыре gpu_*.json
}

TEST(BenchConfig, BackendObjectsCarryGpuOptionsAndLabels) {
    TmpDir d;
    BenchConfig c = load_bench_config(d.write("o.json", R"({
      "ops": ["sha3"], "object_sizes": [1024], "object_counts": [2], "cpu_threads": 2,
      "backends": ["cpu", {"kind": "cpu-mt", "threads": 5, "label": "mt5"},
        {"kind": "gpu", "label": "g", "pinned_host_memory": false, "double_buffering": true, "pool_buffers": true,
         "strategy": "warp", "max_chunk_bytes": 1048576, "merkle_cpu_threshold": 64, "cuda_device": 1}]})"));
    ASSERT_EQ(c.backends.size(), 3u);
    EXPECT_EQ(c.backend_labels, (std::vector<std::string>{"cpu", "mt5", "g"}));
    EXPECT_EQ(c.backends[1].cpu_threads, 5u);  // threads объекта переопределяет глобальные
    const auto& g = c.backends[2];
    EXPECT_EQ(g.kind, crypto::BackendKind::Gpu);
    EXPECT_FALSE(g.pinned_host_memory);
    EXPECT_TRUE(g.gpu_double_buffering);
    EXPECT_TRUE(g.gpu_pool_buffers);
    EXPECT_EQ(g.gpu_hash_strategy, gpu::GpuHashStrategy::WarpPerObject);
    EXPECT_EQ(g.gpu_max_chunk_bytes, 1048576u);
    EXPECT_EQ(g.gpu_merkle_cpu_threshold, 64u);
    EXPECT_EQ(g.cuda_device, 1);

    const char* prefix = R"({"ops": ["sha3"], "object_sizes": [1], "object_counts": [1], "backends": )";
    auto bad = [&](const std::string& backends, const char* name) {
        EXPECT_THROW(load_bench_config(d.write(name, prefix + backends + "}")), VaultError) << backends;
    };
    bad(R"([{"kind": "gpu", "pinned": true}])", "b1.json");               // неизвестная опция (опечатка)
    bad(R"([{"label": "x"}])", "b2.json");                                // нет kind
    bad(R"([{"kind": "gpu", "strategy": "block"}])", "b3.json");          // неверная стратегия
    bad(R"([{"kind": "gpu", "double_buffering": 1}])", "b4.json");        // не boolean
    bad(R"(["cpu", "cpu"])", "b5.json");                                  // повторяющаяся подпись
    bad(R"([{"kind": "gpu"}, {"kind": "gpu"}])", "b6.json");              // обе подписаны "gpu"
    bad(R"([42])", "b7.json");
}

TEST(BenchConfig, MlDsaContextOption) {
    TmpDir d;
    const char* base = R"({"ops": ["mldsa_sign"], "batch_sizes": [1], "mldsa_context": )";
    EXPECT_FALSE(load_bench_config(d.write("a.json", std::string(base) + "\"manifest\"}")).mldsa_empty_context);
    EXPECT_TRUE(load_bench_config(d.write("b.json", std::string(base) + "\"empty\"}")).mldsa_empty_context);
    EXPECT_THROW(load_bench_config(d.write("c.json", std::string(base) + "\"other\"}")), VaultError);
    EXPECT_FALSE(load_bench_config(d.write("d.json", R"({"ops": ["mldsa_sign"], "batch_sizes": [1]})")).mldsa_empty_context);
}

TEST(BenchConfig, ParsesFieldsAndRejectsBadInput) {
    TmpDir d;
    BenchConfig c = load_bench_config(d.write("ok.json", kTinyConfig));
    EXPECT_EQ(c.backends[1].kind, crypto::BackendKind::CpuParallel);
    EXPECT_EQ(c.backends[1].cpu_threads, 3u);
    EXPECT_EQ(c.object_sizes, (std::vector<std::size_t>{256, 4096}));
    EXPECT_EQ(c.max_total_bytes, 100000u);
    EXPECT_EQ(c.warmup_runs, 1);

    EXPECT_THROW(load_bench_config(d.p / "missing.json"), VaultError);
    EXPECT_THROW(load_bench_config(d.write("a.json", "not json")), VaultError);
    EXPECT_THROW(load_bench_config(d.write("b.json", R"({"ops": ["nope"], "object_sizes":[1],"object_counts":[1]})")), VaultError);
    EXPECT_THROW(load_bench_config(d.write("c.json", R"({"ops": ["sha3"], "backends": ["tpu"], "object_sizes":[1],"object_counts":[1]})")), VaultError);
    EXPECT_THROW(load_bench_config(d.write("d.json", R"({"ops": ["sha3"]})")), VaultError);                       // нет размеров
    EXPECT_THROW(load_bench_config(d.write("e.json", R"({"ops": ["mlkem_keygen"]})")), VaultError);               // нет batch_sizes
    EXPECT_THROW(load_bench_config(d.write("f.json", R"({"ops": ["sha3"], "object_sizes":[0],"object_counts":[1]})")), VaultError);
    EXPECT_THROW(load_bench_config(d.write("g.json", R"({"ops": ["sha3"], "object_sizes":[1],"object_counts":[1],"measured_runs":0})")), VaultError);
}

TEST(Benchmark, RunsAllOpsSkipsOversizedAndUnavailableBackends) {
    TmpDir d;
    BenchConfig cfg = load_bench_config(d.write("t.json", kTinyConfig));
    std::vector<BenchRecord> recs = run_benchmarks(cfg);

    // sha3/merkle_build: 2 размера x 2 количества x 3 backend'а x 2 операции;
    // merkle_verify от размера не зависит: 2 количества x 3 backend'а; PQC: 2 batch x 3 backend'а x 6 операций.
    EXPECT_EQ(recs.size(), 2u * 2 * 3 * 2 + 2 * 3 + 2 * 3 * 6);
    std::size_t measured = 0, over = 0, gpu_skipped = 0;
    for (const auto& r : recs) {
        if (r.backend == "gpu") {
            // Без CUDA/устройства gpu-набор недоступен целиком; на GPU-машине без cuPQC PQC-компоненты — CPU-fallback
            // (пропуск, а не CPU-замер под именем gpu); oversize-комбинации пропускаются раньше проверки backend'а.
            // Измеренные gpu-строки (GPU-машина) проверяются общими проверками ниже.
            if (!crypto::gpu_backend_compiled()) EXPECT_TRUE(r.skipped);
            if (r.skipped) {
                EXPECT_TRUE(r.skip_reason == "exceeds max_total_bytes" ||
                            r.skip_reason.find("backend unavailable") != std::string::npos ||
                            r.skip_reason.find("cpu fallback") != std::string::npos ||
                            r.skip_reason.find("not supported by backend") != std::string::npos)
                    << r.skip_reason;
                ++gpu_skipped;
                continue;
            }
        }
        if (r.skipped) {
            EXPECT_EQ(r.skip_reason, "exceeds max_total_bytes");
            EXPECT_GT(r.object_size * r.count, cfg.max_total_bytes);  // 4096 * 50 = 204800 > 100000
            ++over;
            continue;
        }
        ++measured;
        EXPECT_EQ(r.total_ms.n, 3u);
        EXPECT_GT(r.total_ms.median, 0.0) << to_string(r.op);
        EXPECT_GT(r.ops_per_sec, 0.0);
        EXPECT_GT(r.latency_ms, 0.0);
        EXPECT_GE(r.total_ms.max, r.total_ms.min);
        EXPECT_GT(r.kernel_ms.median, 0.0);  // CPU backend заполняет kernel_ms
        if (r.op == BenchOp::Sha3 || r.op == BenchOp::MerkleBuild) EXPECT_GT(r.throughput_gbps, 0.0);
        if (r.op == BenchOp::MerkleVerify) EXPECT_EQ(r.object_size, 0u);
    }
    EXPECT_EQ(over, 2u * 2 /*cpu, cpu-mt*/);  // sha3 и merkle_build, комбинация 4096x50 (gpu учтён в gpu_skipped)
    EXPECT_GT(measured, 0u);
    EXPECT_GT(gpu_skipped, 0u);
}

TEST(Benchmark, WritesCsvAndJson) {
    TmpDir d;
    BenchConfig cfg = load_bench_config(d.write("t.json", kTinyConfig));
    cfg.ops = {BenchOp::Sha3, BenchOp::MlDsaVerify};
    cfg.object_sizes = {1024};
    cfg.object_counts = {8};
    cfg.batch_sizes = {4};
    cfg.backends.pop_back();  // без gpu
    auto recs = run_benchmarks(cfg);
    ASSERT_EQ(recs.size(), 4u);

    write_csv(d.p / "out" / "r.csv", recs);  // создаёт каталог
    std::ifstream in(d.p / "out" / "r.csv");
    std::string header, line;
    std::getline(in, header);
    std::size_t cols = std::count(header.begin(), header.end(), ',') + 1, rows = 0;
    EXPECT_EQ(header.rfind("op,backend,object_size,count,skipped", 0), 0u);
    while (std::getline(in, line)) {
        ++rows;
        EXPECT_EQ(static_cast<std::size_t>(std::count(line.begin(), line.end(), ',')) + 1, cols) << line;
    }
    EXPECT_EQ(rows, recs.size());

    SystemInfo si = collect_system_info();
    EXPECT_FALSE(si.cpu_model.empty());
    EXPECT_GT(si.cpu_threads, 0u);
    EXPECT_NE(si.openssl_version.find("OpenSSL"), std::string::npos);
    EXPECT_EQ(si.liboqs_version.empty(), false);
    EXPECT_FALSE(si.git_commit.empty());
    EXPECT_FALSE(si.timestamp_utc.empty());

    write_json(d.p / "r.json", si, cfg, recs);
    std::ifstream jin(d.p / "r.json");
    nlohmann::json j = nlohmann::json::parse(jin);
    EXPECT_EQ(j["records"].size(), recs.size());
    EXPECT_EQ(j["system"]["liboqs_version"], si.liboqs_version);
    EXPECT_EQ(j["config"]["measured_runs"], 3);
    EXPECT_EQ(j["records"][0]["op"], "sha3");
    EXPECT_GT(j["records"][0]["total_ms"]["median"].get<double>(), 0.0);
}

// Самопроверка benchmark'а: backend с неверным результатом должен ронять прогон,
// а не давать «быстрый» замер (важно для единственного запуска на GPU).
namespace {
class WrongHash final : public crypto::IHashBackend {
public:
    explicit WrongHash(std::shared_ptr<crypto::IHashBackend> inner) : inner_(std::move(inner)) {}
    std::string_view name() const override { return "wrong"; }
    Hash256 sha3_256(ByteView d) override { return inner_->sha3_256(d); }
    Hash256 domain_hash(std::uint8_t dom, ByteView d) override { return inner_->domain_hash(dom, d); }
    void sha3_256_batch(std::span<const ByteView> in, std::span<Hash256> out, TimingBreakdown* t) override {
        inner_->sha3_256_batch(in, out, t);
    }
    void domain_hash_batch(std::uint8_t dom, std::span<const ByteView> in, std::span<Hash256> out,
                           TimingBreakdown* t) override {
        inner_->domain_hash_batch(dom, in, out, t);
        if (!out.empty()) out.back()[0] ^= 1;  // порча последнего хеша
    }

private:
    std::shared_ptr<crypto::IHashBackend> inner_;
};
}  // namespace

TEST(Benchmark, SelfCheckRejectsWrongBackendResults) {
    crypto::CryptoBackends good = crypto::make_backends({});
    auto wrong = std::make_shared<WrongHash>(good.hash);
    std::vector<std::uint8_t> data(10 * 64, 7);
    std::vector<ByteView> views;
    for (std::size_t i = 0; i < 10; ++i) views.emplace_back(data.data() + i * 64, 64);
    std::vector<Hash256> a(10), b(10);
    good.hash->domain_hash_batch(0, views, a, nullptr);
    wrong->domain_hash_batch(0, views, b, nullptr);
    EXPECT_NE(a, b);  // предпосылка: подделка действительно отличается
    BenchConfig cfg;
    cfg.ops = {BenchOp::Sha3};
    cfg.object_sizes = {64};
    cfg.object_counts = {10};
    cfg.warmup_runs = 0;
    cfg.measured_runs = 1;
    crypto::CryptoBackends bad = good;
    bad.hash = wrong;
    EXPECT_NO_THROW(run_benchmarks(cfg, {{"good", good}}));
    EXPECT_THROW(run_benchmarks(cfg, {{"wrong", bad}}), VaultError);
}

// GPU-набор, в котором часть компонентов — CPU-fallback (нет cuPQC): такие точки должны быть skipped,
// а не попасть в данные как «GPU». Настоящий GPU-путь на CPU-сборке недостижим, поэтому набор подделан:
// hash — «gpu» (обёртка над CPU с именем gpu), остальные компоненты — CPU с именем "cpu".
namespace {
class RenamedHash final : public crypto::IHashBackend {
public:
    explicit RenamedHash(std::shared_ptr<crypto::IHashBackend> inner) : inner_(std::move(inner)) {}
    std::string_view name() const override { return "gpu"; }
    Hash256 sha3_256(ByteView d) override { return inner_->sha3_256(d); }
    Hash256 domain_hash(std::uint8_t dom, ByteView d) override { return inner_->domain_hash(dom, d); }
    void sha3_256_batch(std::span<const ByteView> in, std::span<Hash256> out, TimingBreakdown* t) override {
        inner_->sha3_256_batch(in, out, t);
    }
    void domain_hash_batch(std::uint8_t dom, std::span<const ByteView> in, std::span<Hash256> out,
                           TimingBreakdown* t) override {
        inner_->domain_hash_batch(dom, in, out, t);
    }

private:
    std::shared_ptr<crypto::IHashBackend> inner_;
};
}  // namespace

TEST(Benchmark, GpuSetSkipsCpuFallbackComponents) {
    crypto::CryptoBackends set = crypto::make_backends({});
    set.hash = std::make_shared<RenamedHash>(set.hash);
    BenchConfig cfg;
    cfg.ops = {BenchOp::Sha3, BenchOp::MerkleBuild, BenchOp::MlKemKeygen, BenchOp::MlDsaSign};
    cfg.object_sizes = {64};
    cfg.object_counts = {4};
    cfg.batch_sizes = {2};
    cfg.warmup_runs = 0;
    cfg.measured_runs = 1;
    std::vector<BenchRecord> recs = run_benchmarks(cfg, {{"fake-gpu", set, /*is_gpu=*/true}});
    ASSERT_EQ(recs.size(), 4u);
    for (const auto& r : recs) {
        SCOPED_TRACE(std::string(to_string(r.op)));
        if (r.op == BenchOp::Sha3) {
            EXPECT_FALSE(r.skipped);  // hash называется "gpu" -> измеряется
        } else {
            EXPECT_TRUE(r.skipped);   // merkle/kem/sig — "cpu"/"reference" внутри GPU-набора
            EXPECT_NE(r.skip_reason.find("cpu fallback"), std::string::npos) << r.skip_reason;
        }
    }
    // Тот же набор без пометки is_gpu измеряется целиком.
    for (const auto& r : run_benchmarks(cfg, {{"plain", set, false}})) EXPECT_FALSE(r.skipped);
}
