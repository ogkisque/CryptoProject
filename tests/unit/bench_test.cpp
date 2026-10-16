// Benchmark framework (этап 4.5): статистика, конфиг, пропуски, CSV/JSON.
#include <gtest/gtest.h>

#include <filesystem>
#include <algorithm>
#include <fstream>
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

    // sha3/merkle: 2 размера x 2 количества x 3 backend'а x 3 операции; PQC: 2 batch x 3 backend'а x 6 операций.
    EXPECT_EQ(recs.size(), 2u * 2 * 3 * 3 + 2 * 3 * 6);
    std::size_t measured = 0, over = 0, gpu_skipped = 0;
    for (const auto& r : recs) {
        if (r.backend == "gpu" && !crypto::gpu_backend_compiled()) {
            EXPECT_TRUE(r.skipped);
            // oversize-комбинации пропускаются раньше проверки backend'а
            EXPECT_TRUE(r.skip_reason == "exceeds max_total_bytes" ||
                        r.skip_reason.find("backend unavailable") != std::string::npos)
                << r.skip_reason;
            ++gpu_skipped;
            continue;
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
        if (r.op == BenchOp::Sha3 || r.op == BenchOp::MerkleBuild || r.op == BenchOp::MerkleVerify)
            EXPECT_GT(r.throughput_gbps, 0.0);
    }
    EXPECT_EQ(over, 3u * 2 /*cpu, cpu-mt*/);  // 3 операции, комбинация 4096x50 (gpu учтён в gpu_skipped)
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
