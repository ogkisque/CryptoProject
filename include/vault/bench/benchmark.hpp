#pragma once
// Benchmark framework (Milestone 4 — каркас, M5-M7 — наполнение).
// Каждый замер: warm-up, затем measured_runs повторов; для GPU фиксируется
// разбиение alloc/H2D/kernel/D2H/sync. Speedup и crossover считаются в
// bench/analysis/analyze.py по CSV.

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

#include "vault/bench/stats.hpp"
#include "vault/bench/system_info.hpp"
#include "vault/crypto/backends.hpp"

namespace vault::bench {

enum class BenchOp {
    Sha3,          // domain_hash_batch(0x00, objects) — хеширование объектов
    MerkleBuild,   // leaves + root
    MerkleVerify,  // пересчёт root и/или проверка proof batch
    MlKemKeygen, MlKemEncaps, MlKemDecaps,
    MlDsaKeygen, MlDsaSign, MlDsaVerify,
};

struct BenchConfig {
    std::vector<BenchOp> ops;
    std::vector<crypto::BackendConfig> backends;
    std::vector<std::size_t> object_sizes;  // SHA3/Merkle: 1KiB..16MiB
    std::vector<std::size_t> object_counts;  // SHA3/Merkle: 10..100000
    std::vector<std::size_t> batch_sizes;    // PQC: 1..10000
    std::size_t max_total_bytes = std::size_t{4} << 30;  // пропуск комбинаций > лимита
    int warmup_runs = 3;
    int measured_runs = 10;
    bool include_alloc_in_total = true;  // GPU_total учитывает cudaMalloc (§48)
    std::filesystem::path output_csv;
    std::filesystem::path output_json;   // SystemInfo + конфиг + записи
};

struct BenchRecord {
    BenchOp op;
    std::string backend;  // "cpu" | "cpu-mt" | "gpu"
    std::size_t object_size = 0;
    std::size_t count = 0;  // число объектов или batch
    Summary total_ms, kernel_ms, alloc_ms, h2d_ms, d2h_ms, sync_ms;
    double throughput_gbps = 0;  // по median total
    double ops_per_sec = 0;
    double latency_ms = 0;       // median total / count (для batch=1 — single-op latency)
    bool skipped = false;
    std::string skip_reason;     // например, "exceeds max_total_bytes"
};

BenchConfig load_bench_config(const std::filesystem::path& json_path);
std::vector<BenchRecord> run_benchmarks(const BenchConfig& cfg);
void write_csv(const std::filesystem::path& path, const std::vector<BenchRecord>& records);
void write_json(const std::filesystem::path& path, const SystemInfo& info, const BenchConfig& cfg,
                const std::vector<BenchRecord>& records);
std::string_view to_string(BenchOp op) noexcept;

}  // namespace vault::bench
