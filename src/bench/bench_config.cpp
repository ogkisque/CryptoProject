#include <fstream>

#include <nlohmann/json.hpp>

#include "vault/bench/benchmark.hpp"
#include "vault/common/error.hpp"

namespace vault::bench {

namespace {

struct OpName {
    BenchOp op;
    std::string_view name;
};
constexpr OpName kOps[] = {
    {BenchOp::Sha3, "sha3"},
    {BenchOp::MerkleBuild, "merkle_build"},
    {BenchOp::MerkleVerify, "merkle_verify"},
    {BenchOp::MlKemKeygen, "mlkem_keygen"},
    {BenchOp::MlKemEncaps, "mlkem_encaps"},
    {BenchOp::MlKemDecaps, "mlkem_decaps"},
    {BenchOp::MlDsaKeygen, "mldsa_keygen"},
    {BenchOp::MlDsaSign, "mldsa_sign"},
    {BenchOp::MlDsaVerify, "mldsa_verify"},
};

[[noreturn]] void bad(const std::string& what) { throw VaultError(ErrorCode::InvalidArgument, "benchmark config: " + what); }

std::vector<std::size_t> size_list(const nlohmann::json& j, const char* key) {
    std::vector<std::size_t> out;
    if (!j.contains(key)) return out;
    if (!j[key].is_array()) bad(std::string(key) + " must be an array");
    for (const auto& v : j[key]) {
        if (!v.is_number_unsigned() || v.get<std::uint64_t>() == 0) bad(std::string(key) + " must contain positive integers");
        out.push_back(v.get<std::size_t>());
    }
    return out;
}

}  // namespace

std::string_view to_string(BenchOp op) noexcept {
    for (const auto& e : kOps)
        if (e.op == op) return e.name;
    return "?";
}

BenchConfig load_bench_config(const std::filesystem::path& json_path) {
    std::ifstream in(json_path);
    if (!in) throw VaultError(ErrorCode::Io, "cannot open benchmark config: " + json_path.string());
    nlohmann::json j = nlohmann::json::parse(in, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object()) bad("not a valid JSON object: " + json_path.string());

    BenchConfig cfg;
    if (!j.contains("ops") || !j["ops"].is_array() || j["ops"].empty()) bad("'ops' must be a non-empty array");
    for (const auto& o : j["ops"]) {
        bool found = false;
        if (o.is_string())
            for (const auto& e : kOps)
                if (e.name == o.get<std::string>()) {
                    cfg.ops.push_back(e.op);
                    found = true;
                }
        if (!found) bad("unknown op: " + o.dump());
    }

    unsigned threads = 0;
    if (j.contains("cpu_threads")) {
        if (!j["cpu_threads"].is_number_unsigned()) bad("'cpu_threads' must be a non-negative integer");
        threads = j["cpu_threads"].get<unsigned>();
    }
    nlohmann::json backends = j.contains("backends") ? j["backends"] : nlohmann::json::array({"cpu"});
    if (!backends.is_array() || backends.empty()) bad("'backends' must be a non-empty array");
    for (const auto& b : backends) {
        if (!b.is_string()) bad("backend names must be strings");
        crypto::BackendConfig bc;
        bc.kind = crypto::parse_backend_kind(b.get<std::string>());  // бросает InvalidArgument
        bc.cpu_threads = threads;
        cfg.backends.push_back(bc);
    }

    cfg.object_sizes = size_list(j, "object_sizes");
    cfg.object_counts = size_list(j, "object_counts");
    cfg.batch_sizes = size_list(j, "batch_sizes");
    bool needs_objects = false, needs_batches = false;
    for (BenchOp op : cfg.ops) {
        if (op == BenchOp::Sha3 || op == BenchOp::MerkleBuild || op == BenchOp::MerkleVerify) needs_objects = true;
        else needs_batches = true;
    }
    if (needs_objects && (cfg.object_sizes.empty() || cfg.object_counts.empty()))
        bad("object_sizes and object_counts are required for sha3/merkle ops");
    if (needs_batches && cfg.batch_sizes.empty()) bad("batch_sizes is required for ML-KEM/ML-DSA ops");

    if (j.contains("max_total_bytes")) {
        if (!j["max_total_bytes"].is_number_unsigned()) bad("'max_total_bytes' must be a non-negative integer");
        cfg.max_total_bytes = j["max_total_bytes"].get<std::size_t>();
    }
    auto runs = [&](const char* key, int& dst, int min) {
        if (!j.contains(key)) return;
        if (!j[key].is_number_integer() || j[key].get<int>() < min)
            bad(std::string("'") + key + "' must be an integer >= " + std::to_string(min));
        dst = j[key].get<int>();
    };
    runs("warmup_runs", cfg.warmup_runs, 0);
    runs("measured_runs", cfg.measured_runs, 1);
    if (j.contains("include_alloc_in_total")) {
        if (!j["include_alloc_in_total"].is_boolean()) bad("'include_alloc_in_total' must be a boolean");
        cfg.include_alloc_in_total = j["include_alloc_in_total"].get<bool>();
    }
    for (const char* key : {"output_csv", "output_json"}) {
        if (!j.contains(key)) continue;
        if (!j[key].is_string()) bad(std::string("'") + key + "' must be a string");
        (std::string(key) == "output_csv" ? cfg.output_csv : cfg.output_json) = j[key].get<std::string>();
    }
    return cfg;
}

}  // namespace vault::bench
