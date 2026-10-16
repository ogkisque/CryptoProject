// Benchmark framework (этап 4.5). Входы генерируются заранее и вне измерения; на каждый прогон —
// TimingBreakdown от backend'а, полное время total измеряется снаружи через steady_clock (§48).
#include "vault/bench/benchmark.hpp"

#include <algorithm>
#include <chrono>
#include <fstream>
#include <cstring>
#include <iomanip>
#include <optional>
#include <random>
#include <sstream>

#include <nlohmann/json.hpp>

#include "vault/common/error.hpp"
#include "vault/common/thread_pool.hpp"
#include "vault/merkle/merkle.hpp"

namespace vault::bench {

namespace {

using Clock = std::chrono::steady_clock;

constexpr std::size_t kDsaMessageSize = kManifestV1Size;  // в проекте подписывается только Manifest

struct Samples {
    std::vector<double> total, kernel, alloc, h2d, d2h, sync, entropy;
};

// Warm-up + measured_runs прогонов. body(timing) — один прогон операции.
template <typename Body>
Samples measure(const BenchConfig& cfg, Body&& body) {
    for (int i = 0; i < cfg.warmup_runs; ++i) {
        TimingBreakdown tb;
        body(tb);
    }
    Samples s;
    for (int i = 0; i < cfg.measured_runs; ++i) {
        TimingBreakdown tb;
        auto t0 = Clock::now();
        body(tb);
        double wall = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
        s.total.push_back(cfg.include_alloc_in_total ? wall : std::max(0.0, wall - tb.alloc_ms));
        s.kernel.push_back(tb.kernel_ms);
        s.alloc.push_back(tb.alloc_ms);
        s.h2d.push_back(tb.h2d_ms);
        s.d2h.push_back(tb.d2h_ms);
        s.sync.push_back(tb.sync_ms);
        s.entropy.push_back(tb.entropy_ms);
    }
    return s;
}

BenchRecord make_record(BenchOp op, const std::string& backend, std::size_t object_size, std::size_t count,
                        const Samples& s, double bytes_per_run) {
    BenchRecord r;
    r.op = op;
    r.backend = backend;
    r.object_size = object_size;
    r.count = count;
    r.total_ms = summarize(s.total);
    r.kernel_ms = summarize(s.kernel);
    r.alloc_ms = summarize(s.alloc);
    r.h2d_ms = summarize(s.h2d);
    r.d2h_ms = summarize(s.d2h);
    r.sync_ms = summarize(s.sync);
    r.entropy_ms = summarize(s.entropy);
    double sec = r.total_ms.median / 1e3;
    if (sec > 0) {
        r.throughput_gbps = bytes_per_run / sec / 1e9;
        r.ops_per_sec = static_cast<double>(count) / sec;
    }
    r.latency_ms = count ? r.total_ms.median / static_cast<double>(count) : 0;
    return r;
}

BenchRecord skipped_record(BenchOp op, const std::string& backend, std::size_t size, std::size_t count,
                           const std::string& reason) {
    BenchRecord r;
    r.op = op;
    r.backend = backend;
    r.object_size = size;
    r.count = count;
    r.skipped = true;
    r.skip_reason = reason;
    return r;
}

enum class Component { Hash, Merkle, Kem, Sig };

struct NamedBackend {
    std::string name;
    std::optional<crypto::CryptoBackends> backends;  // nullopt -> недоступен
    std::string unavailable_reason;
    bool is_gpu = false;
};

Bytes random_bytes(std::mt19937_64& g, std::size_t n) {
    Bytes b(n);
    std::size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        std::uint64_t v = g();
        std::memcpy(b.data() + i, &v, 8);
    }
    for (; i < n; ++i) b[i] = static_cast<std::uint8_t>(g());
    return b;
}

void require(bool ok, const char* what) {
    if (!ok) throw VaultError(ErrorCode::Internal, std::string("benchmark self-check failed: ") + what);
}

// Пара i из batch'а работает с reference: encaps(pk) -> decaps(sk) даёт тот же секрет.
bool kem_pair_works(crypto::IKemBackend& ref, const crypto::KemBatch& b, std::size_t i) {
    ByteView pk = ByteView(b.public_keys).subspan(i * kMlKem768PublicKeySize, kMlKem768PublicKeySize);
    ByteView sk = b.secret_keys.view().subspan(i * kMlKem768SecretKeySize, kMlKem768SecretKeySize);
    crypto::KemEncapsResult e = ref.encaps(pk, std::nullopt);
    return constant_time_equal(ref.decaps(sk, e.ciphertext).view(), e.shared_secret.view());
}

// Пара i из batch'а работает с reference: sign(sk) -> verify(pk).
bool sig_pair_works(crypto::ISigBackend& ref, const crypto::SigBatch& b, std::size_t i) {
    ByteView pk = ByteView(b.public_keys).subspan(i * kMlDsa65PublicKeySize, kMlDsa65PublicKeySize);
    ByteView sk = b.secret_keys.view().subspan(i * kMlDsa65SecretKeySize, kMlDsa65SecretKeySize);
    const Bytes msg = {'c', 'h', 'e', 'c', 'k'};
    Bytes sig = ref.sign(sk, msg, label::kManifestSigContext, std::nullopt);
    return ref.verify(pk, msg, label::kManifestSigContext, sig);
}

}  // namespace

std::vector<BenchRecord> run_benchmarks(const BenchConfig& cfg) { return run_benchmarks(cfg, {}); }

std::vector<BenchRecord> run_benchmarks(const BenchConfig& cfg, std::vector<BenchBackend> extra) {
    std::vector<NamedBackend> backs;
    for (std::size_t bi = 0; bi < cfg.backends.size(); ++bi) {
        const auto& bc = cfg.backends[bi];
        NamedBackend nb;
        nb.name = bi < cfg.backend_labels.size() ? cfg.backend_labels[bi] : std::string(crypto::to_string(bc.kind));
        nb.is_gpu = bc.kind == crypto::BackendKind::Gpu;
        try {
            nb.backends = crypto::make_backends(bc);
        } catch (const VaultError& e) {
            nb.unavailable_reason = e.what();
        }
        backs.push_back(std::move(nb));
    }
    for (auto& e : extra) backs.push_back(NamedBackend{std::move(e.name), std::move(e.backends), {}, e.is_gpu});
    crypto::CryptoBackends ref = crypto::make_backends({});  // подготовка входов — всегда на reference CPU
    std::mt19937_64 rng(0x5EEDB10C);
    // Context string ML-DSA для sign/verify: manifest (как в vault) или пустой (если backend не поддерживает ctx).
    const std::string_view dsa_ctx = cfg.mldsa_empty_context ? std::string_view{} : label::kManifestSigContext;
    std::vector<BenchRecord> out;

    auto for_each_backend = [&](BenchOp op, Component comp, std::size_t size, std::size_t count, auto&& run) {
        for (auto& nb : backs) {
            if (!nb.backends) {
                out.push_back(skipped_record(op, nb.name, size, count, "backend unavailable: " + nb.unavailable_reason));
                continue;
            }
            // GPU-набор может содержать CPU-реализацию компонента (например, нет cuPQC): такой замер
            // был бы CPU-замером под именем GPU, поэтому пропускается.
            if (nb.is_gpu) {
                std::string_view cn;
                switch (comp) {
                    case Component::Hash: cn = nb.backends->hash->name(); break;
                    case Component::Merkle: cn = nb.backends->merkle->name(); break;
                    case Component::Kem: cn = nb.backends->kem->name(); break;
                    case Component::Sig: cn = nb.backends->sig->name(); break;
                }
                if (cn != "gpu") {
                    out.push_back(skipped_record(op, nb.name, size, count, "no gpu implementation of this component (cpu fallback)"));
                    continue;
                }
            }
            // Backend может отказаться от конкретной операции (например, GPU ML-DSA без поддержки context
            // string): это пропуск точки, а не ошибка прогона. Ошибки самопроверки (Internal) остаются фатальными.
            try {
                out.push_back(run(nb));
            } catch (const VaultError& e) {
                if (e.code() != ErrorCode::BackendUnavailable) throw;
                out.push_back(skipped_record(op, nb.name, size, count, std::string("not supported by backend: ") + e.what()));
            }
        }
    };

    for (BenchOp op : cfg.ops) {
        if (op == BenchOp::MerkleVerify) {
            // Проверка proof'ов не читает сами объекты: стоимость зависит только от числа листьев.
            // Поэтому серия идёт по object_counts (object_size = 0), листья — случайные хеши, без
            // генерации гигабайтов данных. Пересчёт root по объектам измеряет merkle_build.
            for (std::size_t count : cfg.object_counts) {
                std::vector<Hash256> leaves(count);
                for (auto& l : leaves) {
                    Bytes r = random_bytes(rng, kHashSize);
                    std::copy(r.begin(), r.end(), l.begin());
                }
                merkle::MerkleTree tree = ref.merkle->build_tree(leaves, nullptr);
                std::vector<merkle::MerkleProof> proofs;
                proofs.reserve(count);
                for (std::size_t i = 0; i < count; ++i) proofs.push_back(merkle::make_proof(tree, i));
                for_each_backend(op, Component::Merkle, 0, count, [&](NamedBackend& nb) {
                    std::vector<std::uint8_t> ok(count);
                    Samples s = measure(cfg, [&](TimingBreakdown& tb) {
                        nb.backends->merkle->verify_proofs_batch(leaves, proofs, tree.root, ok, &tb);
                    });
                    require(std::all_of(ok.begin(), ok.end(), [](auto v) { return v == 1; }), "merkle proofs");
                    return make_record(op, nb.name, 0, count, s, 0);
                });
            }
            continue;
        }
        if (op == BenchOp::Sha3 || op == BenchOp::MerkleBuild) {
            for (std::size_t size : cfg.object_sizes)
                for (std::size_t count : cfg.object_counts) {
                    // Деление вместо умножения: без переполнения size_t.
                    if (count > cfg.max_total_bytes / size) {
                        for (auto& nb : backs) out.push_back(skipped_record(op, nb.name, size, count, "exceeds max_total_bytes"));
                        continue;
                    }
                    Bytes data = random_bytes(rng, size * count);
                    std::vector<ByteView> views;
                    views.reserve(count);
                    for (std::size_t i = 0; i < count; ++i) views.emplace_back(data.data() + i * size, size);
                    const double bytes = static_cast<double>(size) * static_cast<double>(count);
                    // Эталон для самопроверки: результат любого backend'а обязан совпасть с reference
                    // байт-в-байт (§42). Неверный результат = ошибка прогона, а не «быстрый» замер.
                    std::vector<Hash256> ref_leaves(count);
                    ref.merkle->compute_leaves(views, ref_leaves, nullptr);

                    if (op == BenchOp::Sha3) {
                        for_each_backend(op, Component::Hash, size, count, [&](NamedBackend& nb) {
                            std::vector<Hash256> out_h(count);
                            Samples s = measure(cfg, [&](TimingBreakdown& tb) {
                                nb.backends->hash->domain_hash_batch(domain::kMerkleLeaf, views, out_h, &tb);
                            });
                            require(out_h == ref_leaves, "SHA3 batch != reference");
                            return make_record(op, nb.name, size, count, s, bytes);
                        });
                    } else {
                        const Hash256 ref_root = ref.merkle->root_from_leaves(ref_leaves, nullptr);
                        for_each_backend(op, Component::Merkle, size, count, [&](NamedBackend& nb) {
                            std::vector<Hash256> leaves(count);
                            Hash256 root{};
                            Samples s = measure(cfg, [&](TimingBreakdown& tb) {
                                nb.backends->merkle->compute_leaves(views, leaves, &tb);
                                root = nb.backends->merkle->root_from_leaves(leaves, &tb);
                            });
                            require(leaves == ref_leaves && root == ref_root, "Merkle leaves/root != reference");
                            return make_record(op, nb.name, size, count, s, bytes);
                        });
                    }
                }
            continue;
        }

        // ML-KEM / ML-DSA: batch_sizes
        for (std::size_t batch : cfg.batch_sizes) {
            const bool kem = op == BenchOp::MlKemKeygen || op == BenchOp::MlKemEncaps || op == BenchOp::MlKemDecaps;
            if (kem) {
                crypto::KemBatch prep;
                if (op != BenchOp::MlKemKeygen) {
                    ref.kem->keygen_batch(batch, std::nullopt, prep, nullptr);
                    if (op == BenchOp::MlKemDecaps) ref.kem->encaps_batch(prep, std::nullopt, nullptr);
                }
                for_each_backend(op, Component::Kem, 0, batch, [&](NamedBackend& nb) {
                    crypto::KemBatch kb;
                    Samples s;
                    if (op == BenchOp::MlKemKeygen) {
                        s = measure(cfg, [&](TimingBreakdown& tb) { nb.backends->kem->keygen_batch(batch, std::nullopt, kb, &tb); });
                        // Ключи backend'а работоспособны: reference encaps -> reference decaps.
                        require(kb.count == batch && kem_pair_works(*ref.kem, kb, 0) && kem_pair_works(*ref.kem, kb, batch - 1),
                                "ML-KEM keygen: keys do not work with reference");
                    } else if (op == BenchOp::MlKemEncaps) {
                        s = measure(cfg, [&](TimingBreakdown& tb) { nb.backends->kem->encaps_batch(prep, std::nullopt, &tb); });
                        // Reference decaps ciphertext'ов backend'а даёт те же секреты.
                        crypto::KemBatch chk;
                        chk.count = prep.count;
                        chk.secret_keys = prep.secret_keys.clone();
                        chk.ciphertexts = prep.ciphertexts;
                        ref.kem->decaps_batch(chk, nullptr);
                        require(constant_time_equal(chk.shared_secrets.view(), prep.shared_secrets.view()),
                                "ML-KEM encaps: reference decaps disagrees");
                    } else {
                        Bytes expected(prep.shared_secrets.view().begin(), prep.shared_secrets.view().end());
                        s = measure(cfg, [&](TimingBreakdown& tb) { nb.backends->kem->decaps_batch(prep, &tb); });
                        require(Bytes(prep.shared_secrets.view().begin(), prep.shared_secrets.view().end()) == expected,
                                "ML-KEM decaps != encaps");
                    }
                    return make_record(op, nb.name, 0, batch, s, 0);
                });
            } else {
                crypto::SigBatch prep;
                if (op != BenchOp::MlDsaKeygen) {
                    ref.sig->keygen_batch(batch, std::nullopt, prep, nullptr);
                    prep.message_size = kDsaMessageSize;
                    prep.messages = random_bytes(rng, batch * kDsaMessageSize);
                    if (op == BenchOp::MlDsaVerify) ref.sig->sign_batch(prep, dsa_ctx, std::nullopt, nullptr);
                }
                for_each_backend(op, Component::Sig, op == BenchOp::MlDsaKeygen ? 0 : kDsaMessageSize, batch, [&](NamedBackend& nb) {
                    crypto::SigBatch sb;
                    Samples s;
                    if (op != BenchOp::MlDsaKeygen) {
                        // Разовая подготовка backend'а вне замеров: GPU ML-DSA при первом sign/verify калибрует режим
                        // context string (CPU keygen + GPU sign/verify). При warmup_runs = 0 она попала бы в первый
                        // замер. Одиночная проверка заведомо неверной подписи — дешёвый способ её вызвать.
                        const Bytes zero_sig(kMlDsa65SignatureSize, 0);
                        (void)nb.backends->sig->verify(ByteView(prep.public_keys).subspan(0, kMlDsa65PublicKeySize),
                                                       ByteView(prep.messages).subspan(0, kDsaMessageSize), dsa_ctx, zero_sig);
                    }
                    if (op == BenchOp::MlDsaKeygen) {
                        s = measure(cfg, [&](TimingBreakdown& tb) { nb.backends->sig->keygen_batch(batch, std::nullopt, sb, &tb); });
                        require(sb.count == batch && sig_pair_works(*ref.sig, sb, 0) && sig_pair_works(*ref.sig, sb, batch - 1),
                                "ML-DSA keygen: keys do not work with reference");
                    } else if (op == BenchOp::MlDsaSign) {
                        s = measure(cfg, [&](TimingBreakdown& tb) {
                            nb.backends->sig->sign_batch(prep, dsa_ctx, std::nullopt, &tb);
                        });
                        // Все подписи backend'а проходят reference verify.
                        crypto::SigBatch chk;
                        chk.count = prep.count;
                        chk.message_size = prep.message_size;
                        chk.public_keys = prep.public_keys;
                        chk.messages = prep.messages;
                        chk.signatures = prep.signatures;
                        ref.sig->verify_batch(chk, dsa_ctx, nullptr);
                        require(std::all_of(chk.verify_ok.begin(), chk.verify_ok.end(), [](auto v) { return v == 1; }),
                                "ML-DSA sign: reference verify rejects signatures");
                    } else {
                        s = measure(cfg, [&](TimingBreakdown& tb) { nb.backends->sig->verify_batch(prep, dsa_ctx, &tb); });
                        require(std::all_of(prep.verify_ok.begin(), prep.verify_ok.end(), [](auto v) { return v == 1; }),
                                "ML-DSA signatures");
                    }
                    return make_record(op, nb.name, op == BenchOp::MlDsaKeygen ? 0 : kDsaMessageSize, batch, s, 0);
                });
            }
        }
    }
    return out;
}

namespace {

void open_for_write(std::ofstream& f, const std::filesystem::path& path) {
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path());
    f.open(path, std::ios::trunc);
    if (!f) throw VaultError(ErrorCode::Io, "cannot write " + path.string());
}

std::string csv_quote(const std::string& s) {
    std::string o = "\"";
    for (char c : s) o += c == '"' ? "\"\"" : std::string(1, c);
    return o + "\"";
}

nlohmann::json summary_json(const Summary& s) {
    return {{"n", s.n}, {"mean", s.mean}, {"median", s.median}, {"min", s.min}, {"max", s.max}, {"stddev", s.stddev}};
}

}  // namespace

void write_csv(const std::filesystem::path& path, const std::vector<BenchRecord>& records) {
    std::ofstream f;
    open_for_write(f, path);
    f << std::setprecision(10);
    f << "op,backend,object_size,count,skipped,skip_reason,n,"
         "total_mean_ms,total_median_ms,total_min_ms,total_max_ms,total_stddev_ms,"
         "kernel_median_ms,alloc_median_ms,h2d_median_ms,d2h_median_ms,sync_median_ms,entropy_median_ms,"
         "kernel_mean_ms,alloc_mean_ms,h2d_mean_ms,d2h_mean_ms,sync_mean_ms,entropy_mean_ms,"
         "throughput_gbps,ops_per_sec,latency_ms\n";
    for (const auto& r : records) {
        f << to_string(r.op) << ',' << r.backend << ',' << r.object_size << ',' << r.count << ',' << (r.skipped ? 1 : 0)
          << ',' << csv_quote(r.skip_reason) << ',' << r.total_ms.n << ',' << r.total_ms.mean << ',' << r.total_ms.median
          << ',' << r.total_ms.min << ',' << r.total_ms.max << ',' << r.total_ms.stddev << ',' << r.kernel_ms.median << ','
          << r.alloc_ms.median << ',' << r.h2d_ms.median << ',' << r.d2h_ms.median << ',' << r.sync_ms.median << ',' << r.entropy_ms.median << ','
          << r.kernel_ms.mean << ',' << r.alloc_ms.mean << ',' << r.h2d_ms.mean << ',' << r.d2h_ms.mean << ','
          << r.sync_ms.mean << ',' << r.entropy_ms.mean << ',' << r.throughput_gbps << ',' << r.ops_per_sec << ',' << r.latency_ms << '\n';
    }
    if (!f) throw VaultError(ErrorCode::Io, "write failed: " + path.string());
}

void write_json(const std::filesystem::path& path, const SystemInfo& info, const BenchConfig& cfg,
                const std::vector<BenchRecord>& records) {
    using nlohmann::json;
    json j;
    j["system"] = {{"timestamp_utc", info.timestamp_utc}, {"hostname", info.hostname}, {"os", info.os},
                   {"cpu_model", info.cpu_model}, {"cpu_threads", info.cpu_threads}, {"gpu_model", info.gpu_model},
                   {"gpu_arch", info.gpu_arch}, {"gpu_memory", info.gpu_memory},
                   {"cuda_runtime_version", info.cuda_runtime_version}, {"cuda_driver_version", info.cuda_driver_version},
                   {"cupqc_version", info.cupqc_version}, {"openssl_version", info.openssl_version},
                   {"liboqs_version", info.liboqs_version}, {"compiler", info.compiler},
                   {"compiler_flags", info.compiler_flags}, {"cuda_flags", info.cuda_flags},
                   {"build_type", info.build_type}, {"git_commit", info.git_commit}};
    json ops = json::array(), backends = json::array();
    for (BenchOp op : cfg.ops) ops.push_back(std::string(to_string(op)));
    json backend_options = json::array();
    for (std::size_t i = 0; i < cfg.backends.size(); ++i) {
        const auto& b = cfg.backends[i];
        backends.push_back(i < cfg.backend_labels.size() ? cfg.backend_labels[i] : std::string(crypto::to_string(b.kind)));
        json o = {{"kind", std::string(crypto::to_string(b.kind))}};
        if (b.kind == crypto::BackendKind::CpuParallel) o["threads"] = resolve_thread_count(b.cpu_threads);
        if (b.kind == crypto::BackendKind::Gpu)
            o.update({{"cuda_device", b.cuda_device}, {"pinned_host_memory", b.pinned_host_memory},
                      {"double_buffering", b.gpu_double_buffering}, {"pool_buffers", b.gpu_pool_buffers},
                      {"strategy", b.gpu_hash_strategy == gpu::GpuHashStrategy::WarpPerObject ? "warp" : "thread"},
                      {"max_chunk_bytes", b.gpu_max_chunk_bytes}, {"merkle_cpu_threshold", b.gpu_merkle_cpu_threshold}});
        backend_options.push_back(std::move(o));
    }
    j["config"] = {{"ops", ops}, {"backends", backends}, {"backend_options", backend_options}, {"object_sizes", cfg.object_sizes},
                   {"object_counts", cfg.object_counts}, {"batch_sizes", cfg.batch_sizes},
                   {"cpu_threads", cfg.backends.empty() ? 0u : resolve_thread_count(cfg.backends.front().cpu_threads)},
                   {"max_total_bytes", cfg.max_total_bytes}, {"mldsa_context", cfg.mldsa_empty_context ? "empty" : "manifest"}, {"warmup_runs", cfg.warmup_runs},
                   {"measured_runs", cfg.measured_runs}, {"include_alloc_in_total", cfg.include_alloc_in_total}};
    json recs = json::array();
    for (const auto& r : records) {
        recs.push_back({{"op", std::string(to_string(r.op))}, {"backend", r.backend}, {"object_size", r.object_size},
                        {"count", r.count}, {"skipped", r.skipped}, {"skip_reason", r.skip_reason},
                        {"total_ms", summary_json(r.total_ms)}, {"kernel_ms", summary_json(r.kernel_ms)},
                        {"alloc_ms", summary_json(r.alloc_ms)}, {"h2d_ms", summary_json(r.h2d_ms)},
                        {"d2h_ms", summary_json(r.d2h_ms)}, {"sync_ms", summary_json(r.sync_ms)},
                        {"entropy_ms", summary_json(r.entropy_ms)},
                        {"throughput_gbps", r.throughput_gbps}, {"ops_per_sec", r.ops_per_sec},
                        {"latency_ms", r.latency_ms}});
    }
    j["records"] = recs;
    std::ofstream f;
    open_for_write(f, path);
    f << j.dump(2) << '\n';
    if (!f) throw VaultError(ErrorCode::Io, "write failed: " + path.string());
}

}  // namespace vault::bench
