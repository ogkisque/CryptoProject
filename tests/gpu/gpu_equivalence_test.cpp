// CPU == GPU (этап 5, §42): SHA3-256, Merkle, proof batch и `vault verify --backend gpu`.
// Без CUDA-устройства (или без CUDA в сборке) каждый тест делает GTEST_SKIP. Reference — CPU backend.
// При расхождении печатается ПЕРВЫЙ несовпавший элемент (индекс, длина входа, оба хеша).
#include <gtest/gtest.h>
#include <sys/wait.h>

#include <algorithm>
#include <random>

#include "vault/common/error.hpp"
#include "vault/crypto/backends.hpp"
#include "vault/merkle/merkle.hpp"
#include "../integration/test_util.hpp"

using namespace vault;
using namespace vault::testing;

namespace {

Bytes rand_bytes(std::mt19937_64& g, std::size_t n) {
    Bytes b(n);
    for (auto& x : b) x = static_cast<std::uint8_t>(g());
    return b;
}

std::optional<crypto::CryptoBackends> try_gpu(crypto::BackendConfig cfg, std::string* why) {
    cfg.kind = crypto::BackendKind::Gpu;
    try {
        return crypto::make_backends(cfg);
    } catch (const VaultError& e) {
        if (e.code() != ErrorCode::BackendUnavailable) throw;
        if (why) *why = e.what();
        return std::nullopt;
    }
}

// Сравнение двух массивов хешей с подробным сообщением о первом расхождении.
::testing::AssertionResult same_hashes(const std::vector<Hash256>& cpu, const std::vector<Hash256>& gpu,
                                       const std::vector<ByteView>& inputs, const char* what) {
    if (cpu.size() != gpu.size()) return ::testing::AssertionFailure() << what << ": size mismatch";
    for (std::size_t i = 0; i < cpu.size(); ++i)
        if (cpu[i] != gpu[i])
            return ::testing::AssertionFailure() << what << ": first mismatch at index " << i << ", input length "
                                                 << (i < inputs.size() ? inputs[i].size() : 0) << "\n  cpu: " << to_hex(as_view(cpu[i]))
                                                 << "\n  gpu: " << to_hex(as_view(gpu[i]));
    return ::testing::AssertionSuccess();
}

}  // namespace

class GpuEquivalence : public VaultFixture {
protected:
    void SetUp() override {
        VaultFixture::SetUp();
        std::string why;
        auto g = try_gpu({}, &why);
        if (!g) GTEST_SKIP() << "no GPU backend: " << why;
        gpu = std::move(*g);
        cpu = crypto::make_backends({});
        rng.seed(77);
    }
    crypto::CryptoBackends gpu, cpu;
    std::mt19937_64 rng;
};

TEST_F(GpuEquivalence, Sha3KnownAnswers) {
    Bytes a3(200, 0xA3);
    Bytes empty, abc = {'a', 'b', 'c'};
    std::vector<ByteView> in = {empty, abc, a3};
    std::vector<Hash256> out(3);
    gpu.hash->sha3_256_batch(in, out, nullptr);
    EXPECT_EQ(to_hex(as_view(out[0])), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    EXPECT_EQ(to_hex(as_view(out[1])), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
    EXPECT_EQ(to_hex(as_view(out[2])), "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787");
}

TEST_F(GpuEquivalence, Sha3RandomLengthsAndRateBoundaries) {
    std::vector<std::size_t> lens;
    for (std::size_t n = 0; n <= 700; ++n) lens.push_back(n);
    for (std::size_t n : {1000u, 1359u, 1360u, 1361u, 4096u, 10000u, 65536u, 1u << 20}) lens.push_back(n);
    std::vector<Bytes> objs;
    for (std::size_t n : lens) objs.push_back(rand_bytes(rng, n));
    std::vector<ByteView> in(objs.begin(), objs.end());
    for (std::uint8_t dom : {std::uint8_t{0x00}, std::uint8_t{0x01}, std::uint8_t{0x11}}) {
        std::vector<Hash256> a(in.size()), b(in.size());
        cpu.hash->domain_hash_batch(dom, in, a, nullptr);
        gpu.hash->domain_hash_batch(dom, in, b, nullptr);
        EXPECT_TRUE(same_hashes(a, b, in, "domain_hash_batch")) << "domain " << int{dom};
    }
    std::vector<Hash256> a(in.size()), b(in.size());
    cpu.hash->sha3_256_batch(in, a, nullptr);
    gpu.hash->sha3_256_batch(in, b, nullptr);
    EXPECT_TRUE(same_hashes(a, b, in, "sha3_256_batch"));
    // одиночные вызовы
    EXPECT_EQ(cpu.hash->domain_hash(0x12, as_view("x")), gpu.hash->domain_hash(0x12, as_view("x")));
}

TEST_F(GpuEquivalence, AllStrategiesAndTransferModesGiveSameHashes) {
    // Малые порции (1 MiB) заставляют разбить batch на много порций, включая объект больше порции.
    std::vector<Bytes> objs;
    for (int i = 0; i < 300; ++i) objs.push_back(rand_bytes(rng, rng() % 20000));
    objs[100] = rand_bytes(rng, 3u << 20);  // больше порции
    std::vector<ByteView> in(objs.begin(), objs.end());
    std::vector<Hash256> ref(in.size());
    cpu.hash->domain_hash_batch(0x00, in, ref, nullptr);

    for (auto strategy : {gpu::GpuHashStrategy::ThreadPerObject, gpu::GpuHashStrategy::WarpPerObject})
        for (bool pinned : {true, false})
            for (bool dbl : {false, true})
                for (bool pool : {false, true}) {
                    crypto::BackendConfig c;
                    c.gpu_hash_strategy = strategy;
                    c.pinned_host_memory = pinned;
                    c.gpu_double_buffering = dbl;
                    c.gpu_pool_buffers = pool;
                    c.gpu_max_chunk_bytes = 1u << 20;
                    auto g = try_gpu(c, nullptr);
                    ASSERT_TRUE(g.has_value());
                    std::vector<Hash256> out(in.size());
                    for (int rep = 0; rep < 2; ++rep) {  // повторный вызов проверяет переиспользование/освобождение буферов
                        g->hash->domain_hash_batch(0x00, in, out, nullptr);
                        EXPECT_TRUE(same_hashes(ref, out, in, "chunked batch"))
                            << "strategy=" << (strategy == gpu::GpuHashStrategy::WarpPerObject ? "warp" : "thread")
                            << " pinned=" << pinned << " double_buffering=" << dbl << " pool=" << pool << " rep=" << rep;
                    }
                }
}

TEST_F(GpuEquivalence, BatchEdgeCasesAndTimingBreakdown) {
    std::vector<Hash256> none;
    gpu.hash->sha3_256_batch({}, none, nullptr);  // пустой batch допустим
    std::vector<Hash256> wrong(1);
    EXPECT_THROW(gpu.hash->sha3_256_batch({}, wrong, nullptr), VaultError);  // несовпадение размеров

    std::vector<Bytes> objs(64, Bytes(4096, 7));
    std::vector<ByteView> in(objs.begin(), objs.end());
    std::vector<Hash256> out(in.size());
    TimingBreakdown tb;
    gpu.hash->domain_hash_batch(0x00, in, out, &tb);
    EXPECT_GT(tb.total_ms, 0.0);
    EXPECT_GT(tb.kernel_ms, 0.0);
    EXPECT_GT(tb.h2d_ms, 0.0);
    EXPECT_GT(tb.d2h_ms, 0.0);
    EXPECT_GT(tb.alloc_ms, 0.0);  // по умолчанию буферы выделяются на каждый вызов
    EXPECT_GE(tb.total_ms, tb.kernel_ms);
}

TEST_F(GpuEquivalence, MerkleLeavesRootAndTreeForN0To1000) {
    for (std::size_t n : {0u, 1u, 2u, 3u, 4u, 5u, 7u, 8u, 9u, 15u, 16u, 17u, 31u, 33u, 100u, 255u, 256u, 257u, 1000u}) {
        std::vector<Bytes> objs;
        for (std::size_t i = 0; i < n; ++i) objs.push_back(rand_bytes(rng, 1 + rng() % 300));
        std::vector<ByteView> in(objs.begin(), objs.end());
        std::vector<Hash256> la(n), lb(n);
        cpu.merkle->compute_leaves(in, la, nullptr);
        gpu.merkle->compute_leaves(in, lb, nullptr);
        ASSERT_TRUE(same_hashes(la, lb, in, "leaves")) << "N=" << n;
        EXPECT_EQ(cpu.merkle->root_from_leaves(la, nullptr), gpu.merkle->root_from_leaves(lb, nullptr)) << "N=" << n;
        auto ta = cpu.merkle->build_tree(la, nullptr), tb = gpu.merkle->build_tree(lb, nullptr);
        EXPECT_EQ(ta.root, tb.root) << "N=" << n;
        EXPECT_EQ(ta.levels, tb.levels) << "N=" << n;
    }
}

TEST_F(GpuEquivalence, MerkleAllLevelsOnGpuAndHugeLeafCount) {
    for (std::size_t threshold : {std::size_t{0}, std::size_t{1}, std::size_t{4}, std::size_t{1024}}) {
        crypto::BackendConfig c;
        c.gpu_merkle_cpu_threshold = threshold;
        auto g = try_gpu(c, nullptr);
        ASSERT_TRUE(g.has_value());
        for (std::size_t n : {1u, 2u, 3u, 1000u, 4097u, 100000u}) {
            std::vector<Hash256> leaves(n);
            for (auto& l : leaves) {
                Bytes r = rand_bytes(rng, 32);
                std::copy(r.begin(), r.end(), l.begin());
            }
            EXPECT_EQ(cpu.merkle->root_from_leaves(leaves, nullptr), g->merkle->root_from_leaves(leaves, nullptr))
                << "N=" << n << " threshold=" << threshold;
        }
    }
}

TEST_F(GpuEquivalence, ProofBatchesMatchCpuIncludingCorruptions) {
    for (std::size_t n : {1u, 2u, 7u, 1000u, 100000u}) {
        std::vector<Hash256> leaves(n);
        for (auto& l : leaves) {
            Bytes r = rand_bytes(rng, 32);
            std::copy(r.begin(), r.end(), l.begin());
        }
        merkle::MerkleTree tree = cpu.merkle->build_tree(leaves, nullptr);
        std::vector<merkle::MerkleProof> proofs;
        for (std::size_t i = 0; i < n; ++i) proofs.push_back(merkle::make_proof(tree, i));
        std::vector<std::uint8_t> ok_cpu(n), ok_gpu(n);
        gpu.merkle->verify_proofs_batch(leaves, proofs, tree.root, ok_gpu, nullptr);
        EXPECT_EQ(std::count(ok_gpu.begin(), ok_gpu.end(), 1), static_cast<long>(n)) << "N=" << n;

        // порча: лист, сосед, вид шага, индекс
        std::vector<Hash256> bad_leaves = leaves;
        bad_leaves[n / 2][0] ^= 1;
        if (!proofs[0].steps.empty() && proofs[0].steps[0].kind != merkle::ProofStep::Kind::Unpaired) proofs[0].steps[0].sibling[5] ^= 1;
        proofs[n - 1].leaf_index = n;  // вне диапазона
        cpu.merkle->verify_proofs_batch(bad_leaves, proofs, tree.root, ok_cpu, nullptr);
        gpu.merkle->verify_proofs_batch(bad_leaves, proofs, tree.root, ok_gpu, nullptr);
        EXPECT_EQ(ok_cpu, ok_gpu) << "N=" << n;
        EXPECT_EQ(ok_gpu[n - 1], 0);
        EXPECT_EQ(ok_gpu[n / 2], 0);
    }
}

TEST_F(GpuEquivalence, UnavailableDeviceGivesReadableError) {
    crypto::BackendConfig c;
    c.kind = crypto::BackendKind::Gpu;
    c.cuda_device = 99;
    try {
        crypto::make_backends(c);
        FAIL();
    } catch (const VaultError& e) {
        EXPECT_EQ(e.code(), ErrorCode::BackendUnavailable);
        EXPECT_NE(std::string(e.what()).find("99"), std::string::npos) << e.what();
    }
}

// --- vault verify --backend gpu ---

class GpuVaultCli : public GpuEquivalence {
protected:
    int run(const std::string& args) {
        std::string cmd = "cd '" + root.string() + "' && '" VAULT_CLI_PATH "' --vault vault --trusted trusted " + args +
                          " >out.txt 2>err.txt";
        int st = std::system(cmd.c_str());
        return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
    }
    std::string text(const std::string& name) {
        Bytes b = slurp(root / name);
        return std::string(b.begin(), b.end());
    }
    FileId state_first_file() { return Vault::verify_state(paths(), crypto::make_backends({})).state.objects.front().file_id; }
};

TEST_F(GpuVaultCli, VerifyCleanAndTamperedGiveSameResultAsCpu) {
    ASSERT_EQ(run("init"), 0);
    for (int i = 0; i < 5; ++i) {
        spit(root / "in.txt", rand_bytes(rng, 1000 + 777 * i));
        ASSERT_EQ(run("add in.txt"), 0);
    }
    ASSERT_EQ(run("--backend cpu verify"), 0);
    ASSERT_EQ(run("--backend gpu verify"), 0) << text("err.txt");
    EXPECT_EQ(text("out.txt"), "VALID\n");

    // Порча ciphertext в текущем поколении -> тот же VerifyStep на обоих backend'ах.
    FileId some = state_first_file();
    Bytes obj = slurp(object_path(some));
    obj[120] ^= 1;
    spit(object_path(some), obj);
    EXPECT_EQ(run("--backend cpu verify"), 2);
    const std::string cpu_err = text("err.txt");
    EXPECT_EQ(run("--backend gpu verify"), 2);
    const std::string gpu_err = text("err.txt");
    EXPECT_NE(cpu_err.find("INVALID: MerkleRoot"), std::string::npos) << cpu_err;
    EXPECT_NE(gpu_err.find("INVALID: MerkleRoot"), std::string::npos) << gpu_err;
}

TEST_F(GpuVaultCli, VaultsAreInterchangeableBetweenCpuAndGpu) {
    ASSERT_EQ(run("--backend gpu init"), 0);
    spit(root / "in.txt", rand_bytes(rng, 5000));
    ASSERT_EQ(run("--backend gpu add in.txt"), 0) << text("err.txt");
    std::string id = text("out.txt").substr(0, 32);
    EXPECT_EQ(run("--backend cpu verify"), 0);
    ASSERT_EQ(run("--backend cpu add in.txt"), 0);
    EXPECT_EQ(run("--backend gpu verify"), 0);
    EXPECT_EQ(run("--backend gpu extract " + id + " -o res.bin"), 0);
    EXPECT_EQ(slurp(root / "res.bin"), slurp(root / "in.txt"));
    auto r1 = Vault::verify_state(paths(), crypto::make_backends({}));
    crypto::BackendConfig c;
    c.kind = crypto::BackendKind::Gpu;
    auto r2 = Vault::verify_state(paths(), crypto::make_backends(c));
    EXPECT_EQ(r1.state.manifest_hash, r2.state.manifest_hash);
    EXPECT_EQ(r1.state.leaves, r2.state.leaves);
}
