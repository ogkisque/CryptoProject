// Формат не зависит от backend'а (§41): хранилище, созданное одним backend'ом, читается другим.
#include <gtest/gtest.h>

#include "vault/common/error.hpp"
#include "test_util.hpp"

using namespace vault;
using namespace vault::testing;

class BackendVaultTest : public VaultFixture {
protected:
    static crypto::CryptoBackends make(crypto::BackendKind k, unsigned threads = 3) {
        crypto::BackendConfig c;
        c.kind = k;
        c.cpu_threads = threads;
        return crypto::make_backends(c);
    }
};

TEST_F(BackendVaultTest, CpuAndCpuMtInterchangeable) {
    Vault::init(paths(), make(crypto::BackendKind::Cpu));
    FileId a, b;
    {
        Vault v = Vault::open(paths(), make(crypto::BackendKind::CpuParallel));  // MT открывает хранилище cpu
        a = v.add_bytes("a", Bytes(100, 1));
        for (int i = 0; i < 40; ++i) v.add_bytes("f" + std::to_string(i), Bytes(10 + i, 2));  // нечётное и большое число листьев
    }
    {
        Vault v = Vault::open(paths(), make(crypto::BackendKind::Cpu));  // cpu открывает то, что писал MT
        EXPECT_EQ(v.state().objects.size(), 41u);
        EXPECT_EQ(v.extract(a).data.size(), 100u);
        b = v.add_bytes("b", Bytes(5, 3));
    }
    // Один и тот же диск даёт идентичные Manifest и листья при любом backend'е.
    auto r1 = Vault::verify_state(paths(), make(crypto::BackendKind::Cpu));
    auto r2 = Vault::verify_state(paths(), make(crypto::BackendKind::CpuParallel, 5));
    EXPECT_EQ(r1.state.manifest, r2.state.manifest);
    EXPECT_EQ(r1.state.manifest_hash, r2.state.manifest_hash);
    EXPECT_EQ(r1.state.leaves, r2.state.leaves);
    EXPECT_EQ(r1.state.objects.size(), 42u);
    (void)b;
}

TEST_F(BackendVaultTest, GpuBackendUnavailableWithoutCuda) {
    if (crypto::gpu_backend_compiled()) GTEST_SKIP() << "built with CUDA";
    crypto::BackendConfig c;
    c.kind = crypto::BackendKind::Gpu;
    try {
        crypto::make_backends(c);
        FAIL();
    } catch (const VaultError& e) {
        EXPECT_EQ(e.code(), ErrorCode::BackendUnavailable);
    }
}

TEST_F(BackendVaultTest, ProfileIsFilledForOperations) {
    Vault::init(paths(), make(crypto::BackendKind::Cpu));
    Vault v = Vault::open(paths(), make(crypto::BackendKind::Cpu));
    FileId id = v.add_bytes("a", Bytes(1 << 20, 7));
    const PhaseProfile& add = v.last_profile();
    EXPECT_GT(add[Phase::Algorithm], 0);
    EXPECT_GT(add[Phase::Serialization], 0);
    EXPECT_GT(add[Phase::Filesystem], 0);
    EXPECT_GE(add[Phase::MemoryCopy], 0);
    EXPECT_GT(v.open_profile()[Phase::Filesystem], 0);
    v.extract(id);
    EXPECT_GT(v.last_profile()[Phase::Algorithm], 0);
    EXPECT_EQ(v.last_profile()[Phase::Filesystem], 0);  // extract работает по проверенному состоянию в памяти
}
