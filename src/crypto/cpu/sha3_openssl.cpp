#include <openssl/evp.h>

#include <memory>

#include "vault/common/error.hpp"
#include "vault/crypto/cpu_backends.hpp"

namespace vault::crypto {

namespace {

class CpuHashBackend final : public IHashBackend {
public:
    std::string_view name() const override { return "cpu"; }

    Hash256 sha3_256(ByteView data) override { return hash(nullptr, data); }

    Hash256 domain_hash(std::uint8_t domain, ByteView data) override { return hash(&domain, data); }

    void sha3_256_batch(std::span<const ByteView> inputs, std::span<Hash256> out,
                        TimingBreakdown* timing) override {
        run_batch(nullptr, inputs, out, timing);
    }

    void domain_hash_batch(std::uint8_t domain, std::span<const ByteView> inputs,
                           std::span<Hash256> out, TimingBreakdown* timing) override {
        run_batch(&domain, inputs, out, timing);
    }

private:
    static Hash256 hash(const std::uint8_t* domain, ByteView data) {
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        Hash256 out{};
        unsigned int len = 0;
        if (!ctx || EVP_DigestInit_ex(ctx.get(), EVP_sha3_256(), nullptr) != 1 ||
            (domain && EVP_DigestUpdate(ctx.get(), domain, 1) != 1) ||
            (!data.empty() && EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) ||
            EVP_DigestFinal_ex(ctx.get(), out.data(), &len) != 1 || len != kHashSize)
            throw VaultError(ErrorCode::CryptoError, "SHA3-256 failed");
        return out;
    }

    void run_batch(const std::uint8_t* domain, std::span<const ByteView> inputs, std::span<Hash256> out,
                   TimingBreakdown* timing) {
        if (out.size() != inputs.size())
            throw VaultError(ErrorCode::InvalidArgument, "batch size mismatch");
        auto t0 = std::chrono::steady_clock::now();
        for (std::size_t i = 0; i < inputs.size(); ++i) out[i] = hash(domain, inputs[i]);
        if (timing) {
            double ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
            timing->kernel_ms += ms;
            timing->total_ms += ms;
        }
    }
};

}  // namespace

// threads пока игнорируется (M4: CpuParallel).
std::shared_ptr<IHashBackend> make_cpu_hash_backend(unsigned) { return std::make_shared<CpuHashBackend>(); }

}  // namespace vault::crypto
