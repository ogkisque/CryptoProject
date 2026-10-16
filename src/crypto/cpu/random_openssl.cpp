#include <openssl/evp.h>
#include <openssl/rand.h>

#include <memory>

#include "vault/common/error.hpp"
#include "vault/crypto/random.hpp"

namespace vault::crypto {

namespace {

class SystemRandom final : public IRandom {
public:
    void fill(MutableByteView out) override {
        if (out.empty()) return;
        if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1)
            throw VaultError(ErrorCode::CryptoError, "RAND_bytes failed");
    }
};

// Только для тестов: SHAKE256(seed || counter) -> поток байт.
class DeterministicRandom final : public IRandom {
public:
    explicit DeterministicRandom(ByteView seed) : seed_(seed.begin(), seed.end()) {}
    void fill(MutableByteView out) override {
        if (out.empty()) return;
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
        std::uint8_t ctr[8];
        for (int i = 0; i < 8; ++i) ctr[i] = static_cast<std::uint8_t>(counter_ >> (56 - 8 * i));
        ++counter_;
        if (EVP_DigestInit_ex(ctx.get(), EVP_shake256(), nullptr) != 1 ||
            EVP_DigestUpdate(ctx.get(), seed_.data(), seed_.size()) != 1 ||
            EVP_DigestUpdate(ctx.get(), ctr, 8) != 1 ||
            EVP_DigestFinalXOF(ctx.get(), out.data(), out.size()) != 1)
            throw VaultError(ErrorCode::CryptoError, "SHAKE256 failed");
    }

private:
    Bytes seed_;
    std::uint64_t counter_ = 0;
};

}  // namespace

std::unique_ptr<IRandom> make_system_random() { return std::make_unique<SystemRandom>(); }

std::unique_ptr<IRandom> make_deterministic_random_for_tests(ByteView seed) {
    return std::make_unique<DeterministicRandom>(seed);
}

}  // namespace vault::crypto
