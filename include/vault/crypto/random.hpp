#pragma once
// Источник случайности. Production — CSPRNG (OpenSSL RAND_bytes).
// Интерфейс нужен для детерминированных тестов (фиксированные file_id/nonce).

#include <memory>

#include "vault/common/bytes.hpp"

namespace vault::crypto {

class IRandom {
public:
    virtual ~IRandom() = default;
    virtual void fill(MutableByteView out) = 0;
};

std::unique_ptr<IRandom> make_system_random();
// ТОЛЬКО для тестов: детерминированный поток из seed (например, SHAKE256(seed)).
std::unique_ptr<IRandom> make_deterministic_random_for_tests(ByteView seed);

}  // namespace vault::crypto
