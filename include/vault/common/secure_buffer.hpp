#pragma once
// Буферы для секретов (SK_KEM, SK_SIG, K_MLKEM, KEK, DEK, plaintext).
// Гарантируют обнуление при уничтожении/перемещении «насколько позволяет
// платформа» (§7): реализация secure_zero через OPENSSL_cleanse.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "vault/common/bytes.hpp"

namespace vault {

// Обнуление, которое не выкидывается оптимизатором.
void secure_zero(void* ptr, std::size_t len) noexcept;

// Владеющий буфер секрета. Не копируется неявно (только clone()).
class SecureBytes {
public:
    SecureBytes() = default;
    explicit SecureBytes(std::size_t size);
    SecureBytes(ByteView data);  // копирует данные
    ~SecureBytes();

    SecureBytes(const SecureBytes&) = delete;
    SecureBytes& operator=(const SecureBytes&) = delete;
    SecureBytes(SecureBytes&& other) noexcept;
    SecureBytes& operator=(SecureBytes&& other) noexcept;

    SecureBytes clone() const;

    std::uint8_t* data() noexcept { return buf_.data(); }
    const std::uint8_t* data() const noexcept { return buf_.data(); }
    std::size_t size() const noexcept { return buf_.size(); }
    bool empty() const noexcept { return buf_.empty(); }

    ByteView view() const noexcept { return ByteView(buf_.data(), buf_.size()); }
    MutableByteView mutable_view() noexcept { return MutableByteView(buf_.data(), buf_.size()); }

    // Обнуляет и освобождает. resize() запрещён намеренно: перевыделение
    // оставило бы копию секрета в освобождённой памяти.
    void wipe() noexcept;

private:
    std::vector<std::uint8_t> buf_;
};

}  // namespace vault
