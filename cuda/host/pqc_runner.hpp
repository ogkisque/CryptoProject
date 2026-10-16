#pragma once
// Граница между переносимой логикой GPU ML-KEM / ML-DSA и CUDA/cuPQC-кодом (этап 6).
//
// Runner исполняет ОДНУ порцию (count элементов) над плотными host-буферами (шаг = естественный размер
// элемента; padding до 8 байт для подписей ML-DSA — забота runner'а, cudaMemcpy2D). Runner отвечает за:
// выделение памяти, копирования, запуск kernel'ов, обнуление секретов на устройстве (§43), тайминги по фазам.
// Всё остальное — проверка размеров, порционирование, калибровка режима context string, сборка M' — в
// cuda/host/pqc_backends.cpp и тестируется на CPU «фальшивым cuPQC» (tests/unit/gpu_pqc_logic_test.cpp).

#include <cstddef>
#include <cstdint>

#include "vault/common/timing.hpp"

namespace vault::gpu {

class IMlKemRunner {
public:
    virtual ~IMlKemRunner() = default;
    // Максимум device-байт на порцию.
    virtual std::uint64_t max_chunk_bytes() const = 0;
    // Оценка device-памяти на один элемент (ключи + entropy + workspace + выходы) — для планировщика.
    virtual std::uint64_t keygen_item_bytes() const = 0;
    virtual std::uint64_t encaps_item_bytes() const = 0;
    virtual std::uint64_t decaps_item_bytes() const = 0;
    // Можно ли подавать entropy вызывающей стороной (детерминированный режим для тестов/ACVP). false ->
    // операции с seeds != nullptr бросают BackendUnavailable.
    virtual bool supports_seeds() const = 0;

    // seeds: count * 64 (d || z) или nullptr (случайность из cuPQC).
    virtual void keygen(std::size_t count, const std::uint8_t* seeds, std::uint8_t* public_keys,
                        std::uint8_t* secret_keys, TimingBreakdown& tb) = 0;
    // seeds: count * 32 (m) или nullptr.
    virtual void encaps(std::size_t count, const std::uint8_t* public_keys, const std::uint8_t* seeds,
                        std::uint8_t* ciphertexts, std::uint8_t* shared_secrets, TimingBreakdown& tb) = 0;
    virtual void decaps(std::size_t count, const std::uint8_t* secret_keys, const std::uint8_t* ciphertexts,
                        std::uint8_t* shared_secrets, TimingBreakdown& tb) = 0;
};

class IMlDsaRunner {
public:
    virtual ~IMlDsaRunner() = default;
    virtual std::uint64_t max_chunk_bytes() const = 0;
    virtual std::uint64_t keygen_item_bytes() const = 0;
    virtual std::uint64_t sign_item_bytes(std::size_t message_size) const = 0;
    virtual std::uint64_t verify_item_bytes(std::size_t message_size) const = 0;
    virtual bool supports_seeds() const = 0;

    // seeds: count * 32 (xi) или nullptr.
    virtual void keygen(std::size_t count, const std::uint8_t* seeds, std::uint8_t* public_keys,
                        std::uint8_t* secret_keys, TimingBreakdown& tb) = 0;
    // Подписывает message как есть (cuPQC не принимает context string: что именно подписывается — решает
    // калибровка режима в pqc_backends.cpp). rnds: count * 32 или nullptr (hedged). signatures: count * 3309.
    virtual void sign(std::size_t count, const std::uint8_t* secret_keys, const std::uint8_t* messages,
                      std::size_t message_size, const std::uint8_t* rnds, std::uint8_t* signatures,
                      TimingBreakdown& tb) = 0;
    // ok[i] = 1, если подпись i верна для сообщения i (как есть) и открытого ключа i.
    virtual void verify(std::size_t count, const std::uint8_t* public_keys, const std::uint8_t* messages,
                        std::size_t message_size, const std::uint8_t* signatures, std::uint8_t* ok,
                        TimingBreakdown& tb) = 0;
};

}  // namespace vault::gpu
