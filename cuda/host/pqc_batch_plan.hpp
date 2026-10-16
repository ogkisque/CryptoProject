#pragma once
// Порционирование batch'а ML-KEM / ML-DSA (этап 6). Одна операция = один CUDA-блок (cuPQC-PK, Block-режим),
// поэтому порция — это просто число элементов; ограничения: VRAM и gridDim.x <= 2^31 - 1.
// Обычный C++ без CUDA API (tests/unit/pqc_batch_plan_test.cpp).

#include <cstddef>
#include <cstdint>
#include <vector>

namespace vault::gpu {

struct PqcChunk {
    std::size_t first = 0;
    std::size_t count = 0;
};

// Делит batch на смежные порции по <= max(1, max_bytes / bytes_per_item) элементов (и не более 2^31 - 1).
// Элемент, не помещающийся в max_bytes даже один, всё равно идёт порцией из одного элемента: решение
// «хватит ли памяти» принимает cudaMalloc с понятным сообщением. batch == 0 -> пустой план.
// bytes_per_item == 0 или max_bytes == 0 -> VaultError(InvalidArgument).
std::vector<PqcChunk> plan_pqc_chunks(std::size_t batch, std::uint64_t bytes_per_item, std::uint64_t max_bytes);

constexpr std::uint64_t round_up_8(std::uint64_t n) { return (n + 7) / 8 * 8; }

}  // namespace vault::gpu
