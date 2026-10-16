#pragma once
// Host-часть GPU backend'а SHA3/Merkle: порционирование, grid/block, упаковка proof'ов.
// Обычный C++ без CUDA API — собирается и тестируется на любой машине (tests/unit/launch_plan_test.cpp).

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "vault/common/bytes.hpp"
#include "vault/merkle/merkle.hpp"

namespace vault::gpu {

struct LaunchDims {
    unsigned grid = 0;
    unsigned block = 0;
};

// Грид из 1D-блоков по `block` потоков, покрывающий n_threads потоков. Ограничен 2^31-1 блоков по x;
// kernel обязан быть grid-stride-циклом, если n_threads больше, чем покрыто.
LaunchDims launch_dims(std::uint64_t n_threads, unsigned block = 128);
// Для WarpPerObject: 32 потока на объект; block кратен 32.
LaunchDims launch_dims_warp_per_object(std::uint64_t n_objects, unsigned block = 128);

// Память устройства под порцию: данные + (count + 1) смещений u64 + count выходных хешей.
std::uint64_t chunk_device_bytes(std::uint64_t count, std::uint64_t data_bytes);

// Порция смежных объектов [first, first + count) с данными [byte_begin, byte_end) исходного PackedBatch.
struct HashChunk {
    std::size_t first = 0;
    std::size_t count = 0;
    std::uint64_t byte_begin = 0;
    std::uint64_t byte_end = 0;
    bool oversized = false;  // единственный объект, который сам больше max_chunk_bytes
};

// offsets — count_total + 1 значений (как PackedBatch::offsets, неубывающих, offsets[0] может быть != 0).
// Порции жадные и по границам объектов: порция не превышает max_chunk_bytes (по chunk_device_bytes),
// кроме объекта, который не помещается сам — он идёт отдельной порцией с oversized = true.
// Пустой вход -> пустой план. Выбрасывает VaultError(InvalidArgument) при немонотонных offsets или max_chunk_bytes == 0.
std::vector<HashChunk> plan_hash_chunks(std::span<const std::uint64_t> offsets, std::uint64_t max_chunk_bytes);

// Смещения порции относительно её начала (offsets[first..first+count] - byte_begin): так kernel не знает
// о положении порции во всём batch'е.
std::vector<std::uint64_t> rebase_offsets(std::span<const std::uint64_t> offsets, const HashChunk& chunk);

// Расписание подъёма Merkle по уровням: пока в следующем уровне >= cpu_threshold узлов, он считается
// на GPU (kernel «поток на родителя»); остаток (узкие уровни) досчитывается на CPU.
struct MerkleLevelStep {
    std::size_t nodes_in = 0;   // узлов на входе шага
    std::size_t nodes_out = 0;  // узлов на выходе = (nodes_in + 1) / 2
};
struct MerkleSchedule {
    std::vector<MerkleLevelStep> gpu_steps;  // уровни, считаемые на GPU
    std::size_t cpu_start_nodes = 0;         // размер уровня, с которого досчитывает CPU (1 -> корень уже готов)
};
MerkleSchedule plan_merkle_levels(std::size_t leaf_count, std::size_t cpu_threshold);

// Диапазоны proof'ов [first, first + count), для каждого из которых данные на device (лист, заголовок, шаги,
// результат) не превышают max_bytes; proof, не помещающийся даже один, идёт отдельным диапазоном.
struct ProofRange {
    std::size_t first = 0;
    std::size_t count = 0;
};
std::vector<ProofRange> plan_proof_ranges(std::span<const merkle::MerkleProof> proofs, std::uint64_t max_bytes);

// Плоское представление пакета proof'ов для kernel'а «поток на proof» (раскладка — docs/format_v1.md §15):
//   headers[i]: leaf_index, leaf_count, steps_begin (индекс шага в общих массивах), step_count
//   kinds[k]: 0 SiblingLeft | 1 SiblingRight | 2 Unpaired;  siblings[32 * k ..]: сосед (нули для Unpaired)
struct ProofHeader {
    std::uint64_t leaf_index;
    std::uint64_t leaf_count;
    std::uint32_t steps_begin;
    std::uint32_t step_count;
};
static_assert(sizeof(ProofHeader) == 24, "ProofHeader is copied to the device as-is");
struct PackedProofs {
    std::vector<ProofHeader> headers;
    std::vector<std::uint8_t> kinds;
    std::vector<std::uint8_t> siblings;
};
PackedProofs pack_proofs(std::span<const merkle::MerkleProof> proofs);

}  // namespace vault::gpu
