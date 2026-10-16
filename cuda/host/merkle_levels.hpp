#pragma once
// Подъём Merkle-дерева по уровням над абстрактным «устройством» (Dev): ping-pong буферов, сбор уровней,
// CPU-хвост. Тестируется на CPU эмулированным устройством (tests/unit/gpu_pipeline_test.cpp);
// CUDA-реализация Dev — в cuda/src/gpu_merkle_backend.cu.
//
// Контракт Dev: два device-буфера A и B:
//   void begin(std::size_t leaf_count, TimingBreakdown&);       // выделить A (leaf_count узлов) и B ((leaf_count+1)/2)
//   void upload_leaves(const Hash256*, std::size_t n);          // host -> A
//   void level_step(bool from_a, nodes_in, nodes_out);          // из A в B (from_a) или из B в A
//   void download(bool from_a, std::size_t nodes, Hash256* dst); // скопировать узлы буфера A или B на host
//   void end(TimingBreakdown&) noexcept;                         // дождаться, собрать фазы, освободить буферы

#include <vector>

#include "host/launch_plan.hpp"
#include "kernels/merkle_level.cuh"
#include "vault/common/bytes.hpp"
#include "vault/common/timing.hpp"

namespace vault::gpu {

// Один шаг подъёма на CPU тем же кодом, что и kernel. Требует cur.size() >= 2.
inline std::vector<Hash256> host_next_level(const std::vector<Hash256>& cur) {
    std::vector<Hash256> next((cur.size() + 1) / 2);
    for (std::size_t p = 0; p < next.size(); ++p) kernels::merkle_level_node(cur[0].data(), cur.size(), p, next[p].data());
    return next;
}

inline Hash256 host_empty_root() {
    Hash256 h;
    constexpr char label[] = "edu-vault-empty-tree-v1";  // без завершающего '\0'
    kernels::sha3_256_domain(kernels::kDomMerkleEmpty, reinterpret_cast<const std::uint8_t*>(label), sizeof(label) - 1, h.data());
    return h;
}

// leaves.size() >= 1. levels != nullptr -> в него дописываются все уровни выше листьев (levels[0] — листья —
// кладёт вызывающий). Возвращает верхний уровень из одного узла.
template <class Dev>
std::vector<Hash256> run_merkle_levels(Dev& dev, std::span<const Hash256> leaves, const MerkleSchedule& sched,
                                       std::vector<std::vector<Hash256>>* levels, TimingBreakdown& tb) {
    std::vector<Hash256> cur(leaves.begin(), leaves.end());
    if (!sched.gpu_steps.empty()) {
        dev.begin(leaves.size(), tb);
        try {
            dev.upload_leaves(leaves.data(), leaves.size());
            bool in_a = true;  // где лежит текущий уровень
            for (const MerkleLevelStep& step : sched.gpu_steps) {
                dev.level_step(in_a, step.nodes_in, step.nodes_out);
                in_a = !in_a;  // результат шага — в противоположном буфере
                if (levels) {
                    std::vector<Hash256> lvl(step.nodes_out);
                    dev.download(in_a, step.nodes_out, lvl.data());
                    levels->push_back(std::move(lvl));
                }
            }
            cur.assign(sched.cpu_start_nodes, Hash256{});
            dev.download(in_a, sched.cpu_start_nodes, cur.data());
        } catch (...) {
            dev.end(tb);
            throw;
        }
        dev.end(tb);
    }
    // CPU-хвост: узкие уровни (или всё дерево, если GPU-шагов нет).
    while (cur.size() > 1) {
        cur = host_next_level(cur);
        if (levels) levels->push_back(cur);
    }
    return cur;
}

}  // namespace vault::gpu
