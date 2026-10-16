#pragma once
// Конвейер порций SHA3-batch'а над абстрактным «устройством» (Dev). Вся логика, которую легко испортить
// при написании «вслепую» (порционирование, ротация слотов, порядок завершения, сборка staging-буфера),
// живёт здесь и тестируется на CPU эмулированным устройством (tests/unit/gpu_pipeline_test.cpp).
// CUDA-реализация Dev (cuda/src/gpu_hash_backend.cu) — тонкая обёртка над cudaMemcpyAsync / kernel.
//
// Контракт Dev (все методы работают со слотом s < slot_count()):
//   unsigned slot_count();
//   Staging  prepare(s, chunk, tb);   // готовит device- и staging-буферы под порцию; Staging{data, offsets}
//                                     //   data — >= max(1, байт порции), offsets — chunk.count + 1 значений
//   void     launch(s, chunk, domain, out_chunk_dst, stage_ms, tb);
//                                     // ставит в очередь H2D, kernel, D2H; НЕ ждёт. Staging слота нельзя
//                                     // менять до finish(s). out_chunk_dst — куда в итоге попадёт count хешей
//   void     finish(s, chunk, out_chunk_dst, tb);  // ждёт завершения, добавляет фазы в tb, гарантирует, что
//                                                  // хеши лежат в out_chunk_dst
//   void     drain() noexcept;        // дождаться всего в полёте (путь ошибки)

#include <algorithm>
#include <chrono>
#include <cstring>
#include <optional>
#include <span>
#include <vector>

#include "host/launch_plan.hpp"
#include "vault/common/bytes.hpp"
#include "vault/common/timing.hpp"

namespace vault::gpu {

struct Staging {
    std::uint8_t* data = nullptr;
    std::uint64_t* offsets = nullptr;
};

template <class Dev>
void run_hash_pipeline(Dev& dev, int domain, std::span<const ByteView> inputs, std::span<Hash256> out,
                       std::uint64_t max_chunk_bytes, TimingBreakdown& tb) {
    const std::size_t n = inputs.size();
    if (n == 0) return;
    std::vector<std::uint64_t> offsets(n + 1, 0);
    for (std::size_t i = 0; i < n; ++i) offsets[i + 1] = offsets[i] + inputs[i].size();
    const std::vector<HashChunk> plan = plan_hash_chunks(offsets, max_chunk_bytes);

    const unsigned nslots = dev.slot_count();
    std::vector<std::optional<HashChunk>> in_flight(nslots);
    auto finish = [&](unsigned s) {
        const HashChunk c = *in_flight[s];
        in_flight[s].reset();
        dev.finish(s, c, out.data() + c.first, tb);
    };

    try {
        for (std::size_t c = 0; c < plan.size(); ++c) {
            const unsigned s = static_cast<unsigned>(c % nslots);
            if (in_flight[s]) finish(s);  // слот ещё занят порцией c - nslots

            const HashChunk& chunk = plan[c];
            Staging st = dev.prepare(s, chunk, tb);
            // Сборка порции: объекты лежат разрозненно, одна копия в смежный staging неизбежна.
            const auto t0 = std::chrono::steady_clock::now();
            for (std::size_t k = 0; k < chunk.count; ++k) {
                const std::size_t i = chunk.first + k;
                const std::uint64_t rel = offsets[i] - chunk.byte_begin;
                st.offsets[k] = rel;
                if (!inputs[i].empty()) std::memcpy(st.data + rel, inputs[i].data(), inputs[i].size());
            }
            st.offsets[chunk.count] = chunk.byte_end - chunk.byte_begin;
            const double stage_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();

            dev.launch(s, chunk, domain, out.data() + chunk.first, stage_ms, tb);
            in_flight[s] = chunk;
        }
        // Остаток: в полёте последние min(nslots, plan.size()) порций; завершаем в порядке запуска.
        for (std::size_t c = plan.size() > nslots ? plan.size() - nslots : 0; c < plan.size(); ++c) {
            const unsigned s = static_cast<unsigned>(c % nslots);
            if (in_flight[s]) finish(s);
        }
    } catch (...) {
        dev.drain();
        throw;
    }
}

}  // namespace vault::gpu
