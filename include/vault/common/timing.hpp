#pragma once
// Разбиение времени выполнения на фазы. Используется и backend'ами
// (GPU: alloc/H2D/kernel/D2H/sync), и логикой vault (algorithm/serialization/fs/memcpy).

#include <chrono>
#include <cstdint>

namespace vault {

// Заполняется batch-операциями backend'а, если передан ненулевой указатель.
// CPU backend заполняет только kernel_ms (= время алгоритма) и total_ms.
struct TimingBreakdown {
    double alloc_ms = 0;   // cudaMalloc / pinned alloc
    double h2d_ms = 0;     // host -> device
    double kernel_ms = 0;  // чистое время вычислений
    double d2h_ms = 0;     // device -> host
    double sync_ms = 0;    // cudaStreamSynchronize и пр.
    double total_ms = 0;   // wall-clock от входа до выхода из функции

    TimingBreakdown& operator+=(const TimingBreakdown& o) {
        alloc_ms += o.alloc_ms; h2d_ms += o.h2d_ms; kernel_ms += o.kernel_ms;
        d2h_ms += o.d2h_ms; sync_ms += o.sync_ms; total_ms += o.total_ms;
        return *this;
    }
};

// Фазы прикладных операций vault (Milestone 4, задача 7).
enum class Phase : std::uint8_t { Algorithm, Serialization, Filesystem, MemoryCopy, kCount };

struct PhaseProfile {
    double ms[static_cast<int>(Phase::kCount)] = {};
    double& operator[](Phase p) { return ms[static_cast<int>(p)]; }
    double operator[](Phase p) const { return ms[static_cast<int>(p)]; }
    PhaseProfile& operator+=(const PhaseProfile& o) {
        for (int i = 0; i < static_cast<int>(Phase::kCount); ++i) ms[i] += o.ms[i];
        return *this;
    }
};

// RAII-таймер: добавляет прошедшее время к профилю (если профиль задан).
class ScopedPhase {
public:
    ScopedPhase(PhaseProfile* profile, Phase phase)
        : profile_(profile), phase_(phase), start_(std::chrono::steady_clock::now()) {}
    ~ScopedPhase() {
        if (profile_) {
            auto d = std::chrono::steady_clock::now() - start_;
            (*profile_)[phase_] += std::chrono::duration<double, std::milli>(d).count();
        }
    }
    ScopedPhase(const ScopedPhase&) = delete;
    ScopedPhase& operator=(const ScopedPhase&) = delete;

private:
    PhaseProfile* profile_;
    Phase phase_;
    std::chrono::steady_clock::time_point start_;
};

}  // namespace vault
