#pragma once
// Настройки GPU backend'ов. Вынесены в отдельный заголовок без CUDA и без зависимостей, чтобы их мог
// использовать и BackendConfig (CPU-часть, benchmark-конфиги), и GPU-реализация.

#include <cstddef>

namespace vault::gpu {

// Стратегия параллелизма SHA3 (sponge последователен внутри сообщения).
enum class GpuHashStrategy {
    ThreadPerObject,  // один поток на объект — основная
    WarpPerObject,    // warp на объект: 25 lane'ов держат состояние Keccak, обмен через __shfl_sync
};

struct GpuOptions {
    int device = 0;
    // true: вход собирается в pinned-буфер (быстрый DMA, но лишняя memcpy на CPU); false: из pageable-памяти.
    bool pinned_host_memory = true;
    // true: две порции в полёте на двух stream'ах (копирование/сборка следующей перекрывает вычисление текущей).
    bool double_buffering = false;
    // true: device/pinned-буферы переиспользуются между вызовами; false: cudaMalloc/cudaFree на КАЖДЫЙ вызов
    // и их время учитывается в alloc_ms (честная оценка §48: «GPU_total включает аллокацию»).
    bool pool_buffers = false;
    GpuHashStrategy hash_strategy = GpuHashStrategy::ThreadPerObject;
    // Максимум device-памяти на одну порцию SHA3-batch'а (данные + смещения + выходы). 0 = автоматически
    // по свободной VRAM (но не более 1 GiB).
    std::size_t max_chunk_bytes = 0;
    // Уровни Merkle с числом узлов меньше порога досчитываются на CPU.
    std::size_t merkle_cpu_threshold = 1024;
};

}  // namespace vault::gpu
