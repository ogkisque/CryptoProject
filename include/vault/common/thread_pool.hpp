#pragma once
// Простой пул потоков для CPU-MT backend'ов (этап 4). Единственная операция — parallel_for:
// блокирующий запуск n независимых задач; вызывающий поток тоже работает.
// Не реентерабельный: из задачи нельзя вызывать parallel_for того же пула.

#include <cstddef>
#include <functional>
#include <memory>
#include <vector>

namespace vault {

class ThreadPool {
public:
    // threads — общее число исполнителей, включая вызывающий поток (>= 1).
    explicit ThreadPool(unsigned threads);
    ~ThreadPool();
    ThreadPool(const ThreadPool&) = delete;
    ThreadPool& operator=(const ThreadPool&) = delete;

    unsigned size() const noexcept { return threads_; }

    // fn(i) для i в [0, n). Первое исключение из задач пробрасывается после завершения всех задач.
    // Одновременные вызовы из разных потоков сериализуются.
    void parallel_for(std::size_t n, const std::function<void(std::size_t)>& fn);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    unsigned threads_;
};

// Общий пул на заданное число потоков (одинаков для hash/merkle/kem/sig backend'ов одного набора,
// чтобы не плодить простаивающие потоки). 0 -> hardware_concurrency().
std::shared_ptr<ThreadPool> shared_thread_pool(unsigned threads);
unsigned resolve_thread_count(unsigned requested) noexcept;

// Делит [0, n) на не более `parts` смежных диапазонов с примерно равной суммой весов.
// weight(i) должен быть >= 1. Возвращает границы: диапазон k = [b[k], b[k+1]).
std::vector<std::size_t> split_by_weight(std::size_t n, std::size_t parts,
                                         const std::function<std::size_t(std::size_t)>& weight);

}  // namespace vault
