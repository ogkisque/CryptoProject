#include "vault/common/thread_pool.hpp"

#include <algorithm>
#include <atomic>
#include <condition_variable>
#include <exception>
#include <map>
#include <mutex>
#include <thread>

namespace vault {

namespace {
struct Job {
    const std::function<void(std::size_t)>* fn = nullptr;
    std::size_t n = 0;
    std::atomic<std::size_t> next{0};
    std::atomic<std::size_t> completed{0};
    std::mutex err_mu;
    std::exception_ptr err;
};
}  // namespace

struct ThreadPool::Impl {
    std::vector<std::thread> workers;
    std::mutex dispatch_mu;  // один parallel_for за раз
    std::mutex mu;
    std::condition_variable cv_work, cv_done;
    std::shared_ptr<Job> job;
    std::uint64_t epoch = 0;
    bool stop = false;

    // Берёт задачи из job, пока они есть. Каждая задача — не более одного раза.
    void run_tasks(Job& j) {
        for (;;) {
            std::size_t i = j.next.fetch_add(1);
            if (i >= j.n) return;
            try {
                (*j.fn)(i);
            } catch (...) {
                std::lock_guard<std::mutex> lk(j.err_mu);
                if (!j.err) j.err = std::current_exception();
            }
            if (j.completed.fetch_add(1) + 1 == j.n) {
                std::lock_guard<std::mutex> lk(mu);  // не терять пробуждение caller'а
                cv_done.notify_all();
            }
        }
    }

    void worker() {
        std::uint64_t seen = 0;
        for (;;) {
            std::shared_ptr<Job> j;
            {
                std::unique_lock<std::mutex> lk(mu);
                cv_work.wait(lk, [&] { return stop || epoch != seen; });
                if (stop) return;
                seen = epoch;
                j = job;
            }
            if (j) run_tasks(*j);
        }
    }
};

ThreadPool::ThreadPool(unsigned threads) : impl_(std::make_unique<Impl>()), threads_(std::max(1u, threads)) {
    for (unsigned i = 1; i < threads_; ++i) impl_->workers.emplace_back([this] { impl_->worker(); });
}

ThreadPool::~ThreadPool() {
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        impl_->stop = true;
    }
    impl_->cv_work.notify_all();
    for (auto& t : impl_->workers) t.join();
}

void ThreadPool::parallel_for(std::size_t n, const std::function<void(std::size_t)>& fn) {
    if (n == 0) return;
    if (impl_->workers.empty() || n == 1) {
        for (std::size_t i = 0; i < n; ++i) fn(i);
        return;
    }
    std::lock_guard<std::mutex> dispatch(impl_->dispatch_mu);
    auto job = std::make_shared<Job>();
    job->fn = &fn;
    job->n = n;
    {
        std::lock_guard<std::mutex> lk(impl_->mu);
        impl_->job = job;
        ++impl_->epoch;
    }
    impl_->cv_work.notify_all();
    impl_->run_tasks(*job);
    {
        std::unique_lock<std::mutex> lk(impl_->mu);
        impl_->cv_done.wait(lk, [&] { return job->completed.load() == n; });
        impl_->job.reset();
    }
    if (job->err) std::rethrow_exception(job->err);
}

unsigned resolve_thread_count(unsigned requested) noexcept {
    if (requested != 0) return requested;
    unsigned hc = std::thread::hardware_concurrency();
    return hc == 0 ? 1 : hc;
}

std::shared_ptr<ThreadPool> shared_thread_pool(unsigned threads) {
    static std::mutex mu;
    static std::map<unsigned, std::weak_ptr<ThreadPool>> pools;
    threads = resolve_thread_count(threads);
    std::lock_guard<std::mutex> lk(mu);
    if (auto p = pools[threads].lock()) return p;
    auto p = std::make_shared<ThreadPool>(threads);
    pools[threads] = p;
    return p;
}

std::vector<std::size_t> split_by_weight(std::size_t n, std::size_t parts,
                                         const std::function<std::size_t(std::size_t)>& weight) {
    std::vector<std::size_t> b{0};
    if (n == 0) return b;
    parts = std::max<std::size_t>(1, std::min(parts, n));
    std::size_t total = 0;
    for (std::size_t i = 0; i < n; ++i) total += weight(i);
    std::size_t acc = 0, target_idx = 1;
    for (std::size_t i = 0; i < n; ++i) {
        acc += weight(i);
        // закрываем диапазон, когда накоплено >= target_idx/parts всего веса
        if (target_idx < parts && acc * parts >= total * target_idx && i + 1 < n) {
            b.push_back(i + 1);
            while (target_idx < parts && acc * parts >= total * target_idx) ++target_idx;
        }
    }
    b.push_back(n);
    return b;
}

}  // namespace vault
