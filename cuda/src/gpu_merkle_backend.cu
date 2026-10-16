// Merkle Tree на GPU (этап 5). Не компилировалось локально (нет CUDA).
//
// Логика подъёма по уровням (ping-pong буферов, сбор уровней, CPU-хвост) — в cuda/host/merkle_levels.hpp и
// проверена на CPU эмулированным устройством; логика узлов — общий код kernels/merkle_level.cuh, проверенный
// против reference. Здесь — CUDA-часть.
//  * compute_leaves — GPU-backend SHA3 с доменом 0x00 (kernel «поток/warp на объект»);
//  * уровни дерева — kernel «поток на родителя»; уровни с числом узлов < merkle_cpu_threshold
//    досчитываются на CPU (запуск kernel'а для нескольких узлов дороже самих хешей);
//  * verify_proofs_batch — kernel «поток на proof».
// IMerkleBackend разделяет compute_leaves и root_from_leaves, поэтому листья проходят D2H -> H2D:
// это N * 32 байт, мало по сравнению с данными; влияние видно в разбивке фаз.
#include <cstring>
#include <memory>
#include <vector>

#include "host/launch_plan.hpp"
#include "host/merkle_levels.hpp"
#include "kernels/merkle_level.cuh"
#include "src/gpu_runtime.hpp"
#include "vault/gpu/gpu_backends.hpp"

namespace vault::gpu {

namespace {

__global__ void merkle_level_kernel(const std::uint8_t* in, std::uint64_t n, std::uint8_t* out) {
    const std::uint64_t parents = (n + 1) / 2;
    const std::uint64_t stride = static_cast<std::uint64_t>(gridDim.x) * blockDim.x;
    for (std::uint64_t p = static_cast<std::uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x; p < parents; p += stride)
        kernels::merkle_level_node(in, static_cast<std::size_t>(n), static_cast<std::size_t>(p), out + 32 * p);
}

__global__ void merkle_proof_kernel(const std::uint8_t* leaves, const ProofHeader* headers, const std::uint8_t* kinds,
                                    const std::uint8_t* siblings, const std::uint8_t* root, std::uint8_t* ok,
                                    std::uint64_t count) {
    const std::uint64_t stride = static_cast<std::uint64_t>(gridDim.x) * blockDim.x;
    for (std::uint64_t i = static_cast<std::uint64_t>(blockIdx.x) * blockDim.x + threadIdx.x; i < count; i += stride) {
        const ProofHeader h = headers[i];
        ok[i] = kernels::merkle_verify_proof(leaves + 32 * i, h.leaf_index, h.leaf_count, kinds + h.steps_begin,
                                             siblings + 32ull * h.steps_begin, h.step_count, root)
                    ? 1
                    : 0;
    }
}

// CUDA-реализация контракта Dev из host/merkle_levels.hpp. Один экземпляр на один вызов (буферы не
// пулируются: они малы, а время их освобождения честно уходит в alloc_ms).
class CudaMerkleDevice {
public:
    void begin(std::size_t leaf_count, TimingBreakdown& tb) {
        a_.reserve(leaf_count * 32, &tb.alloc_ms);
        b_.reserve((leaf_count + 1) / 2 * 32, &tb.alloc_ms);
    }

    void upload_leaves(const Hash256* leaves, std::size_t n) {
        h2d0_.record(stream_);
        CUDA_CHECK(cudaMemcpyAsync(a_.get(), leaves, n * 32, cudaMemcpyHostToDevice, stream_.get()));
        h2d1_.record(stream_);
        have_h2d_ = true;
    }

    void level_step(bool from_a, std::size_t nodes_in, std::size_t nodes_out) {
        auto ev = std::make_unique<std::pair<Event, Event>>();
        ev->first.record(stream_);
        const LaunchDims d = launch_dims(nodes_out, kBlockSize);
        DeviceBuffer& in = from_a ? a_ : b_;
        DeviceBuffer& out = from_a ? b_ : a_;
        merkle_level_kernel<<<d.grid, d.block, 0, stream_.get()>>>(in.get(), nodes_in, out.get());
        CUDA_CHECK_LAUNCH("merkle_level_kernel");
        ev->second.record(stream_);
        kernel_events_.push_back(std::move(ev));
    }

    void download(bool from_a, std::size_t nodes, Hash256* dst) {
        Event d0, d1;
        d0.record(stream_);
        CUDA_CHECK(cudaMemcpyAsync(dst, (from_a ? a_ : b_).get(), nodes * 32, cudaMemcpyDeviceToHost, stream_.get()));
        d1.record(stream_);
        const auto t_sync = Clock::now();
        stream_.synchronize();
        sync_ms_ += ms_since(t_sync);
        d2h_ms_ += elapsed_ms(d0, d1);
        collect_kernel_events();  // после синхронизации события готовы
    }

    void end(TimingBreakdown& tb) noexcept {
        cudaStreamSynchronize(stream_.get());  // в noexcept-контексте: ошибки уже были бы пойманы CUDA_CHECK выше
        try {
            collect_kernel_events();
            if (have_h2d_) {
                h2d_ms_ += elapsed_ms(h2d0_, h2d1_);
                have_h2d_ = false;
            }
        } catch (...) {
        }
        tb.h2d_ms += h2d_ms_;
        tb.kernel_ms += kernel_ms_;
        tb.d2h_ms += d2h_ms_;
        tb.sync_ms += sync_ms_;
        h2d_ms_ = kernel_ms_ = d2h_ms_ = sync_ms_ = 0;
        a_.release(&tb.alloc_ms);
        b_.release(&tb.alloc_ms);
    }

private:
    void collect_kernel_events() {
        for (auto& ev : kernel_events_) kernel_ms_ += elapsed_ms(ev->first, ev->second);
        kernel_events_.clear();
    }

    Stream stream_;
    Event h2d0_, h2d1_;
    DeviceBuffer a_, b_;
    std::vector<std::unique_ptr<std::pair<Event, Event>>> kernel_events_;
    double h2d_ms_ = 0, kernel_ms_ = 0, d2h_ms_ = 0, sync_ms_ = 0;
    bool have_h2d_ = false;
};

class GpuMerkleBackend final : public merkle::IMerkleBackend {
public:
    explicit GpuMerkleBackend(const GpuOptions& opt) : ctx_(opt), hash_(make_gpu_hash_backend(opt)) {}

    std::string_view name() const override { return "gpu"; }

    void compute_leaves(std::span<const ByteView> objs, std::span<Hash256> out, TimingBreakdown* timing) override {
        hash_->domain_hash_batch(domain::kMerkleLeaf, objs, out, timing);
    }

    Hash256 root_from_leaves(std::span<const Hash256> leaves, TimingBreakdown* timing) override {
        if (leaves.empty()) return host_empty_root();
        TimingBreakdown tb;
        const auto t_total = Clock::now();
        std::vector<Hash256> top = levels(leaves, nullptr, tb);
        tb.total_ms = ms_since(t_total);
        if (timing) *timing += tb;
        return top[0];
    }

    merkle::MerkleTree build_tree(std::span<const Hash256> leaves, TimingBreakdown* timing) override {
        merkle::MerkleTree tree;
        if (leaves.empty()) {
            tree.root = host_empty_root();
            return tree;
        }
        TimingBreakdown tb;
        const auto t_total = Clock::now();
        tree.levels.emplace_back(leaves.begin(), leaves.end());
        levels(leaves, &tree.levels, tb);
        tree.root = tree.levels.back()[0];
        tb.total_ms = ms_since(t_total);
        if (timing) *timing += tb;
        return tree;
    }

    void verify_proofs_batch(std::span<const Hash256> leaves, std::span<const merkle::MerkleProof> proofs,
                             const Hash256& root, std::span<std::uint8_t> out_ok, TimingBreakdown* timing) override {
        if (leaves.size() != proofs.size() || out_ok.size() != proofs.size())
            throw VaultError(ErrorCode::InvalidArgument, "merkle: batch size mismatch");
        TimingBreakdown tb;
        const auto t_total = Clock::now();
        for (const ProofRange& r : plan_proof_ranges(proofs, ctx_.max_chunk_bytes()))
            verify_range(leaves.subspan(r.first, r.count), proofs.subspan(r.first, r.count), root,
                         out_ok.subspan(r.first, r.count), tb);
        tb.total_ms = ms_since(t_total);
        if (timing) *timing += tb;
    }

private:
    // Дерево слишком большое для device-буферов (A + B > max_chunk_bytes) -> считается целиком на CPU.
    std::vector<Hash256> levels(std::span<const Hash256> leaves, std::vector<std::vector<Hash256>>* out_levels,
                                TimingBreakdown& tb) {
        MerkleSchedule sched = plan_merkle_levels(leaves.size(), ctx_.options().merkle_cpu_threshold);
        if (leaves.size() * 32 * 2 > ctx_.max_chunk_bytes()) sched = MerkleSchedule{{}, leaves.size()};
        CudaMerkleDevice dev;
        return run_merkle_levels(dev, leaves, sched, out_levels, tb);
    }

    void verify_range(std::span<const Hash256> leaves, std::span<const merkle::MerkleProof> proofs, const Hash256& root,
                      std::span<std::uint8_t> out_ok, TimingBreakdown& tb) {
        const PackedProofs packed = pack_proofs(proofs);
        const std::size_t n = proofs.size();
        DeviceBuffer d_leaves, d_headers, d_kinds, d_sibs, d_root, d_ok;
        Stream stream;
        Event e_h2d0, e_h2d1, e_k0, e_k1, e_d2h0, e_d2h1;
        try {
            d_leaves.reserve(n * 32, &tb.alloc_ms);
            d_headers.reserve(packed.headers.size() * sizeof(ProofHeader), &tb.alloc_ms);
            d_kinds.reserve(packed.kinds.size(), &tb.alloc_ms);
            d_sibs.reserve(packed.siblings.size(), &tb.alloc_ms);
            d_root.reserve(32, &tb.alloc_ms);
            d_ok.reserve(n, &tb.alloc_ms);

            e_h2d0.record(stream);
            CUDA_CHECK(cudaMemcpyAsync(d_leaves.get(), leaves.data(), n * 32, cudaMemcpyHostToDevice, stream.get()));
            CUDA_CHECK(cudaMemcpyAsync(d_headers.get(), packed.headers.data(), packed.headers.size() * sizeof(ProofHeader),
                                       cudaMemcpyHostToDevice, stream.get()));
            if (!packed.kinds.empty()) {
                CUDA_CHECK(cudaMemcpyAsync(d_kinds.get(), packed.kinds.data(), packed.kinds.size(), cudaMemcpyHostToDevice, stream.get()));
                CUDA_CHECK(cudaMemcpyAsync(d_sibs.get(), packed.siblings.data(), packed.siblings.size(), cudaMemcpyHostToDevice, stream.get()));
            }
            CUDA_CHECK(cudaMemcpyAsync(d_root.get(), root.data(), 32, cudaMemcpyHostToDevice, stream.get()));
            e_h2d1.record(stream);

            e_k0.record(stream);
            const LaunchDims d = launch_dims(n, kBlockSize);
            merkle_proof_kernel<<<d.grid, d.block, 0, stream.get()>>>(
                d_leaves.get(), d_headers.get<ProofHeader>(), d_kinds.get(), d_sibs.get(), d_root.get(), d_ok.get(), n);
            CUDA_CHECK_LAUNCH("merkle_proof_kernel");
            e_k1.record(stream);

            e_d2h0.record(stream);
            CUDA_CHECK(cudaMemcpyAsync(out_ok.data(), d_ok.get(), n, cudaMemcpyDeviceToHost, stream.get()));
            e_d2h1.record(stream);
            const auto t_sync = Clock::now();
            stream.synchronize();
            tb.sync_ms += ms_since(t_sync);
            tb.h2d_ms += elapsed_ms(e_h2d0, e_h2d1);
            tb.kernel_ms += elapsed_ms(e_k0, e_k1);
            tb.d2h_ms += elapsed_ms(e_d2h0, e_d2h1);
        } catch (...) {
            cudaStreamSynchronize(stream.get());
            throw;
        }
        d_leaves.release(&tb.alloc_ms);
        d_headers.release(&tb.alloc_ms);
        d_kinds.release(&tb.alloc_ms);
        d_sibs.release(&tb.alloc_ms);
        d_root.release(&tb.alloc_ms);
        d_ok.release(&tb.alloc_ms);
    }

    GpuContext ctx_;
    std::shared_ptr<crypto::IHashBackend> hash_;
};

}  // namespace

std::shared_ptr<merkle::IMerkleBackend> make_gpu_merkle_backend(const GpuOptions& opt) {
    return std::make_shared<GpuMerkleBackend>(opt);
}

}  // namespace vault::gpu
