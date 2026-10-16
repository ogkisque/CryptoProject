#include "host/launch_plan.hpp"

#include <algorithm>
#include <limits>

#include "vault/common/error.hpp"

namespace vault::gpu {

namespace {
constexpr std::uint64_t kMaxGridX = 0x7fffffffULL;  // 2^31 - 1: предел gridDim.x
}

LaunchDims launch_dims(std::uint64_t n_threads, unsigned block) {
    if (block == 0) throw VaultError(ErrorCode::InvalidArgument, "launch_dims: block must be > 0");
    LaunchDims d;
    d.block = block;
    std::uint64_t blocks = (n_threads + block - 1) / block;
    if (blocks == 0) blocks = 1;  // пустой запуск запрещён CUDA; kernel сам отсекает лишние потоки
    d.grid = static_cast<unsigned>(std::min(blocks, kMaxGridX));
    return d;
}

LaunchDims launch_dims_warp_per_object(std::uint64_t n_objects, unsigned block) {
    if (block == 0 || block % 32 != 0)
        throw VaultError(ErrorCode::InvalidArgument, "launch_dims_warp_per_object: block must be a multiple of 32");
    return launch_dims(n_objects * 32ULL, block);
}

std::uint64_t chunk_device_bytes(std::uint64_t count, std::uint64_t data_bytes) {
    return data_bytes + 8ULL * (count + 1) + 32ULL * count;
}

std::vector<HashChunk> plan_hash_chunks(std::span<const std::uint64_t> offsets, std::uint64_t max_chunk_bytes) {
    if (max_chunk_bytes == 0) throw VaultError(ErrorCode::InvalidArgument, "plan_hash_chunks: max_chunk_bytes == 0");
    std::vector<HashChunk> plan;
    if (offsets.size() <= 1) return plan;
    for (std::size_t i = 1; i < offsets.size(); ++i)
        if (offsets[i] < offsets[i - 1])
            throw VaultError(ErrorCode::InvalidArgument, "plan_hash_chunks: offsets must be non-decreasing");

    const std::size_t n = offsets.size() - 1;
    std::size_t i = 0;
    while (i < n) {
        HashChunk c;
        c.first = i;
        c.byte_begin = offsets[i];
        std::size_t j = i;  // [i, j) — уже в порции
        for (; j < n; ++j) {
            std::uint64_t data = offsets[j + 1] - c.byte_begin;
            if (chunk_device_bytes(j + 1 - i, data) > max_chunk_bytes) break;
        }
        if (j == i) {  // объект не помещается даже один -> отдельная порция
            j = i + 1;
            c.oversized = true;
        }
        c.count = j - i;
        c.byte_end = offsets[j];
        plan.push_back(c);
        i = j;
    }
    return plan;
}

std::vector<std::uint64_t> rebase_offsets(std::span<const std::uint64_t> offsets, const HashChunk& chunk) {
    if (chunk.first + chunk.count + 1 > offsets.size())
        throw VaultError(ErrorCode::InvalidArgument, "rebase_offsets: chunk outside offsets");
    std::vector<std::uint64_t> out(chunk.count + 1);
    for (std::size_t k = 0; k <= chunk.count; ++k) out[k] = offsets[chunk.first + k] - chunk.byte_begin;
    return out;
}

MerkleSchedule plan_merkle_levels(std::size_t leaf_count, std::size_t cpu_threshold) {
    MerkleSchedule s;
    std::size_t n = leaf_count;
    s.cpu_start_nodes = n;
    while (n > 1) {
        std::size_t out = (n + 1) / 2;
        if (out < cpu_threshold) break;  // узкий уровень — на CPU
        s.gpu_steps.push_back({n, out});
        n = out;
        s.cpu_start_nodes = n;
    }
    return s;
}

std::vector<ProofRange> plan_proof_ranges(std::span<const merkle::MerkleProof> proofs, std::uint64_t max_bytes) {
    if (max_bytes == 0) throw VaultError(ErrorCode::InvalidArgument, "plan_proof_ranges: max_bytes == 0");
    std::vector<ProofRange> out;
    std::size_t begin = 0;
    while (begin < proofs.size()) {
        std::size_t end = begin;
        std::uint64_t bytes = 0;
        while (end < proofs.size()) {
            // лист 32 + заголовок + шаги (вид 1 + сосед 32) + байт результата
            const std::uint64_t b = 32 + sizeof(ProofHeader) + proofs[end].steps.size() * 33ULL + 1;
            if (end > begin && bytes + b > max_bytes) break;
            bytes += b;
            ++end;
        }
        out.push_back({begin, end - begin});
        begin = end;
    }
    return out;
}

PackedProofs pack_proofs(std::span<const merkle::MerkleProof> proofs) {
    PackedProofs p;
    p.headers.reserve(proofs.size());
    std::uint64_t total_steps = 0;
    for (const auto& pr : proofs) total_steps += pr.steps.size();
    if (total_steps > std::numeric_limits<std::uint32_t>::max())
        throw VaultError(ErrorCode::InvalidArgument, "pack_proofs: too many proof steps");
    p.kinds.reserve(total_steps);
    p.siblings.assign(static_cast<std::size_t>(total_steps) * 32, 0);
    std::uint32_t at = 0;
    for (const auto& pr : proofs) {
        p.headers.push_back({pr.leaf_index, pr.leaf_count, at, static_cast<std::uint32_t>(pr.steps.size())});
        for (const auto& s : pr.steps) {
            p.kinds.push_back(static_cast<std::uint8_t>(s.kind));
            if (s.kind != merkle::ProofStep::Kind::Unpaired) std::copy(s.sibling.begin(), s.sibling.end(), p.siblings.begin() + 32ULL * at);
            ++at;
        }
    }
    return p;
}

}  // namespace vault::gpu
