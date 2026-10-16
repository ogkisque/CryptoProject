#include "host/pqc_batch_plan.hpp"

#include <algorithm>

#include "vault/common/error.hpp"

namespace vault::gpu {

std::vector<PqcChunk> plan_pqc_chunks(std::size_t batch, std::uint64_t bytes_per_item, std::uint64_t max_bytes) {
    if (bytes_per_item == 0 || max_bytes == 0)
        throw VaultError(ErrorCode::InvalidArgument, "plan_pqc_chunks: bytes_per_item and max_bytes must be > 0");
    constexpr std::uint64_t kMaxGrid = 0x7fffffffULL;
    const std::uint64_t per_chunk = std::clamp<std::uint64_t>(max_bytes / bytes_per_item, 1, kMaxGrid);
    std::vector<PqcChunk> plan;
    for (std::size_t at = 0; at < batch;) {
        const std::size_t n = static_cast<std::size_t>(std::min<std::uint64_t>(per_chunk, batch - at));
        plan.push_back({at, n});
        at += n;
    }
    return plan;
}

}  // namespace vault::gpu
