// ЗАГЛУШКА cuPQC-PK для scripts/check_cuda_syntax.sh. Повторяет ЗАДОКУМЕНТИРОВАННУЮ поверхность API
// (docs.nvidia.com/cuda/cupqc, examples/public_key/*.cu в NVIDIA/cuPQC): дескрипторы через operator+,
// статические traits, device-методы execute(...) с задокументированными сигнатурами, host-функции
// make_workspace / get_entropy / destroy_workspace / release_entropy. Размеры — правдоподобные, не настоящие.
// Ничего не вычисляет.
#pragma once
#include <cstddef>
#include <cstdint>
#include "cuda_runtime.h"

namespace cupqc {

enum class algorithm { ML_KEM, ML_DSA };
enum class function { Keygen, Encaps, Decaps, Sign, Verify };

template <algorithm A, unsigned C, function F, unsigned Dim, bool HasBlock>
struct Desc {
    static constexpr algorithm alg = A;
    static constexpr bool kem = A == algorithm::ML_KEM;
    static constexpr std::size_t public_key_size = kem ? 1184 : 1952;
    static constexpr std::size_t secret_key_size = kem ? 2400 : 4032;
    static constexpr std::size_t ciphertext_size = kem ? 1088 : 0;
    static constexpr std::size_t shared_secret_size = kem ? 32 : 0;
    static constexpr std::size_t signature_size = kem ? 0 : 3309;
    static constexpr std::size_t entropy_size = F == function::Keygen ? (kem ? 64 : 32) : (F == function::Decaps || F == function::Verify ? 0 : 32);
    static constexpr std::size_t workspace_size = 16384;
    static constexpr std::size_t shared_memory_size = kem ? 12288 : 60000;  // ML-DSA > 48 KiB: проверяет путь с dynamic smem
    static constexpr dim3 BlockDim = dim3(Dim, 1, 1);

    // Keygen
    template <function G = F, class = typename std::enable_if<G == function::Keygen>::type>
    __device__ void execute(uint8_t* public_key, uint8_t* secret_key, uint8_t* entropy, uint8_t* workspace, uint8_t* smem_workspace);
    // Encaps
    template <function G = F, class = typename std::enable_if<G == function::Encaps>::type>
    __device__ void execute(uint8_t* ciphertext, uint8_t* shared_secret, const uint8_t* public_key, uint8_t* entropy,
                            uint8_t* workspace, uint8_t* smem_workspace, int = 0);
    // Decaps
    template <function G = F, class = typename std::enable_if<G == function::Decaps>::type>
    __device__ void execute(uint8_t* shared_secret, const uint8_t* ciphertext, const uint8_t* secret_key, uint8_t* workspace,
                            uint8_t* smem_workspace, long = 0);
    // Sign
    template <function G = F, class = typename std::enable_if<G == function::Sign>::type>
    __device__ void execute(uint8_t* signature, const uint8_t* message, const size_t message_length, const uint8_t* secret_key,
                            uint8_t* entropy, uint8_t* workspace, uint8_t* smem_workspace, short = 0);
    // Verify
    template <function G = F, class = typename std::enable_if<G == function::Verify>::type>
    __device__ bool execute(const uint8_t* message, const size_t message_length, const uint8_t* signature,
                            const uint8_t* public_key, uint8_t* workspace, uint8_t* smem_workspace, char = 0);
};

template <algorithm A, unsigned C> struct AlgTag {};
template <function F> struct Function {};
struct Block {};
template <unsigned X, unsigned Y = 1, unsigned Z = 1> struct BlockDim {};

// Сборка дескриптора: ML_xxx() + Function<>() + Block() + BlockDim<>()
template <algorithm A, unsigned C, function F = function::Keygen, unsigned Dim = 128, bool B = false, bool HasFn = false>
struct Builder : Desc<A, C, F, Dim, B> {};

constexpr auto ML_KEM_768() { return Builder<algorithm::ML_KEM, 3>(); }
constexpr auto ML_DSA_65() { return Builder<algorithm::ML_DSA, 3>(); }

template <algorithm A, unsigned C, function F0, unsigned D, bool B, bool H, function F>
constexpr auto operator+(Builder<A, C, F0, D, B, H>, Function<F>) { return Builder<A, C, F, D, B, true>(); }
template <algorithm A, unsigned C, function F, unsigned D, bool B, bool H>
constexpr auto operator+(Builder<A, C, F, D, B, H>, Block) { return Builder<A, C, F, D, true, H>(); }
template <algorithm A, unsigned C, function F, unsigned D0, bool B, bool H, unsigned X>
constexpr auto operator+(Builder<A, C, F, D0, B, H>, BlockDim<X>) { return Builder<A, C, F, X, B, H>(); }

template <class PK> uint8_t* make_workspace(size_t batch, cudaStream_t stream = 0);
template <class PK> uint8_t* get_entropy(size_t batch, cudaStream_t stream = 0);
void destroy_workspace(uint8_t* workspace, cudaStream_t stream = 0);
void release_entropy(uint8_t* workspace, cudaStream_t stream = 0);

}  // namespace cupqc
