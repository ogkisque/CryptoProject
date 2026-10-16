#pragma once
// Макросы для кода, который исполняется и на устройстве (nvcc), и на CPU (g++ в unit-тестах).
// Один и тот же исходный текст kernel-логики проверяется на CPU против OpenSSL и reference Merkle.

#if defined(__CUDACC__)
#define VAULT_HD __host__ __device__
#define VAULT_UNROLL _Pragma("unroll")
#else
#define VAULT_HD
#define VAULT_UNROLL
#endif
