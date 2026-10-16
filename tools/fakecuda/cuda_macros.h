// ЗАГЛУШКА для scripts/check_cuda_syntax.sh: только объявления, чтобы clang мог разобрать .cu без CUDA Toolkit.
// Не заменяет nvcc: проверяет синтаксис и вызовы host/device, но не ограничения nvcc/PTX.
#include <stdlib.h>
#define __global__ __attribute__((global))
#define __device__ __attribute__((device))
#define __host__ __attribute__((host))
#define __constant__ __attribute__((constant))
#define __shared__ __attribute__((shared))
template <typename T> __attribute__((device)) T __shfl_sync(unsigned, T, int, int = 32);
