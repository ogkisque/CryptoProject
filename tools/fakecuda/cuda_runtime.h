// ЗАГЛУШКА для scripts/check_cuda_syntax.sh: только объявления, чтобы clang мог разобрать .cu без CUDA Toolkit.
// Не заменяет nvcc: проверяет синтаксис и вызовы host/device, но не ограничения nvcc/PTX.
#pragma once
// Заглушка CUDA runtime для СИНТАКСИЧЕСКОЙ проверки .cu через clang (не для запуска).
#include <stddef.h>
#include <type_traits>
#include <stdint.h>
typedef int cudaError_t;
enum { cudaSuccess = 0 };
typedef struct CUstream_st* cudaStream_t;
typedef struct CUevent_st* cudaEvent_t;
enum cudaFuncAttribute { cudaFuncAttributeMaxDynamicSharedMemorySize = 8 };
enum cudaDeviceAttr { cudaDevAttrMaxSharedMemoryPerBlockOptin = 97 };
enum cudaMemcpyKind { cudaMemcpyHostToDevice, cudaMemcpyDeviceToHost, cudaMemcpyDeviceToDevice };
#define cudaStreamNonBlocking 1
#define cudaHostAllocDefault 0
struct cudaDeviceProp { char name[256]; int major, minor; size_t totalGlobalMem; int multiProcessorCount; };
struct uint3 { unsigned x, y, z; };
struct dim3 { unsigned x, y, z; constexpr dim3(unsigned a=1,unsigned b=1,unsigned c=1):x(a),y(b),z(c){} };
extern "C" {
cudaError_t cudaMalloc(void**, size_t); cudaError_t cudaFree(void*);
cudaError_t cudaHostAlloc(void**, size_t, unsigned); cudaError_t cudaFreeHost(void*);
cudaError_t cudaStreamCreateWithFlags(cudaStream_t*, unsigned); cudaError_t cudaStreamDestroy(cudaStream_t);
cudaError_t cudaStreamSynchronize(cudaStream_t);
cudaError_t cudaEventCreate(cudaEvent_t*); cudaError_t cudaEventDestroy(cudaEvent_t);
cudaError_t cudaEventRecord(cudaEvent_t, cudaStream_t); cudaError_t cudaEventElapsedTime(float*, cudaEvent_t, cudaEvent_t);
cudaError_t cudaMemcpyAsync(void*, const void*, size_t, cudaMemcpyKind, cudaStream_t);
cudaError_t cudaMemcpy2DAsync(void*, size_t, const void*, size_t, size_t, size_t, cudaMemcpyKind, cudaStream_t);
cudaError_t cudaMemsetAsync(void*, int, size_t, cudaStream_t);
cudaError_t cudaDeviceGetAttribute(int*, cudaDeviceAttr, int);
cudaError_t cudaMemGetInfo(size_t*, size_t*); cudaError_t cudaGetDeviceCount(int*); cudaError_t cudaSetDevice(int);
cudaError_t cudaGetDeviceProperties(cudaDeviceProp*, int);
cudaError_t cudaRuntimeGetVersion(int*); cudaError_t cudaDriverGetVersion(int*);
const char* cudaGetErrorName(cudaError_t); const char* cudaGetErrorString(cudaError_t); cudaError_t cudaGetLastError();
unsigned __cudaPushCallConfiguration(dim3, dim3, size_t, void*);
cudaError_t cudaConfigureCall(dim3, dim3, size_t, cudaStream_t);
}
template <class T> cudaError_t cudaFuncSetAttribute(T*, cudaFuncAttribute, int);
extern __device__ uint3 threadIdx, blockIdx; extern __device__ dim3 blockDim, gridDim;
