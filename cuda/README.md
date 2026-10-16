# GPU-часть (CUDA / cuPQC)

Собирается только с `-DVAULT_ENABLE_CUDA=ON` на машине с GPU (см. docs/gpu_machine.md).
Реализует фабрики из `include/vault/gpu/gpu_backends.hpp`.

```
cuda/
  kernels/               # .cuh: device-функции (Keccak-f[1600], Merkle level)
  src/
    device.cu            # query_device, cuda_device_available, GpuContext (stream, пулы буферов)
    gpu_hash_backend.cu  # SHA3-256 batch                          (Milestone 5)
    gpu_merkle_backend.cu# уровни дерева, proof verification batch (Milestone 5)
    gpu_kem_backend.cu   # ML-KEM-768 через cuPQC                  (Milestone 6)
    gpu_sig_backend.cu   # ML-DSA-65 через cuPQC                   (Milestone 6)
```
