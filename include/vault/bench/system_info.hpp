#pragma once
// Окружение benchmark'а для воспроизводимости (§49, Milestone 7 задача 2).

#include <string>

namespace vault::bench {

struct SystemInfo {
    std::string timestamp_utc;
    std::string hostname;
    std::string os;
    std::string cpu_model;        // /proc/cpuinfo
    unsigned cpu_threads = 0;
    std::string gpu_model;        // cudaGetDeviceProperties, "" без CUDA
    std::string gpu_arch;         // "sm_86"
    std::string gpu_memory;
    std::string cuda_runtime_version;
    std::string cuda_driver_version;
    std::string cupqc_version;
    std::string openssl_version;
    std::string liboqs_version;
    std::string compiler;         // из макросов на этапе сборки
    std::string compiler_flags;   // VAULT_COMPILE_FLAGS из CMake
    std::string cuda_flags;
    std::string build_type;
    std::string git_commit;
};

SystemInfo collect_system_info();

}  // namespace vault::bench
