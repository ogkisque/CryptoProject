#include <openssl/crypto.h>
#include <oqs/oqs.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <chrono>
#include <ctime>
#include <fstream>
#include <thread>

#include "vault/bench/system_info.hpp"
#ifdef VAULT_HAS_CUDA
#include "vault/gpu/gpu_backends.hpp"
#endif

namespace vault::bench {

namespace {
std::string cpu_model() {
    std::ifstream in("/proc/cpuinfo");
    for (std::string line; std::getline(in, line);) {
        if (line.rfind("model name", 0) == 0) {
            auto pos = line.find(':');
            if (pos != std::string::npos) return line.substr(pos + 2);
        }
    }
    return "unknown";
}
}  // namespace

SystemInfo collect_system_info() {
    SystemInfo si;
    std::time_t t = std::time(nullptr);
    char buf[32];
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", &tm);
    si.timestamp_utc = buf;

    char host[256] = {};
    if (::gethostname(host, sizeof host - 1) == 0) si.hostname = host;
    utsname u{};
    if (::uname(&u) == 0) si.os = std::string(u.sysname) + " " + u.release + " " + u.machine;
    si.cpu_model = cpu_model();
    si.cpu_threads = std::thread::hardware_concurrency();
    si.openssl_version = OpenSSL_version(OPENSSL_VERSION);
    si.liboqs_version = OQS_version();
    si.compiler = __VERSION__;
#ifdef VAULT_COMPILE_FLAGS
    si.compiler_flags = VAULT_COMPILE_FLAGS;
#endif
#ifdef VAULT_BUILD_TYPE
    si.build_type = VAULT_BUILD_TYPE;
#endif
#ifdef VAULT_GIT_COMMIT
    si.git_commit = VAULT_GIT_COMMIT;
#endif
#ifdef VAULT_HAS_CUDA
    if (gpu::cuda_device_available()) {
        gpu::GpuDeviceInfo d = gpu::query_device(0);
        si.gpu_model = d.name;
        si.gpu_arch = "sm_" + std::to_string(d.sm_major) + std::to_string(d.sm_minor);
        si.gpu_memory = std::to_string(d.total_memory >> 20) + " MiB";
        si.cuda_runtime_version = std::to_string(d.runtime_version);
        si.cuda_driver_version = std::to_string(d.driver_version);
    }
#endif
#ifdef VAULT_CUDA_FLAGS
    si.cuda_flags = VAULT_CUDA_FLAGS;
#endif
#ifdef VAULT_CUPQC_VERSION
    si.cupqc_version = VAULT_CUPQC_VERSION;
#endif
    return si;
}

}  // namespace vault::bench
