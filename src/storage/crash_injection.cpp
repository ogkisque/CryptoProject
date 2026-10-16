#include "vault/storage/crash_injection.hpp"

#include <cstdlib>

#include "vault/common/error.hpp"

namespace vault::storage {

namespace {
struct Entry { CrashPoint p; std::string_view name; };
constexpr Entry kEntries[] = {
    {CrashPoint::None, "none"},
    {CrashPoint::BeforeSnapshotWrite, "before-snapshot-write"},
    {CrashPoint::DuringSnapshotWrite, "during-snapshot-write"},
    {CrashPoint::AfterSnapshotFsync, "after-snapshot-fsync"},
    {CrashPoint::AfterPublishBeforeTrusted, "before-trusted-update"},
    {CrashPoint::DuringTrustedUpdate, "during-trusted-update"},
    {CrashPoint::AfterTrustedUpdate, "after-trusted-update"},
};
}  // namespace

CrashPoint crash_point_from_string(std::string_view s) {
    for (const auto& e : kEntries)
        if (e.name == s) return e.p;
    throw VaultError(ErrorCode::InvalidArgument, "unknown crash point");
}

std::string_view to_string(CrashPoint p) noexcept {
    for (const auto& e : kEntries)
        if (e.p == p) return e.name;
    return "?";
}

CrashPoint configured_crash_point() {
    static const CrashPoint cp = [] {
        const char* env = std::getenv("VAULT_CRASH_POINT");
        return (env && *env) ? crash_point_from_string(env) : CrashPoint::None;
    }();
    return cp;
}

void crash_here(CrashPoint here) noexcept {
    try {
        if (here != CrashPoint::None && here == configured_crash_point()) std::_Exit(kCrashExitCode);
    } catch (...) {
        std::abort();  // неверное значение VAULT_CRASH_POINT — ошибка теста, а не "ожидаемый crash"
    }
}

}  // namespace vault::storage
