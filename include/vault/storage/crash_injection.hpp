#pragma once
// Точки аварийного завершения для crash-тестов (§57 "Crash tests").
// Активируются переменной окружения VAULT_CRASH_POINT=<name>; в точке
// процесс завершается через std::_Exit(kCrashExitCode) без деструкторов
// и без flush — имитация kill -9 / потери питания на уровне процесса.

#include <string_view>

namespace vault::storage {

inline constexpr int kCrashExitCode = 86;

enum class CrashPoint {
    None,
    BeforeSnapshotWrite,          // "before-snapshot-write"
    DuringSnapshotWrite,          // "during-snapshot-write" (после части объектов)
    AfterSnapshotFsync,           // "after-snapshot-fsync"  (до publish)
    AfterPublishBeforeTrusted,    // "before-trusted-update"
    DuringTrustedUpdate,          // "during-trusted-update" (tmp записан, rename не сделан)
    AfterTrustedUpdate,           // "after-trusted-update"  (до GC)
};

CrashPoint crash_point_from_string(std::string_view s);
std::string_view to_string(CrashPoint p) noexcept;

// Читает VAULT_CRASH_POINT один раз.
CrashPoint configured_crash_point();
// Если here == configured_crash_point() -> std::_Exit(kCrashExitCode).
void crash_here(CrashPoint here) noexcept;

}  // namespace vault::storage
