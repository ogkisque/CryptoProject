#pragma once
// CLI (§50). Глобальные опции:
//   --vault <dir>     (env VAULT_DIR, по умолчанию ./vault)
//   --trusted <dir>   (env VAULT_TRUSTED_DIR, по умолчанию ./trusted)
//   --backend cpu|cpu-mt|gpu   (по умолчанию cpu)
//   --threads <n>     (число потоков cpu-mt; 0 = все ядра)
// Коды возврата: 0 — успех, 1 — ошибка использования/IO,
//                2 — нарушение целостности/аутентичности (VerificationError, AuthFailed).

#include <filesystem>
#include <optional>
#include <string>

#include "vault/crypto/backends.hpp"
#include "vault/vault/vault.hpp"

namespace vault::cli {

struct GlobalOptions {
    VaultPaths paths;
    crypto::BackendConfig backend;
    bool verbose = false;  // печатать PhaseProfile / шаги проверки
};

int cmd_init(const GlobalOptions& g);
int cmd_add(const GlobalOptions& g, const std::filesystem::path& file);
// Пишет в output или в basename(filename) в текущей директории.
// Имя из plaintext санитизируется (никаких '/', '..', абсолютных путей);
// существующий файл не перезаписывается без force.
int cmd_extract(const GlobalOptions& g, const std::string& file_id_hex,
                const std::optional<std::filesystem::path>& output, bool force);
int cmd_remove(const GlobalOptions& g, const std::string& file_id_hex);
int cmd_list(const GlobalOptions& g, bool show_names);
int cmd_verify(const GlobalOptions& g);
int cmd_gc(const GlobalOptions& g);
// csv/json (если заданы) переопределяют output_csv/output_json из конфига.
int cmd_benchmark(const GlobalOptions& g, const std::filesystem::path& config_json,
                  const std::optional<std::filesystem::path>& csv, const std::optional<std::filesystem::path>& json);

}  // namespace vault::cli
