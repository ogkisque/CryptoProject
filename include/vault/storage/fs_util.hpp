#pragma once
// Примитивы durable-записи для POSIX (Linux). Основа crash-safe протокола (§28).

#include <filesystem>

#include "vault/common/bytes.hpp"
#include "vault/common/secure_buffer.hpp"

namespace vault::storage {

namespace fs = std::filesystem;

Bytes read_file(const fs::path& path);
// Для plaintext: размер известен заранее (fstat), без перевыделений; буфер обнуляется сам.
SecureBytes read_file_secure(const fs::path& path);
// Пишет во временный файл рядом, fsync(file), rename -> path, fsync(parent dir).
void write_file_atomic_durable(const fs::path& path, ByteView data, unsigned mode = 0644);
// Пишет файл (без rename) и делает fsync. Для файлов внутри *.tmp snapshot.
void write_file_durable(const fs::path& path, ByteView data, unsigned mode = 0644);
void fsync_path(const fs::path& path);  // файл или директория
void fsync_dir(const fs::path& dir);
// rename(2) + fsync родительской директории.
void atomic_rename(const fs::path& from, const fs::path& to);
// Создаёт hardlink (объекты immutable); при EXDEV/EPERM — копия + fsync.
void link_or_copy(const fs::path& from, const fs::path& to);

}  // namespace vault::storage
