#pragma once
// Недоверенное файловое хранилище (директория vault/). Атакующий может
// произвольно читать/менять/удалять/подменять всё, что здесь лежит (§36),
// поэтому backend только перемещает байты — никаких проверок и решений
// о доверии; всё проверяет vault::StateVerifier.
//
// Модель: хранилище — последовательность snapshot'ов (поколений).
//   Milestone 1-2: FlatStorage — одно изменяемое "поколение 0" (vault/objects/...).
//   Milestone 3:   GenerationStorage — immutable generations/<N>/ (§30).
// Логика vault работает только через этот интерфейс, поэтому переход
// M2 -> M3 не затрагивает шифрование/верификацию.

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "vault/common/bytes.hpp"

namespace vault::storage {

// Сырые данные snapshot'а, как они лежат на диске (недоверенные!).
struct RawObjectFile {
    std::string file_name;  // имя на диске, например "<hex file_id>.obj"
    Bytes data;             // должно быть CanonicalEncode(EncryptedFileV1)
};

struct RawSnapshot {
    std::uint64_t generation = 0;  // номер из имени директории (недоверенный)
    std::optional<Bytes> manifest;   // manifest.bin (M2+)
    std::optional<Bytes> signature;  // manifest.sig (M2+)
    std::vector<RawObjectFile> objects;
};

// Транзакционная запись нового snapshot'а:
//   new_snapshot = base_snapshot + put_object(...) - remove_object(...)
// Для GenerationStorage всё пишется в generations/<N+1>.tmp/, неизменённые
// объекты линкуются из базы при sync(); publish() = atomic rename.
// Для FlatStorage операции применяются на месте (без rollback-гарантий — это M1/M2).
class ISnapshotWriter {
public:
    virtual ~ISnapshotWriter() = default;
    virtual void put_object(const FileId& id, ByteView encoded_object) = 0;
    virtual void remove_object(const FileId& id) = 0;
    virtual void put_manifest(ByteView manifest, ByteView signature) = 0;
    // fsync всех файлов и директорий snapshot'а (§28 шаг 6).
    virtual void sync() = 0;
    // Атомарная публикация + fsync родителя (§28 шаг 7).
    virtual void publish() = 0;
    // Удаляет незавершённый snapshot. Вызывается и деструктором, если не было publish().
    virtual void abort() noexcept = 0;
};

class IStorageBackend {
public:
    virtual ~IStorageBackend() = default;

    virtual const std::filesystem::path& root() const = 0;
    virtual bool exists() const = 0;
    virtual void create_layout() = 0;  // ошибка, если уже существует

    // CT_KEM неизменен на всё время жизни хранилища (vault/kem.ct).
    virtual Bytes read_kem_ct() const = 0;
    virtual void write_kem_ct(ByteView ct) = 0;  // durable, только при init

    // Опубликованные поколения (без *.tmp). FlatStorage: {0}.
    virtual std::vector<std::uint64_t> list_generations() const = 0;
    virtual RawSnapshot read_snapshot(std::uint64_t generation) const = 0;
    // Ускоренное чтение одного объекта (для extract без загрузки всего snapshot'а
    // в память — только после того, как состояние проверено).
    virtual std::optional<Bytes> read_object(std::uint64_t generation, const FileId& id) const = 0;

    virtual std::unique_ptr<ISnapshotWriter> begin_snapshot(
        std::uint64_t new_generation, std::optional<std::uint64_t> base_generation) = 0;

    // Garbage collection (§28 шаг 9) и очистка orphan *.tmp после crash (§29).
    virtual void remove_generation(std::uint64_t generation) = 0;
    virtual std::vector<std::string> list_incomplete_snapshots() const = 0;
    virtual void remove_incomplete_snapshot(const std::string& name) = 0;
};

std::unique_ptr<IStorageBackend> make_flat_storage(const std::filesystem::path& vault_dir);
std::unique_ptr<IStorageBackend> make_generation_storage(const std::filesystem::path& vault_dir);

// Имя файла объекта на диске: "<32 hex>.obj".
std::string object_file_name(const FileId& id);

}  // namespace vault::storage
