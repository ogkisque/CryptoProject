// FlatStorage (этапы 1-2): одно изменяемое "поколение 0".
//   vault/kem.ct, vault/objects/<hex file_id>.obj, (M2) vault/manifest.bin, manifest.sig
// Никаких проверок: хранилище недоверенное, всё проверяет StateVerifier.
#include <algorithm>
#include <system_error>

#include "vault/common/error.hpp"
#include "vault/storage/fs_util.hpp"
#include "vault/storage/storage_backend.hpp"

namespace vault::storage {

std::string object_file_name(const FileId& id) { return to_hex(as_view(id)) + ".obj"; }

namespace {

class FlatWriter final : public ISnapshotWriter {
public:
    explicit FlatWriter(fs::path root) : root_(std::move(root)) {}

    // tmp пишется в корень vault (не в objects/): после сбоя посреди записи
    // в objects/ не остаётся постороннего файла, который сломал бы проверку.
    void put_object(const FileId& id, ByteView data) override {
        std::string name = object_file_name(id);
        fs::path tmp = root_ / (name + ".tmp");
        fs::remove(tmp);
        write_file_durable(tmp, data);
        atomic_rename(tmp, root_ / "objects" / name);  // + fsync(objects/)
        fsync_dir(root_);
    }
    void remove_object(const FileId& id) override {
        std::error_code ec;
        if (!fs::remove(root_ / "objects" / object_file_name(id), ec) || ec)
            throw VaultError(ErrorCode::NotFound, "object file does not exist");
        fsync_dir(root_ / "objects");
    }
    void put_manifest(ByteView manifest, ByteView signature) override {
        write_file_atomic_durable(root_ / "manifest.bin", manifest);
        write_file_atomic_durable(root_ / "manifest.sig", signature);
    }
    void sync() override {
        fsync_dir(root_ / "objects");
        fsync_dir(root_);
    }
    void publish() override { fsync_dir(root_); }
    void abort() noexcept override {}  // изменения применяются на месте, откатывать нечего

private:
    fs::path root_;
};

class FlatStorage final : public IStorageBackend {
public:
    explicit FlatStorage(fs::path root) : root_(std::move(root)) {}

    const fs::path& root() const override { return root_; }
    bool exists() const override { return fs::is_directory(root_); }

    void create_layout() override {
        if (fs::exists(root_)) throw VaultError(ErrorCode::AlreadyExists, "vault directory already exists: " + root_.string());
        fs::create_directories(root_ / "objects");
        fsync_dir(root_);
        fsync_dir(root_.parent_path().empty() ? fs::path(".") : root_.parent_path());
    }

    Bytes read_kem_ct() const override { return read_file(root_ / "kem.ct"); }
    void write_kem_ct(ByteView ct) override { write_file_atomic_durable(root_ / "kem.ct", ct); }

    std::vector<std::uint64_t> list_generations() const override { return {0}; }

    RawSnapshot read_snapshot(std::uint64_t) const override {
        RawSnapshot snap;
        snap.generation = 0;
        std::vector<fs::path> files;
        for (const auto& entry : fs::directory_iterator(root_ / "objects")) {
            if (entry.is_symlink() || !entry.is_regular_file())
                throw VaultError(ErrorCode::FormatError, "non-regular entry in objects/: " + entry.path().string());
            files.push_back(entry.path());
        }
        std::sort(files.begin(), files.end());
        for (const auto& f : files) snap.objects.push_back({f.filename().string(), read_file(f)});
        if (fs::exists(root_ / "manifest.bin")) snap.manifest = read_file(root_ / "manifest.bin");
        if (fs::exists(root_ / "manifest.sig")) snap.signature = read_file(root_ / "manifest.sig");
        return snap;
    }

    std::optional<Bytes> read_object(std::uint64_t, const FileId& id) const override {
        fs::path p = root_ / "objects" / object_file_name(id);
        if (!fs::exists(p)) return std::nullopt;
        return read_file(p);
    }

    std::unique_ptr<ISnapshotWriter> begin_snapshot(std::uint64_t, std::optional<std::uint64_t>) override {
        return std::make_unique<FlatWriter>(root_);
    }

    void remove_generation(std::uint64_t) override {
        throw VaultError(ErrorCode::InvalidArgument, "FlatStorage has no removable generations");
    }
    std::vector<std::string> list_incomplete_snapshots() const override { return {}; }
    void remove_incomplete_snapshot(const std::string&) override {}

private:
    fs::path root_;
};

}  // namespace

std::unique_ptr<IStorageBackend> make_flat_storage(const fs::path& vault_dir) {
    return std::make_unique<FlatStorage>(vault_dir);
}

}  // namespace vault::storage
