// GenerationStorage (этап 3): immutable поколения (docs/format_v1.md §10).
//   vault/kem.ct
//   vault/generations/<%016x>/{objects/<hex file_id>.obj, manifest.bin, manifest.sig}
//   vault/generations/<%016x>.tmp/   — незавершённое поколение (orphan после crash)
// Неизменённые объекты переходят в новое поколение hardlink'ом (решение L-1): файлы объектов
// никогда не переписываются на месте. Никаких проверок доверия — только перемещение байт.
#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <set>
#include <system_error>

#include "vault/common/error.hpp"
#include "vault/storage/fs_util.hpp"
#include "vault/storage/storage_backend.hpp"

namespace vault::storage {

namespace {

constexpr const char* kTmpSuffix = ".tmp";

std::string generation_name(std::uint64_t g) {
    char buf[32];
    std::snprintf(buf, sizeof buf, "%016" PRIx64, g);
    return buf;
}

// Ровно 16 hex-цифр нижнего регистра.
std::optional<std::uint64_t> parse_generation_name(const std::string& s) {
    if (s.size() != 16) return std::nullopt;
    std::uint64_t v = 0;
    for (char c : s) {
        int d;
        if (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else return std::nullopt;
        v = (v << 4) | static_cast<std::uint64_t>(d);
    }
    return v;
}

bool is_tmp_name(const std::string& s) {
    const std::string suf = kTmpSuffix;
    return s.size() == 16 + suf.size() && s.compare(16, suf.size(), suf) == 0 &&
           parse_generation_name(s.substr(0, 16)).has_value();
}

class GenerationWriter final : public ISnapshotWriter {
public:
    GenerationWriter(fs::path gens, std::uint64_t gen, std::optional<std::uint64_t> base)
        : gens_(std::move(gens)), name_(generation_name(gen)), tmp_(gens_ / (name_ + kTmpSuffix)),
          final_(gens_ / name_), base_(base ? std::optional<fs::path>(gens_ / generation_name(*base)) : std::nullopt) {
        std::error_code ec;
        fs::remove_all(tmp_, ec);  // остаток прерванной попытки
        fs::create_directories(tmp_ / "objects");
    }
    ~GenerationWriter() override {
        if (!published_) abort();
    }

    void put_object(const FileId& id, ByteView data) override {
        std::string n = object_file_name(id);
        removed_.erase(n);
        write_file_durable(tmp_ / "objects" / n, data);
        written_.insert(n);
    }
    void remove_object(const FileId& id) override {
        std::string n = object_file_name(id);
        bool in_new = written_.erase(n) > 0;
        if (in_new) {
            fs::remove(tmp_ / "objects" / n);
        } else if (!base_ || !fs::exists(*base_ / "objects" / n)) {
            throw VaultError(ErrorCode::NotFound, "object file does not exist");
        }
        removed_.insert(n);
    }
    void put_manifest(ByteView manifest, ByteView signature) override {
        write_file_durable(tmp_ / "manifest.bin", manifest);
        write_file_durable(tmp_ / "manifest.sig", signature);
    }
    void sync() override {
        if (synced_) return;
        if (base_) {
            for (const auto& e : fs::directory_iterator(*base_ / "objects")) {
                std::string n = e.path().filename().string();
                if (removed_.count(n) || written_.count(n)) continue;
                link_or_copy(e.path(), tmp_ / "objects" / n);
            }
        }
        fsync_dir(tmp_ / "objects");
        fsync_dir(tmp_);
        synced_ = true;
    }
    void publish() override {
        if (!synced_) sync();
        if (fs::exists(final_)) throw VaultError(ErrorCode::AlreadyExists, "generation already exists: " + name_);
        atomic_rename(tmp_, final_);  // rename + fsync(generations/)
        published_ = true;
    }
    void abort() noexcept override {
        std::error_code ec;
        fs::remove_all(tmp_, ec);
        published_ = true;  // повторно не вызывать
    }

private:
    fs::path gens_;
    std::string name_;
    fs::path tmp_, final_;
    std::optional<fs::path> base_;
    std::set<std::string> written_, removed_;
    bool synced_ = false, published_ = false;
};

class GenerationStorage final : public IStorageBackend {
public:
    explicit GenerationStorage(fs::path root) : root_(std::move(root)), gens_(root_ / "generations") {}

    const fs::path& root() const override { return root_; }
    bool exists() const override { return fs::is_directory(root_); }

    void create_layout() override {
        if (fs::exists(root_)) throw VaultError(ErrorCode::AlreadyExists, "vault directory already exists: " + root_.string());
        fs::create_directories(gens_);
        fsync_dir(gens_);
        fsync_dir(root_);
        fsync_dir(root_.parent_path().empty() ? fs::path(".") : root_.parent_path());
    }

    Bytes read_kem_ct() const override { return read_file(root_ / "kem.ct"); }
    void write_kem_ct(ByteView ct) override { write_file_atomic_durable(root_ / "kem.ct", ct); }

    std::vector<std::uint64_t> list_generations() const override {
        std::vector<std::uint64_t> out;
        if (!fs::is_directory(gens_)) return out;
        for (const auto& e : fs::directory_iterator(gens_)) {
            if (e.is_symlink() || !e.is_directory()) continue;
            if (auto g = parse_generation_name(e.path().filename().string())) out.push_back(*g);
        }
        std::sort(out.begin(), out.end());
        return out;
    }

    RawSnapshot read_snapshot(std::uint64_t generation) const override {
        fs::path dir = gens_ / generation_name(generation);
        if (fs::is_symlink(dir) || !fs::is_directory(dir))
            throw VaultError(ErrorCode::NotFound, "generation " + std::to_string(generation) + " does not exist");
        RawSnapshot snap;
        snap.generation = generation;
        std::vector<fs::path> files;
        if (!fs::is_directory(dir / "objects"))
            throw VaultError(ErrorCode::FormatError, "generation has no objects/ directory");
        for (const auto& entry : fs::directory_iterator(dir / "objects")) {
            if (entry.is_symlink() || !entry.is_regular_file())
                throw VaultError(ErrorCode::FormatError, "non-regular entry in objects/: " + entry.path().string());
            files.push_back(entry.path());
        }
        std::sort(files.begin(), files.end());
        for (const auto& f : files) snap.objects.push_back({f.filename().string(), read_file(f)});
        if (fs::exists(dir / "manifest.bin")) snap.manifest = read_file(dir / "manifest.bin");
        if (fs::exists(dir / "manifest.sig")) snap.signature = read_file(dir / "manifest.sig");
        return snap;
    }

    std::optional<Bytes> read_object(std::uint64_t generation, const FileId& id) const override {
        fs::path p = gens_ / generation_name(generation) / "objects" / object_file_name(id);
        if (!fs::exists(p)) return std::nullopt;
        return read_file(p);
    }

    std::unique_ptr<ISnapshotWriter> begin_snapshot(std::uint64_t new_generation,
                                                    std::optional<std::uint64_t> base_generation) override {
        return std::make_unique<GenerationWriter>(gens_, new_generation, base_generation);
    }

    void remove_generation(std::uint64_t generation) override {
        std::error_code ec;
        fs::remove_all(gens_ / generation_name(generation), ec);
        if (ec) throw VaultError(ErrorCode::Io, "cannot remove generation: " + ec.message());
        fsync_dir(gens_);
    }

    std::vector<std::string> list_incomplete_snapshots() const override {
        std::vector<std::string> out;
        if (!fs::is_directory(gens_)) return out;
        for (const auto& e : fs::directory_iterator(gens_)) {
            std::string n = e.path().filename().string();
            if (is_tmp_name(n)) out.push_back(n);
        }
        std::sort(out.begin(), out.end());
        return out;
    }

    void remove_incomplete_snapshot(const std::string& name) override {
        if (!is_tmp_name(name)) throw VaultError(ErrorCode::InvalidArgument, "not an incomplete snapshot name");
        std::error_code ec;
        fs::remove_all(gens_ / name, ec);
        if (ec) throw VaultError(ErrorCode::Io, "cannot remove incomplete snapshot: " + ec.message());
        fsync_dir(gens_);
    }

private:
    fs::path root_, gens_;
};

}  // namespace

std::unique_ptr<IStorageBackend> make_generation_storage(const fs::path& vault_dir) {
    return std::make_unique<GenerationStorage>(vault_dir);
}

}  // namespace vault::storage
