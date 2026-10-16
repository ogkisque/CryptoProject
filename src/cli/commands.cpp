#include "commands.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

#include "vault/common/error.hpp"
#include "vault/storage/fs_util.hpp"

namespace vault::cli {

namespace {

FileId parse_file_id(const std::string& hex) {
    auto id = file_id_from_hex(hex);
    if (!id) throw VaultError(ErrorCode::InvalidArgument, "file_id must be 32 hex characters");
    return *id;
}

Vault open_vault(const GlobalOptions& g) {
    return Vault::open(g.paths, crypto::make_backends(g.backend));
}

// Имя из недоверенного (с точки зрения FS) plaintext -> безопасное имя в текущей директории.
std::filesystem::path sanitize_filename(const std::string& name) {
    std::filesystem::path base = std::filesystem::path(name).filename();
    std::string s = base.string();
    if (s.empty() || s == "." || s == ".." || s.find('/') != std::string::npos ||
        s.find('\0') != std::string::npos)
        return "extracted.bin";
    return base;
}

void write_output(const std::filesystem::path& path, ByteView data, bool force) {
    int flags = O_WRONLY | O_CREAT | O_CLOEXEC | (force ? O_TRUNC : O_EXCL);
    int fd = ::open(path.c_str(), flags, 0600);
    if (fd < 0) {
        if (errno == EEXIST)
            throw VaultError(ErrorCode::AlreadyExists, "output file exists (use --force): " + path.string());
        throw VaultError(ErrorCode::Io, "cannot create '" + path.string() + "': " + std::strerror(errno));
    }
    const std::uint8_t* p = data.data();
    std::size_t left = data.size();
    while (left > 0) {
        ssize_t n = ::write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            int e = errno;
            ::close(fd);
            throw VaultError(ErrorCode::Io, std::string("write failed: ") + std::strerror(e));
        }
        p += n;
        left -= static_cast<std::size_t>(n);
    }
    ::fsync(fd);
    ::close(fd);
}

}  // namespace

int cmd_init(const GlobalOptions& g) {
    Vault::init(g.paths, crypto::make_backends(g.backend));
    std::cout << "initialized vault: " << g.paths.vault_dir.string()
              << "\ntrusted area:      " << g.paths.trusted_dir.string() << "\n";
    return 0;
}

int cmd_add(const GlobalOptions& g, const std::filesystem::path& file) {
    Vault v = open_vault(g);
    FileId id = v.add_file(file);
    std::cout << to_hex(as_view(id)) << "\n";
    return 0;
}

int cmd_extract(const GlobalOptions& g, const std::string& file_id_hex,
                const std::optional<std::filesystem::path>& output, bool force) {
    FileId id = parse_file_id(file_id_hex);
    Vault v = open_vault(g);
    ExtractedFile f = v.extract(id);  // бросает исключение при ошибке аутентификации — файл не создаётся
    std::filesystem::path out = output ? *output : sanitize_filename(f.filename);
    write_output(out, f.data.view(), force);
    std::cout << "extracted '" << f.filename << "' -> " << out.string() << " (" << f.data.size() << " bytes)\n";
    return 0;
}

int cmd_remove(const GlobalOptions& g, const std::string& file_id_hex) {
    FileId id = parse_file_id(file_id_hex);
    Vault v = open_vault(g);
    v.remove(id);
    std::cout << "removed " << to_hex(as_view(id)) << "\n";
    return 0;
}

int cmd_list(const GlobalOptions& g, bool show_names) {
    Vault v = open_vault(g);
    for (const ObjectInfo& o : v.list(show_names)) {
        std::cout << to_hex(as_view(o.file_id)) << "  " << o.ciphertext_size;
        if (o.filename) std::cout << "  " << *o.filename;
        std::cout << "\n";
    }
    return 0;
}

int cmd_verify(const GlobalOptions& g) {
    Vault v = open_vault(g);  // open уже включает полную проверку
    core::VerifyReport r = v.verify();
    if (g.verbose)
        std::cout << "objects: " << r.state.objects.size() << ", generation: " << r.state.generation << "\n";
    std::cout << "VALID (stage 1: object structure only; Merkle/Manifest checks come in stage 2)\n";
    return 0;
}

int cmd_gc(const GlobalOptions& g) {
    Vault v = open_vault(g);
    std::cout << "removed " << v.garbage_collect() << " stale generation(s)\n";
    return 0;
}

int cmd_benchmark(const GlobalOptions&, const std::filesystem::path&) {
    std::cerr << "benchmark: not implemented yet (stage 4)\n";
    return 1;
}

}  // namespace vault::cli
