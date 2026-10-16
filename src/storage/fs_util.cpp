#include "vault/storage/fs_util.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "vault/common/error.hpp"

namespace vault::storage {

namespace {

[[noreturn]] void io_fail(const std::string& what, const fs::path& p, int err = errno) {
    throw VaultError(ErrorCode::Io, what + " '" + p.string() + "': " + std::strerror(err));
}

struct Fd {
    int fd;
    explicit Fd(int f) : fd(f) {}
    ~Fd() { if (fd >= 0) ::close(fd); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
};

void write_all(int fd, const std::uint8_t* data, std::size_t len, const fs::path& p) {
    while (len > 0) {
        ssize_t n = ::write(fd, data, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            io_fail("write failed", p);
        }
        data += n;
        len -= static_cast<std::size_t>(n);
    }
}

void read_all(int fd, std::uint8_t* data, std::size_t len, const fs::path& p) {
    while (len > 0) {
        ssize_t n = ::read(fd, data, len);
        if (n < 0) {
            if (errno == EINTR) continue;
            io_fail("read failed", p);
        }
        if (n == 0) throw VaultError(ErrorCode::Io, "file changed while reading: " + p.string());
        data += n;
        len -= static_cast<std::size_t>(n);
    }
}

std::size_t open_and_size(const fs::path& path, Fd& out_fd) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) io_fail("cannot open", path);
    out_fd.fd = fd;
    struct stat st;
    if (::fstat(fd, &st) != 0) io_fail("fstat failed", path);
    if (!S_ISREG(st.st_mode)) throw VaultError(ErrorCode::Io, "not a regular file: " + path.string());
    return static_cast<std::size_t>(st.st_size);
}

}  // namespace

Bytes read_file(const fs::path& path) {
    Fd fd(-1);
    std::size_t size = open_and_size(path, fd);
    Bytes out(size);
    read_all(fd.fd, out.data(), size, path);
    return out;
}

SecureBytes read_file_secure(const fs::path& path) {
    Fd fd(-1);
    std::size_t size = open_and_size(path, fd);
    SecureBytes out(size);
    read_all(fd.fd, out.data(), size, path);
    return out;
}

void write_file_durable(const fs::path& path, ByteView data, unsigned mode) {
    int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, static_cast<mode_t>(mode));
    if (fd < 0) io_fail("cannot create", path);
    Fd guard(fd);
    try {
        write_all(fd, data.data(), data.size(), path);
        if (::fsync(fd) != 0) io_fail("fsync failed", path);
    } catch (...) {
        ::unlink(path.c_str());
        throw;
    }
}

void write_file_atomic_durable(const fs::path& path, ByteView data, unsigned mode) {
    fs::path tmp = path;
    tmp += ".tmp";
    ::unlink(tmp.c_str());  // остаток предыдущего сбоя
    write_file_durable(tmp, data, mode);
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        int err = errno;
        ::unlink(tmp.c_str());
        io_fail("rename failed", path, err);
    }
    fsync_dir(path.parent_path().empty() ? fs::path(".") : path.parent_path());
}

void fsync_path(const fs::path& path) {
    int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) io_fail("cannot open for fsync", path);
    Fd guard(fd);
    if (::fsync(fd) != 0) io_fail("fsync failed", path);
}

void fsync_dir(const fs::path& dir) { fsync_path(dir); }

void atomic_rename(const fs::path& from, const fs::path& to) {
    if (::rename(from.c_str(), to.c_str()) != 0) io_fail("rename failed", from);
    fsync_dir(to.parent_path().empty() ? fs::path(".") : to.parent_path());
}

void link_or_copy(const fs::path& from, const fs::path& to) {
    if (::link(from.c_str(), to.c_str()) == 0) return;
    Bytes data = read_file(from);
    write_file_durable(to, data);
}

}  // namespace vault::storage
