#include <sys/stat.h>

#include "vault/common/error.hpp"
#include "vault/storage/crash_injection.hpp"
#include "vault/encoding/trusted_state.hpp"
#include "vault/storage/fs_util.hpp"
#include "vault/storage/trusted_storage.hpp"

namespace vault::storage {

namespace {

class FileTrustedStorage final : public ITrustedStorage {
public:
    explicit FileTrustedStorage(fs::path dir) : dir_(std::move(dir)) {}

    bool exists() const override { return fs::exists(state_path()); }

    void initialize(const TrustedKeys& keys, const encoding::TrustedStateV1& state) override {
        if (fs::exists(dir_)) throw VaultError(ErrorCode::AlreadyExists, "trusted directory already exists: " + dir_.string());
        if (keys.kem_pk.size() != kMlKem768PublicKeySize || keys.kem_sk.size() != kMlKem768SecretKeySize)
            throw VaultError(ErrorCode::InvalidArgument, "bad ML-KEM key sizes");
        make_private_dir(dir_);
        make_private_dir(dir_ / "keys");
        write_file_durable(dir_ / "keys" / "kem.pk", keys.kem_pk, 0600);
        write_file_durable(dir_ / "keys" / "kem.sk", keys.kem_sk.view(), 0600);
        if (keys.sig_pk) write_file_durable(dir_ / "keys" / "sig.pk", *keys.sig_pk, 0600);
        if (keys.sig_sk) write_file_durable(dir_ / "keys" / "sig.sk", keys.sig_sk->view(), 0600);
        fsync_dir(dir_ / "keys");
        // trusted_state.bin пишется последним: его наличие = инициализация завершена.
        write_file_atomic_durable(state_path(), encoding::encode_trusted_state(state), 0600);
        fsync_dir(dir_);
    }

    encoding::TrustedStateV1 load_state() const override {
        return encoding::decode_trusted_state(read_file(state_path()));
    }

    TrustedPublicKeys load_public_keys() const override {
        TrustedPublicKeys k;
        k.kem_pk = read_file(dir_ / "keys" / "kem.pk");
        if (k.kem_pk.size() != kMlKem768PublicKeySize)
            throw VaultError(ErrorCode::FormatError, "kem.pk has wrong size");
        if (fs::exists(dir_ / "keys" / "sig.pk")) k.sig_pk = read_file(dir_ / "keys" / "sig.pk");
        return k;
    }

    SecureBytes load_kem_secret_key() const override {
        SecureBytes sk = read_file_secure(dir_ / "keys" / "kem.sk");
        if (sk.size() != kMlKem768SecretKeySize) throw VaultError(ErrorCode::FormatError, "kem.sk has wrong size");
        return sk;
    }

    SecureBytes load_sig_secret_key() const override {
        if (!fs::exists(dir_ / "keys" / "sig.sk")) throw VaultError(ErrorCode::NotFound, "no signing key (stage 2)");
        return read_file_secure(dir_ / "keys" / "sig.sk");
    }

    // §28 шаг 8: tmp + fsync, затем rename + fsync(dir). Между ними — crash-точка.
    void update_state(const encoding::TrustedStateV1& state) override {
        fs::path tmp = state_path();
        tmp += ".tmp";
        std::error_code ec;
        fs::remove(tmp, ec);  // остаток прежнего сбоя
        write_file_durable(tmp, encoding::encode_trusted_state(state), 0600);
        crash_here(CrashPoint::DuringTrustedUpdate);
        atomic_rename(tmp, state_path());
    }

private:
    fs::path state_path() const { return dir_ / "trusted_state.bin"; }
    static void make_private_dir(const fs::path& p) {
        fs::create_directories(p);
        ::chmod(p.c_str(), 0700);
    }
    fs::path dir_;
};

}  // namespace

std::unique_ptr<ITrustedStorage> make_file_trusted_storage(const fs::path& dir) {
    return std::make_unique<FileTrustedStorage>(dir);
}

}  // namespace vault::storage
