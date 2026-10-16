#pragma once
// Иерархия ошибок. Любая криптографическая/форматная ошибка — исключение;
// частичные результаты (особенно plaintext) вызывающей стороне не отдаются.

#include <stdexcept>
#include <string>

namespace vault {

enum class ErrorCode {
    Internal,
    InvalidArgument,
    Io,                    // ошибки файловой системы
    FormatError,           // нарушение канонического формата (длины, trailing data, ...)
    UnsupportedVersion,    // format_version / crypto_suite_id не поддерживаются
    CryptoError,           // ошибка библиотеки (OpenSSL/liboqs/cuPQC)
    AuthenticationFailed,  // GCM tag / AES-KW integrity check / подпись
    StateVerification,     // см. VerificationError
    NotFound,
    AlreadyExists,
    BackendUnavailable,    // например, GPU backend без CUDA
};

class VaultError : public std::runtime_error {
public:
    VaultError(ErrorCode code, const std::string& what) : std::runtime_error(what), code_(code) {}
    ErrorCode code() const noexcept { return code_; }

private:
    ErrorCode code_;
};

// Шаг проверки состояния (§27, §52), на котором обнаружено нарушение.
// Тесты атак проверяют не только факт ошибки, но и ожидаемый шаг.
enum class VerifyStep {
    LoadTrustedState,
    LoadManifest,
    ManifestParse,
    FormatVersion,
    CryptoSuite,
    StorageUuidMismatch,
    KemKeyId,
    SigKeyId,
    Signature,
    Generation,
    ManifestHash,
    KemCtHash,
    ObjectParse,
    ObjectBinding,  // storage_uuid / format_version / suite объекта
    ObjectNameMismatch,  // имя файла объекта на диске != file_id внутри
    DuplicateFileId,
    FileCount,
    MerkleRoot,
};

const char* to_string(VerifyStep step) noexcept;

class VerificationError : public VaultError {
public:
    VerificationError(VerifyStep step, const std::string& what)
        : VaultError(ErrorCode::StateVerification, what), step_(step) {}
    VerifyStep step() const noexcept { return step_; }

private:
    VerifyStep step_;
};

}  // namespace vault
