#pragma once
// FilePlaintext (§13) — то, что шифруется AES-GCM:
//   u32 filename_length || filename (UTF-8) || u64 file_data_length || file_data

#include <string>

#include "vault/common/bytes.hpp"
#include "vault/common/secure_buffer.hpp"

namespace vault::encoding {

struct FilePlaintext {
    std::string filename;  // UTF-8, валидируется при decode
    SecureBytes file_data;
};

// Результат — секрет (содержит plaintext), поэтому SecureBytes.
SecureBytes encode_file_plaintext(std::string_view filename, ByteView file_data);

// Строгий разбор: длины, UTF-8, kMaxFilenameLength, отсутствие trailing data.
FilePlaintext decode_file_plaintext(ByteView encoded);

}  // namespace vault::encoding
