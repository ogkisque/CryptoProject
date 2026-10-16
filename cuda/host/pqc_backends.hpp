#pragma once
// IKemBackend / ISigBackend поверх runner'а (cuda/host/pqc_runner.hpp). Не зависит от CUDA: собирается и
// тестируется всегда; CUDA-реализации runner'ов — cuda/src/gpu_{kem,sig}_backend.cu.

#include <memory>

#include "host/pqc_runner.hpp"
#include "vault/crypto/kem_backend.hpp"
#include "vault/crypto/sig_backend.hpp"

namespace vault::gpu {

std::shared_ptr<crypto::IKemBackend> make_pqc_kem_backend(std::unique_ptr<IMlKemRunner> runner);

// Что именно подписывает/проверяет cuPQC ML-DSA, если ему отдать сообщение M (документация context string не
// описывает — определяется калибровкой при первом использовании, см. pqc_backends.cpp):
enum class SigContextMode {
    Unknown,           // калибровка ещё не выполнялась
    Internal,          // сообщение трактуется как M' (ML-DSA.Sign_internal): ctx реализуется сборкой
                       //   M' = 0x00 || len(ctx) || ctx || M на стороне вызывающего -> полная совместимость с FIPS 204
    PureEmptyContext,  // cuPQC сам подписывает «pure» с ПУСТЫМ ctx: пригодно только при ctx = ""
    Unusable,          // подписи несовместимы с liboqs ни так, ни так
};

// cpu_reference — CPU-реализация (liboqs): нужна для калибровки и как единичный fallback (sign/verify по
// одному) для контекстов, которые GPU не поддерживает; batch-вызовы без поддержки контекста бросают
// BackendUnavailable, чтобы benchmark пометил их как skipped, а не выдал CPU-замер за GPU.
std::shared_ptr<crypto::ISigBackend> make_pqc_sig_backend(std::unique_ptr<IMlDsaRunner> runner,
                                                         std::shared_ptr<crypto::ISigBackend> cpu_reference);

// Выполняет (при необходимости) калибровку и возвращает режим. Бросает InvalidArgument, если backend не создан
// make_pqc_sig_backend.
SigContextMode sig_context_mode(crypto::ISigBackend& backend);

}  // namespace vault::gpu
