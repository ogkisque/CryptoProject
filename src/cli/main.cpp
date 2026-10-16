#include <CLI/CLI.hpp>
#include <cstdlib>
#include <iostream>

#include "commands.hpp"
#include "vault/common/error.hpp"

using namespace vault;

namespace {

std::string env_or(const char* name, const char* fallback) {
    const char* v = std::getenv(name);
    return (v && *v) ? v : fallback;
}

int report_error(const std::exception& e) {
    if (auto* ve = dynamic_cast<const VerificationError*>(&e)) {
        std::cerr << "INVALID: " << to_string(ve->step()) << ": " << ve->what() << "\n";
        return 2;
    }
    if (auto* v = dynamic_cast<const VaultError*>(&e)) {
        std::cerr << "error: " << v->what() << "\n";
        return v->code() == ErrorCode::AuthenticationFailed ? 2 : 1;
    }
    std::cerr << "error: " << e.what() << "\n";
    return 1;
}

}  // namespace

int main(int argc, char** argv) {
    CLI::App app{"edu-vault: secure file vault with post-quantum key protection"};
    app.require_subcommand(1);

    std::string vault_dir = env_or("VAULT_DIR", "./vault");
    std::string trusted_dir = env_or("VAULT_TRUSTED_DIR", "./trusted");
    std::string backend = "cpu";
    bool verbose = false;
    app.add_option("--vault", vault_dir, "untrusted vault directory (env VAULT_DIR)");
    app.add_option("--trusted", trusted_dir, "trusted area directory (env VAULT_TRUSTED_DIR)");
    app.add_option("--backend", backend, "cpu | cpu-mt | gpu")->check(CLI::IsMember({"cpu", "cpu-mt", "gpu"}));
    app.add_flag("-v,--verbose", verbose);

    int rc = 0;
    auto run = [&](auto&& fn) {
        try {
            cli::GlobalOptions g;
            g.paths = {vault_dir, trusted_dir};
            g.backend.kind = crypto::parse_backend_kind(backend);
            g.verbose = verbose;
            rc = fn(g);
        } catch (const std::exception& e) {
            rc = report_error(e);
        }
    };

    app.add_subcommand("init", "create a new vault")->callback([&] { run(cli::cmd_init); });

    std::string add_path;
    auto* add = app.add_subcommand("add", "encrypt and add a file");
    add->add_option("file", add_path)->required();
    add->callback([&] { run([&](auto& g) { return cli::cmd_add(g, add_path); }); });

    std::string ex_id, ex_out;
    bool ex_force = false;
    auto* ex = app.add_subcommand("extract", "decrypt a file");
    ex->add_option("file_id", ex_id)->required();
    ex->add_option("-o,--output", ex_out, "output path (default: original filename in cwd)");
    ex->add_flag("-f,--force", ex_force, "overwrite existing output");
    ex->callback([&] {
        run([&](auto& g) {
            std::optional<std::filesystem::path> out;
            if (!ex_out.empty()) out = ex_out;
            return cli::cmd_extract(g, ex_id, out, ex_force);
        });
    });

    std::string rm_id;
    auto* rm = app.add_subcommand("remove", "remove a file");
    rm->add_option("file_id", rm_id)->required();
    rm->callback([&] { run([&](auto& g) { return cli::cmd_remove(g, rm_id); }); });

    bool names = false;
    auto* ls = app.add_subcommand("list", "list files");
    ls->add_flag("--names", names, "decrypt and show original filenames");
    ls->callback([&] { run([&](auto& g) { return cli::cmd_list(g, names); }); });

    app.add_subcommand("verify", "verify vault state")->callback([&] { run(cli::cmd_verify); });
    app.add_subcommand("gc", "remove stale generations")->callback([&] { run(cli::cmd_gc); });

    std::string bench_cfg;
    auto* bench = app.add_subcommand("benchmark", "CPU/GPU benchmark");
    bench->add_option("--config", bench_cfg);
    bench->callback([&] { run([&](auto& g) { return cli::cmd_benchmark(g, bench_cfg); }); });

    try {
        app.parse(argc, argv);
    } catch (const CLI::ParseError& e) {
        return app.exit(e);
    }
    return rc;
}
