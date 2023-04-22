#include <cstdio>
#include <fstream>
#include "fuzzer/FuzzedDataProvider.h"
#include "libpe/pe.h"

std::string get_temp_file(const uint8_t* data, size_t size) noexcept {
    std::string tmpname = std::tmpnam(nullptr);

    std::ofstream tmpfile(tmpname, std::ios::out | std::ios::binary);
    if (!tmpfile.is_open()) {
        return "";
    }
    tmpfile.write(reinterpret_cast<const char*>(data), size);
    return tmpname;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    pe_ctx_t ctx;
    std::string fp = get_temp_file(data, size);

    if (fp.empty()) {
        return 0;
    }

    pe_err_e err = pe_load_file(&ctx, fp.c_str());
    if (err != LIBPE_E_OK) {
        pe_unload(&ctx);
        std::remove(fp.c_str());
        return -1;
    }

    err = pe_parse(&ctx);
    if (err != LIBPE_E_OK || !pe_is_pe(&ctx)) {
        pe_unload(&ctx);
        std::remove(fp.c_str());
        return -1;
    }

    pe_unload(&ctx);
    std::remove(fp.c_str());

    return 0;
}
