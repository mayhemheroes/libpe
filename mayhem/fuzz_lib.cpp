#include <cstdio>
#include "fuzzer/FuzzedDataProvider.h"
#include "libpe/pe.h"

std::string get_temp_file(FuzzedDataProvider& fdp) noexcept {
    std::string tmpname = std::tmpnam(nullptr);

    std::FILE *tmpf = std::fopen(tmpname.c_str(), "w+");
    if (!tmpf) {
        return "";
    }
    std::fputs(fdp.ConsumeRemainingBytesAsString().c_str(), tmpf);
    std::fclose(tmpf);
    return tmpname;
}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    pe_ctx_t ctx;
    std::string fp = get_temp_file(fdp);
    if (fp == "") {
        return 0;
    }
    pe_err_e err = pe_load_file(&ctx, fp.c_str());
    if (err != LIBPE_E_OK) {
        pe_unload(&ctx);
        return -1;
    }

    err = pe_parse(&ctx);
    if (err != LIBPE_E_OK || !pe_is_pe(&ctx)) {
        pe_unload(&ctx);
        return -1;
    }

    pe_unload(&ctx);

    return 0;
}
