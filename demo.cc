#include "fuzzer/Fuzzer.h"

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    //VulnerableFunctionx(data,size,data);
    Fuzzer fuzzer("vuln.so",0x401100,0x40117C,UC_ARCH_X86, UC_MODE_64);
    fuzzer.start(data,size);
    return 0;
}