#include "fuzzer/Fuzzer.h"

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {

    //VulnerableFunctionx(data,size,data);
    //注：函数的入口地址可以通过objdump -S来查找
    //Fuzzer fuzzer("vuln.so",0x401100,0x40117C,UC_ARCH_X86, UC_MODE_64); //参数意义：fuzz目标、函数入口地址、函数出口地址、处理器架构、运行模式
    Fuzzer fuzzer("vuln.so",0x401180,0x40125C,UC_ARCH_X86, UC_MODE_64); //参数意义：fuzz目标、函数入口地址、函数出口地址、处理器架构、运行模式
    //Fuzzer fuzzer("vuln.so",0x1180,0x125C,UC_ARCH_X86, UC_MODE_64); //参数意义：fuzz目标、函数入口地址、函数出口地址、处理器架构、运行模式
    //Fuzzer fuzzer("vuln3.so",0x590,0x66c,UC_ARCH_X86, UC_MODE_64); //参数意义：fuzz目标、函数入口地址、函数出口地址、处理器架构、运行模式
    fuzzer.entrance(data,size);     //  void* data,size_t size
    fuzzer.start(DATA,size,DATA);   //  输入函数对应参数

    return 0;
}
