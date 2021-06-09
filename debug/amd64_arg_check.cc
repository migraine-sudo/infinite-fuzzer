#include "fuzzer/Fuzzer.h"

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {

    //VulnerableFunctionx(data,size,data);

    //Fuzzer fuzzer("debug/int_debug",0x401130,0x401173,UC_ARCH_X86, UC_MODE_64); //参数意义：fuzz目标、函数入口地址、函数出口地址、处理器架构、运行模式
    Fuzzer fuzzer("debug/int_debug",0x401130,0x40119E,UC_ARCH_X86, UC_MODE_64); //参数意义：fuzz目标、函数入口地址、函数出口地址、处理器架构、运行模式
    fuzzer.entrance(data,size);           //  void* data,size_t size
    fuzzer.skip(0x401173,0x401194);          // 需要跳过的指令(系统调用、Libc函数)
    int num{1};
    fuzzer.start(num,++num,++num,++num,++num,++num,++num,++num);   //  输入函数对应参数
    sleep(10);
    return 0;
}