#include "fuzzer/Fuzzer.h"

void Hook(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data)
{
    //if(addr == 0x401180)
        //cout << "hello fuzzer!"<< endl;
#ifdef __DEBUG__
        printf("HOOK_CODE: 0x%" PRIx64 ", 0x%x\n", addr, size);
        if(addr == 0x401350)
        {
            register_display<AMD64>(uc);
            stack_display<AMD64>(uc);
            sleep(2);
        }
#endif

}

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {

    //VulnerableFunction(data,size,data);
    //注：函数的入口地址可以通过objdump -S来查找
    //Fuzzer fuzzer("vuln.so",0x401180,0x40125C,UC_ARCH_X86, UC_MODE_64); //参数意义：fuzz目标、函数入口地址、函数出口地址、处理器架构、运行模式
    //Fuzzer fuzzer("vuln.so",0x1180,0x125C,UC_ARCH_X86, UC_MODE_64); //参数意义：fuzz目标、函数入口地址、函数出口地址、处理器架构、运行模式
    //Fuzzer fuzzer("vuln.so",0x1260,0x1343,UC_ARCH_X86, UC_MODE_64); //参数意义：fuzz目标、函数入口地址、函数出口地址、处理器架构、运行模式
    Fuzzer fuzzer("vuln.so",0x1350,0x1440,UC_ARCH_X86, UC_MODE_64); //参数意义：fuzz目标、函数入口地址、函数出口地址、处理器架构、运行模式
    
    fuzzer.entrance(data,size);     //  void* data,size_t size
    fuzzer.add_hook(CODE,Hook);     //  使用者自定义Hook函数
    //fuzzer.start(DATA,size,DATA);   //  输入函数对应参数
    //fuzzer.start(DATA,(double)size,DATA);   //  输入函数对应参数
    //bool VulnerableFunction4(uint8_t* data, size_t userless1, size_t useless2, size_t useless3,size_t useless4,size_t useless5,size_t size,uint8_t* data2)
    fuzzer.start(DATA,0,0,0,0,0,size,DATA);   //  输入函数对应参数

    return 0;
}
