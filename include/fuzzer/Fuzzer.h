#ifndef __FUZZER__
#define __FUZZER__

#include <iostream>
#include <string>
#include <cstring>
#include <fstream>
#include <sstream>

#include <unicorn/unicorn.h>

#include "Runtime.h"
#include "Memory.h"

using namespace std;

/* Unicorn
typedef enum uc_arch {
    UC_ARCH_ARM = 1,    // ARM 架构 (包括 Thumb, Thumb-2)
    UC_ARCH_ARM64,      // ARM-64, 也称 AArch64
    UC_ARCH_MIPS,       // Mips 架构
    UC_ARCH_X86,        // X86 架构 (包括 x86 & x86-64)
    UC_ARCH_PPC,        // PowerPC 架构 (暂不支持)
    UC_ARCH_SPARC,      // Sparc 架构
    UC_ARCH_M68K,       // M68K 架构
    UC_ARCH_MAX,
} uc_arch;
*/

/*
typedef enum uc_mode {
    UC_MODE_LITTLE_ENDIAN = 0,    // 小端序模式 (默认)
    UC_MODE_BIG_ENDIAN = 1 << 30, // 大端序模式

    // arm / arm64
    UC_MODE_ARM = 0,              // ARM 模式
    UC_MODE_THUMB = 1 << 4,       // THUMB 模式 (包括 Thumb-2)
    UC_MODE_MCLASS = 1 << 5,      // ARM's Cortex-M 系列 (暂不支持)
    UC_MODE_V8 = 1 << 6,          // ARMv8 A32 encodings for ARM (暂不支持)

    // arm (32bit) cpu 类型
    UC_MODE_ARM926 = 1 << 7,	  // ARM926 CPU 类型
    UC_MODE_ARM946 = 1 << 8,	  // ARM946 CPU 类型
    UC_MODE_ARM1176 = 1 << 9,	  // ARM1176 CPU 类型

    // mips
    UC_MODE_MICRO = 1 << 4,       // MicroMips 模式 (暂不支持)
    UC_MODE_MIPS3 = 1 << 5,       // Mips III ISA (暂不支持)
    UC_MODE_MIPS32R6 = 1 << 6,    // Mips32r6 ISA (暂不支持)
    UC_MODE_MIPS32 = 1 << 2,      // Mips32 ISA
    UC_MODE_MIPS64 = 1 << 3,      // Mips64 ISA

    // x86 / x64
    UC_MODE_16 = 1 << 1,          // 16-bit 模式
    UC_MODE_32 = 1 << 2,          // 32-bit 模式
    UC_MODE_64 = 1 << 3,          // 64-bit 模式

    // ppc 
    UC_MODE_PPC32 = 1 << 2,       // 32-bit 模式 (暂不支持)
    UC_MODE_PPC64 = 1 << 3,       // 64-bit 模式 (暂不支持)
    UC_MODE_QPX = 1 << 4,         // Quad Processing eXtensions 模式 (暂不支持)

    // sparc
    UC_MODE_SPARC32 = 1 << 2,     // 32-bit 模式
    UC_MODE_SPARC64 = 1 << 3,     // 64-bit 模式
    UC_MODE_V9 = 1 << 4,          // SparcV9 模式 (暂不支持)

    // m68k
} uc_mode;
*/

void hook_code(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data);


/**
Fuzzer模块,需在LLVMFuzzerTestOneInput中声明/调用，用于生成一个模糊测试的基本对象。
Fuzzer基于Unicorn来实现任意架构二进制文件模拟，通过hook函数来实现覆盖率检测和内存问题(原版libfuzzer使用插桩实现)。
优点：无需源代码，无需在意架构，fuzz anywhere，anything.
缺点：继承了一部分libfuzzer原理导致但缺点（但也解决了最大的痛点）
使用案例：
*/
class Fuzzer
{
public:
    Fuzzer(string target):target(target){}
    Fuzzer(string target, uint64_t start, uint64_t end, uc_arch arch, uc_mode mode):target(target){
        
        //初始化 运行时 和 内存映射 对象
        mem = &Memory::getInstance();
        rt = new Runtime(start,end);

        //载入目标 初始化Unicorn对象
        load_target();
        uc_open(arch, mode, &(this->uc));
        
        mem->set_env(uc,UC_ARCH_X86, UC_MODE_64,rt);
        if(!mem->mem_map(rt->base(),(size_t)target_size,UC_PROT_ALL))
            //cout << "Error : Please init the Memory before fuzzing!" << endl;
            abort();

        }
    Fuzzer(string target, uint64_t start, uint64_t end, uint64_t base ):target(target){ Runtime rt(start,end,base);}
    Fuzzer(string target, uint64_t start, uint64_t end, uint64_t base , uint64_t data):target(target){ Runtime rt(start,end,base,data);}
    
    ~Fuzzer(){
        delete[] bin_buffer; 
        uc_close(uc);
        }
    
    //void transfer_parameters_(uc_arch arch){}
    bool load_target();
    bool map_target()
    {
        mem->mem_map(this->rt->base(), 2 * 1024 * 1024, UC_PROT_ALL);
        mem->mem_write(this->rt->base(), bin_buffer, target_size - 1);
        return true;
    }
    void start(void* data,size_t size)
    {
        map_target();
        mem->init_arg(data,size);
        uc_hook code_hook,block_hook;
        err = uc_hook_add(uc, &code_hook, UC_HOOK_CODE, reinterpret_cast<void *>(hook_code), NULL, 1, 0);
        err=uc_emu_start(this->uc,rt->start(),rt->end(),0,0);
        if (err) {
            printf("Failed on uc_emu_start() with error returned %u: %s\n",
            err, uc_strerror(err));
            //if(err != 6) // ignore read error
            abort();
  }
    }
private:
    Runtime* rt;
    Memory* mem;
    string target;
    int target_size;
    char* bin_buffer;
    uc_engine *uc;
    uc_err err;
};

// 载入整个目标文件到内存中

inline bool Fuzzer::load_target()
{
    stringstream stringflow; 
    int size;

    ifstream in(target.c_str(),ios::in | ios::binary);
    if(!in.is_open())
    {
        cout << "Error opening file" << endl;
        return false;
    }

    stringflow << in.rdbuf();
    string file_flow(stringflow.str() );

    size = file_flow.length();
    bin_buffer = new char[size];
    
    if(!memcpy(bin_buffer,file_flow.c_str(),size-1))
    {
        cout << "Error memcpy binary" << endl;
        return false;
    }
    target_size = size;

    return true;
}

void hook_code(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data)
{
    printf("HOOK_CODE: 0x%" PRIx64 ", 0x%x\n", addr, size);
}


#endif
