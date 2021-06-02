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
#include "Debug.h"

#define PCS_N (1 << 12)

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


//初始化全局变量给hook函数
uint64_t data_size;
uint64_t data_addr;

__attribute__((section("__libfuzzer_extra_counters")))
uint8_t Counters[PCS_N];
uint16_t  prevPR = 0;

//扩展用,为使用者对代码块进行自定义提供接口
extern void hook_code_execute(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data);

/**
Fuzzer模块,需在LLVMFuzzerTestOneInput中声明/调用，用于生成一个模糊测试的基本对象。
Fuzzer基于Unicorn来实现任意架构二进制文件模拟，通过hook函数来实现覆盖率检测和内存问题(原版libfuzzer使用插桩实现)。
优点：无需源代码，无需在意架构，fuzz anywhere，anything.
缺点：继承了一部分libfuzzer原理导致的缺点（但也解决了最大的痛点）
使用案例：
*/
class Fuzzer
{

public:

    // 构造函数初始化
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

    ~Fuzzer(){
        delete[] bin_buffer; 
        uc_close(uc);
        }

    // 钩子函数 用于检测函数是否存在栈溢出

    static void hook_code(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data)
    {
        uint32_t canary;

#ifdef __DEBUG__
        printf("HOOK_CODE: 0x%" PRIx64 ", 0x%x\n", addr, size);
        if(addr == 0x40113B)
        {
            register_display<AMD64>(uc);
            stack_display<AMD64>(uc);
            sleep(2);
        }
#endif
    
        hook_code_execute(uc,addr,size,user_data);
        uc_mem_read(uc,data_addr+data_size, &canary, 4);
        if(canary!=CANARY)      //0xFFFFFFFF
        {
            fprintf(stderr, "========= ERROR:InfiniteSanitizer: stack overflow on address 0x%lx at pc 0x%lx bp  sp  \n",(data_addr+data_size),addr);
            abort();
        }
    }

    static void hook_block(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data)
    {
        //printf("HOOK_BLOCK: 0x%" PRIx64 ", 0x%x\n", addr, size);
        //Counters[addr]++;
        uint16_t pr = addr;
        uint16_t idx = pr ^ prevPR;
        Counters[idx]++;
        prevPR = (pr >> 1);
    }


    void entrance(void* data,size_t size);    // 设置函数 入口和结束地址。这部分之后需要内置一下，不需要用户调用。
    template <class ...Args>
    void start(Args... args);                 //  开始fuzz,提供一个可变参数的入口
    //还提供一个自定义的参数入口
    //void 写入数据到某个寄存器或者push入栈中
    
    //void sleep();


protected:

    bool load_target();         //  载入目标到内存(bin_buffer)中
    bool map_target();          //  映射bin_buffer内容到内存中
    //template<class T> void print_register();

private:

    Runtime* rt;
    Memory* mem;
    string target;
    int target_size;
    char* bin_buffer;
    uc_engine *uc;
    uc_err err;
};


//  开始 fuzz 流程
//  流程 1.从缓冲区将代码映射到内存 2.初始化寄存器 3.根据不同架构函数调用约定传递参数 4. 设置钩子检测覆盖率和内存错误

template <class ...Args>
void Fuzzer::start(Args... args)    
{
    //映射内存和初始化寄存器
    map_target();

    //写入对应参数
    mem->set_args(args...);

    // 设置钩子 1. 反馈代码覆盖率 2. 检测内存问题
    uc_hook code_hook,block_hook;
    uc_hook_add(uc, &code_hook, UC_HOOK_CODE, reinterpret_cast<void *>(hook_code), NULL, 1, 0);
    uc_hook_add(uc, &block_hook, UC_HOOK_BLOCK, reinterpret_cast<void *>(hook_block), NULL, 1, 0);
    // 运行
    err = uc_emu_start(this->uc,rt->start(),rt->end(),0,0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned %u: %s\n",
        err, uc_strerror(err));
        abort();
    }
}


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


//  映射bin_buffer内容到内存中

bool Fuzzer::map_target()
{
    mem->mem_map(this->rt->base(), 2 * 1024 * 1024, UC_PROT_ALL);
    mem->mem_write(this->rt->base(), bin_buffer, target_size - 1);
    return true;
}


// 1.设置代码段入口和出口地址 2. 准备data内存空间

void Fuzzer::entrance(void* data,size_t size)
{
   mem->init_reg(data,size); 
   data_size = size;
   data_addr = rt->data();
}


#endif