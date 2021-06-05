#ifndef __FUZZER__
#define __FUZZER__

#include <iostream>
#include <string>
#include <cstring>
#include <fstream>
#include <sstream>
#include <vector>

#include <unicorn/unicorn.h>

#include "Runtime.h"
#include "Memory.h"
#include "Debug.h"

#define PCS_N (1 << 16)

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

vector<uint64_t> skip_addr;

static const uint16_t crc16tab[256]= {
    0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
    0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
    0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
    0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
    0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
    0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
    0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
    0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
    0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
    0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
    0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
    0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
    0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
    0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
    0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
    0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
    0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
    0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
    0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
    0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
    0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
    0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
    0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
    0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
    0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
    0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
    0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
    0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
    0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
    0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
    0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
    0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};

//扩展用,为使用者对代码块进行自定义提供接口
//extern void hook_code_execute(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data);

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
        
        //初始化Unicorn  运行时 和 内存映射 对象对象
        uc_open(arch, mode, &(this->uc));
        rt = new Runtime();
        if(start < rt->base() || end < rt->base() ){
            rt->start(start + rt->base());
            rt->end(end + rt->base());
        }
        else{
            rt->start(start);
            rt->end(end);
        }
        mem = new Memory(uc,UC_ARCH_X86, UC_MODE_64,rt);
        
        //载入并且映射目标
        load_target();
        if(!mem->mem_map(rt->base(),(size_t)target_size,UC_PROT_ALL))
            //cout << "Error : Please init the Memory before fuzzing!" << endl;
            abort();
        map_target();

        }

    Fuzzer(Fuzzer const& fuzzer){
        cout << "Do not copy this member,or you will get one UAF..." << endl;
    }

    /*
    Fuzzer operator = (Fuzzer fuzzer){
       //cout << "Do not copy this member,or you will get one UAF..." << endl; 
       //return new Fuzzer(); 
    }
    */
    ~Fuzzer(){
        delete[] bin_buffer; 
        uc_close(uc);
        }


    static uint16_t crc16(uint32_t value) {
        int counter;
        uint16_t crc = 0;
        for (counter = 0; counter < 4; counter++) {
            uint8_t v = value & 0xff;
            crc = (crc<<8) ^ crc16tab[((crc>>8) ^ v)&0xff];
            value >>= 8;
    }
    return crc;
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
    
        //hook_code_execute(uc,addr,size,user_data);
        uc_mem_read(uc,data_addr+data_size, &canary, 4);
        if(canary!=CANARY)      //0xFFFFFFFF
        {
            fprintf(stderr, "========= ERROR:InfiniteSanitizer: stack overflow on address 0x%lx at pc 0x%lx bp  sp  \n",(data_addr+data_size),addr);
            abort();
        }
        for(auto address:skip_addr)
        {
            if( address == addr )
            {
                long r_rip = addr + size ;
                uc_reg_write(uc, UC_X86_REG_RIP, &r_rip); 
            }
        }
        

    }

    static void hook_block(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data)
    {
        //printf("HOOK_BLOCK: 0x%" PRIx64 ", 0x%x\n", addr, size);
        //Counters[addr]++;
        uint16_t pr = crc16(addr);
        //uint16_t pr = addr;
        uint16_t idx = pr ^ prevPR;
        Counters[idx]++;
        prevPR = (pr >> 1);
    }


    void entrance(void* data,size_t size);    // 设置函数 入口和结束地址。这部分之后需要内置一下，不需要用户调用。
    template <class ...Args>
    void start(Args... args);                 //  开始fuzz,提供一个可变参数的入口
    //还提供一个自定义的参数入口
    //void 写入数据到某个寄存器或者push入栈中

    //template <class T,class ...Args>
    //void skip(T head,Args... args);
    template<class ...Args>
    void skip(uint64_t head,Args...args);
    void skip();
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
    vector<uint64_t> skip_address;
};


//  开始 fuzz 流程
//  流程 1.从缓冲区将代码映射到内存 2.初始化寄存器 3.根据不同架构函数调用约定传递参数 4. 设置钩子检测覆盖率和内存错误

template <class ...Args>
void Fuzzer::start(Args... args)    
{

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

template<class ...Args>
void Fuzzer::skip(uint64_t head,Args...args)
{
    (this->skip_address).push_back(head);
    skip(args...); 
}
void Fuzzer::skip()
{
    skip_addr.insert(skip_addr.end(),this->skip_address.begin(),this->skip_address.end());
    return ;
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

inline bool Fuzzer::map_target()
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