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
#include "Utils.h"


using namespace std;
using namespace Utils;

/**
Fuzzer模块,需在LLVMFuzzerTestOneInput中声明/调用，用于生成一个模糊测试的基本对象。
Fuzzer基于Unicorn来实现任意架构二进制文件模拟，通过hook函数来实现覆盖率检测和内存问题(原版libfuzzer使用插桩实现)。
优点：无需源代码，无需在意架构，fuzz anywhere，anything.
缺点：继承了一部分libfuzzer原理导致的缺点（但也解决了最大的痛点）
使用案例：
*/
class Fuzzer
{
protected:
typedef vector<uint64_t> address_list;
typedef Runtime* Runtime_pointer;
typedef Memory* Memory_pointer;
typedef char* char_pointer;
#define  multiple_type template<class ...Args> void
public:
    // 构造函数初始化
    Fuzzer(string target, uint64_t start, uint64_t end, uc_arch arch, uc_mode mode):target(target){
        //初始化Unicorn  运行时 和 内存映射 对象对象
        uc_open(arch, mode, &(this->uc));
        if(start < Runtime().base() || end < Runtime().base() )
            rt = new Runtime(start + Runtime().base(),end + Runtime().base());
        else
            rt = new Runtime(start,end);
        mem = new Memory(uc,arch, mode,rt);
        
        //载入并且映射目标
        load_target();
        if(!mem->mem_map(rt->base(),(size_t)target_size,UC_PROT_ALL))
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

    void entrance(void* data,size_t size);    // 设置函数 入口和结束地址。这部分之后需要内置一下，不需要用户调用。
    multiple_type start(Args... args);                 // 开始fuzz,会根据不同架构和模式自动将参数写入模拟执行的函数
    //还需要提供一个自定义的参数入口
    //void 写入数据到某个寄存器或者push入栈中

    multiple_type skip(uint64_t head,Args...args);      // 设定一些需要跳过的地址
    void skip();
    void add_hook(hook_type type,void (*hook_ext)       // 载入用户自定义的hook函数
    (uc_engine* uc, uint64_t addr, uint32_t size, void* user_data));                         

protected:
    bool load_target();         //  载入目标到内存(bin_buffer)中
    bool map_target();          //  映射bin_buffer内容到内存中

private:
    Runtime_pointer rt;
    Memory_pointer mem;
    string target;
    int target_size;
    char_pointer bin_buffer;
    uc_engine *uc;
    uc_err err;
    address_list skip_address;
};


//  开始 fuzz 流程
//  流程 1.从缓冲区将代码映射到内存 2.初始化寄存器 3.根据不同架构函数调用约定传递参数 4. 设置钩子检测覆盖率和内存错误

multiple_type Fuzzer::start(Args... args)    
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

multiple_type Fuzzer::skip(uint64_t head,Args...args)
{
    (this->skip_address).push_back(head);
    skip(args...); 
}

void Fuzzer::skip()
{
    skip_addr.insert(skip_addr.end(),this->skip_address.begin(),this->skip_address.end());
    return ;
}

void Fuzzer::add_hook(hook_type type,void (*hook_ext)(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data))                         // 增加hook函数
{
    if(type==CODE)
        hook_code_ext = hook_ext;
    if(type==BLOCK)
        hook_block_ext = hook_ext;
    //...
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