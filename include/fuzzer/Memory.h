#ifndef __MEMORY__
#define __MEMORY__

#include <iostream>

#include <unicorn/unicorn.h>

using namespace std;

/**
 Memory 是一个单例模式，即一次fuzz只能实例化一个对象。
    1.封装了Unicorn提供的内存操作相关API(参考https://github.com/unicorn-engine/unicorn/blob/master/docs/Micro%20Unicorn-Engine%20API%20Documentation/Micro%20Unicorn-Engine%20API%20Documentation.md)
    2.对不同架构不同模式分别提供参数在内存上的初始化（比如X64通过栈传递参数）
*/

class Memory
{
public:
    static Memory& getInstance()
    {
        static Memory instance_;
        return instance_;
    }
    // 请务必在调用任何Memory类中方法前调用这个函数来设置架构和模式
    void set_env(uc_engine *uc,uc_arch arch,uc_mode mode,Runtime *rt)
    {
        this->uc_ = uc;
        this->arch_ = arch;
        this->mode_ = mode;
        this->rt_ =rt;
        this->inited = true;
    }
    // 封装Uncorn函数
    bool mem_map(uint64_t address, size_t size, uint32_t perms);
    bool mem_unmap(uint64_t address, size_t size);
    bool mem_map_ptr(uint64_t address, size_t size, uint32_t perms, void *ptr);
    bool mem_read(uint64_t address, void *bytes, size_t size);
    bool mem_write(uint64_t address, const void *_bytes, size_t size);
    bool reg_read(int regid, void *value);
    bool reg_write(int regid, const void *value);

    // 实现寄存器初始化 以及 参数传递
    bool init_arg(void* data,size_t size);

private:
    Runtime *rt_;
    uc_engine *uc_; //Unicorn对象
    uc_err err_;    //Unicorn错误类型
    uc_arch arch_;  //Unicorn对象架构
    uc_mode mode_;  //Unicorn对象运行模式
    bool inited = false;    //是否使用set_env初始化
private:
    Memory(){}
    //Memory(uc_engine *uc,uc_arch arch,uc_mode mode):uc_(uc),arch_(arch),mode_(mode)
    
};

bool Memory::mem_map(uint64_t address, size_t size, uint32_t perms)
{
    if(!this->inited)
    {
        cout << "The memory has not been initialized !" << endl;
        return false;
    }
    uc_mem_map(this->uc_, address, size, perms);
    return true;
}

bool Memory::mem_unmap(uint64_t address, size_t size)
{
   if(!this->inited)
    {
        cout << "The memory has not been initialized !" << endl;
        return false;
    }
    uc_mem_unmap(this->uc_, address, size);
    return true; 
}

bool Memory::mem_map_ptr(uint64_t address, size_t size, uint32_t perms, void *ptr)
{
   if(!this->inited)
    {
        cout << "The memory has not been initialized !" << endl;
        return false;
    }
    uc_mem_map_ptr(this->uc_, address, size, perms, ptr);
    return true;  
}

bool Memory::mem_read(uint64_t address, void *bytes, size_t size)
{
    if(!this->inited)
    {
        cout << "The memory has not been initialized !" << endl;
        return false;
    }
    uc_mem_read(this->uc_, address, bytes, size);
    return true; 
}

bool Memory::mem_write(uint64_t address, const void *bytes, size_t size)
{
    if(!this->inited)
    {
        cout << "The memory has not been initialized !" << endl;
        return false;
    }
    uc_mem_write(this->uc_, address, bytes, size);
    return true; 
}

bool Memory::reg_read(int regid, void *value)
{
    if(!this->inited)
    {
        cout << "The memory has not been initialized !" << endl;
        return false;
    }
    uc_reg_read(this->uc_, regid, value);
    return true;  
}

bool Memory::reg_write(int regid, const void *value)
{
    if(!this->inited)
    {
        cout << "The memory has not been initialized !" << endl;
        return false;
    }
    uc_reg_write(this->uc_, regid, value);
    return true;  
}

bool Memory::init_arg(void* data,size_t size)
{
    switch(this->arch_){
    case UC_ARCH_X86:{
        switch(this->mode_){
            case UC_MODE_64:
            {
                uint64_t r_rdi = reinterpret_cast<uint64_t>(this->rt_->data());
                uint64_t r_rdx = reinterpret_cast<uint64_t>(this->rt_->data());
                uint64_t r_rsi = size;
                uint64_t r_rsp = this->rt_->stack_top();
                this->mem_map(this->rt_->data(), size , UC_PROT_ALL);
                this->mem_write(this->rt_->data() , data, size - 1);
                this->reg_write( UC_X86_REG_RDI, &r_rdi);
                this->reg_write( UC_X86_REG_RSI, &r_rsi);
                //this->reg_write( UC_X86_REG_RDX, &r_rdx);

                this->mem_map(this->rt_->stack(), this->rt_->stack_size() , UC_PROT_ALL);
                this->reg_write(UC_X86_REG_RSP, &r_rsp);
                break;
            }
            case UC_MODE_32: break;
            default:return false;
        }
    }
    break;
    default:
        cout << "Error init arg" << endl;
    break;
    }
    return true;
}

#endif
