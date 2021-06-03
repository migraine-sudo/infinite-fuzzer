#ifndef __MEMORY__
#define __MEMORY__

#include <iostream>

#include <unicorn/unicorn.h>

#define DATA 65537
#define CANARY 0xFFFFFFFF
using namespace std;

/**
 Memory 是一个单例模式，即一次fuzz只能实例化一个对象。
    1.封装了Unicorn提供的内存操作相关API(参考https://github.com/unicorn-engine/unicorn/blob/master/docs/Micro%20Unicorn-Engine%20API%20Documentation/Micro%20Unicorn-Engine%20API%20Documentation.md)
    2.对不同架构不同模式分别提供参数在内存上的初始化（比如X64通过栈传递参数）
*/

class Memory
{
public:
    /*
    static Memory& getInstance()
    {
        static Memory instance_;
        return instance_;
    }
    */
    Memory(){}
    Memory(uc_engine *uc,uc_arch arch,uc_mode mode,Runtime *rt)
    {
        this->set_env(uc,arch,mode,rt);
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
    bool init_reg(void* data,size_t size);
    bool insert_arg(uint64_t data);
    template<class T,class ...Args>
    bool set_args(T head,Args... args);
    bool set_args();

    // 虚拟机的指令操作模拟
    bool push(uint64_t data);

private:
    Runtime *rt_;   //Runtime对象
    uc_engine *uc_; //Unicorn对象
    uc_err err_;    //Unicorn错误类型
    uc_arch arch_;  //Unicorn对象架构
    uc_mode mode_;  //Unicorn对象运行模式

    bool inited = false;    //是否使用set_env初始化
    uint64_t arg_num = 0;   //当前函数参数个数（记得每次运行前重置）
    bool not_push_0 = true; //是否push ret值
//private:
    //Memory(){}
    //Memory(uc_engine *uc,uc_arch arch,uc_mode mode):uc_(uc),arch_(arch),mode_(mode)
    
};


// 初始化对应架构的寄存器等

bool Memory::init_reg(void* data,size_t size)
{
    arg_num=0; 
    switch(this->arch_){
    case UC_ARCH_X86:{
        switch(this->mode_){
            case UC_MODE_64:
            {
                /*
                uint64_t r_rdi = reinterpret_cast<uint64_t>(this->rt_->data());
                uint64_t r_rdx = reinterpret_cast<uint64_t>(this->rt_->data());
                uint64_t r_rsi = size;
                this->mem_map(this->rt_->data(), size , UC_PROT_ALL);
                this->mem_write(this->rt_->data() , data, size - 1);
                this->reg_write( UC_X86_REG_RDI, &r_rdi);
                this->reg_write( UC_X86_REG_RSI, &r_rsi);
                //this->reg_write( UC_X86_REG_RDX, &r_rdx);
                */

                //初始化 栈空间 和 测试数据data的空间
                uint64_t r_rsp = this->rt_->stack_top();
                this->mem_map(this->rt_->stack(), (this->rt_->stack_size())+0x1000, UC_PROT_ALL);
                this->reg_write(UC_X86_REG_RSP, &r_rsp);

                this->mem_map(this->rt_->data(), size , UC_PROT_ALL);
                this->mem_write(this->rt_->data() , data, size - 1);

                //在data内存后设置canary
                uint32_t canary=CANARY; //#0xFFFFFFFF
                this->mem_write(this->rt_->data()+size, &canary, 4);

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

// 根据不同架构的 调用约定 传递参数
bool Memory::insert_arg(uint64_t arg)
{
    switch(this->arch_){
    case UC_ARCH_X86:{
        switch(this->mode_){
            case UC_MODE_64:
            {
                uint64_t reg;
                if(arg == DATA)  //参数为DATA 默认选择data(void *)作为参数
                    reg =reinterpret_cast<uint64_t>(this->rt_->data()); 
                else
                    reg = arg;
                // 依据x86架构64位的 函数调用约定 传递参数 : RDI RSI RDX RCX R8 R9
                switch(this->arg_num){
                    case 0:
                    {
                        this->reg_write( UC_X86_REG_RDI, &reg); 
                        break;
                    }
                    case 1:
                    {
                       this->reg_write( UC_X86_REG_RSI, &reg); 
                       break;
                    }
                    case 2:
                    {
                       this->reg_write( UC_X86_REG_RDX, &reg); 
                       break;
                    }
                    case 3:
                    {
                       this->reg_write( UC_X86_REG_RCX, &reg); 
                       break;
                    }
                    case 4:
                    {
                       this->reg_write( UC_X86_REG_R8D, &reg); 
                       break;
                    }
                    case 5:
                    {
                       this->reg_write( UC_X86_REG_R9D, &reg); 
                       break;
                    }
                    default:
                    {
                        //if(not_push_0)      //首先push ret地址为0x0
                        //    this->push(0);
                        //not_push_0 = false;
                        this->push(reg);
                        //cout << "Error in insert arg, too many args ! " << endl;
                        //return false;
                        break;
                    }
                       
                }
                break;
            }
            default:
            {
                cout << "Error Mode in insert arg" << endl;
                return false;
                break;
            }

        }
        break;
    }
    default:
    {
        cout << "Error ARCH in insert arg" << endl;
        return false;
        break;
    }
        
    }
    this->arg_num++;

    return true;
}
// 递归解析多参数包
template<class T,class ...Args>
bool Memory::set_args(T head,Args... args)
{
    if(head == (uint64_t)DATA)
        this->insert_arg(DATA);

    else
        this->insert_arg((uint64_t)head);
    
    //cout << " head = " << head << endl;
    return this->set_args(args...);
}
// 递归出口
bool Memory::set_args()
{
    //cout << "empty" << endl; // 递归出口
    return true;
}


///////////////////
// 实现入栈出栈操作//
//////////////////
bool Memory::push(uint64_t data)
{
    if(this->arch_ == UC_ARCH_X86)
    {
        if(this->mode_ == UC_MODE_64)
        {
            //mem_write(rt_->stack_top() ,&data ,8);
#ifdef __DEBUG__
            cout << "stack_top =" << rt_->stack_top() << "  "<< "stack_size = " <<rt_->stack_size() <<endl;
#endif
            rt_->stack_red(8); //64位一次可处理8字节
            mem_write(rt_->stack_top() ,&data ,8);
#ifdef __DEBUG__
            cout << "stack_top =" << rt_->stack_top() << "  "<< "stack_size = " <<rt_->stack_size() <<endl;
#endif
            return true;
        }
    }
    return false;
}




/** 封装 Unicorn 的 Memory 相关API **/

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




#endif
