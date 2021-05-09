#ifndef __MY_DEBUG__
#define __MY_DEBUG__

// 针对Unicornni引擎的Debug模式
// 1.方便开发InfiniteFuzzer过程中的掌握虚拟机运行信息
// 2.如果有必要，可以为Unicorn引擎提供代码

//定义一些常量和类
const string reg_amd64[]=
{"rax","rbx","rcx","rdx","rsp","rbp","rsi","rdi","rip","r8","r9","r10","r11","r12","r13","r14","r15"};
class AMD64{};class X86{};class MIPS{};


template<class T> void register_display(uc_engine* uc)
{
    return ;
}
template<> void register_display<AMD64>(uc_engine* uc)
{
    //printf("AMD64\n");
    uint64_t rax,rbx,rcx,rdx,rsp,rbp,rsi,rdi,rip,r8,r9,r10,r11,r12,r13,r14,r15;
            uc_reg_read(uc,UC_X86_REG_RAX,&rax);
            uc_reg_read(uc,UC_X86_REG_RBX,&rbx);
            uc_reg_read(uc,UC_X86_REG_RCX,&rcx);
            uc_reg_read(uc,UC_X86_REG_RDX,&rdx);
            uc_reg_read(uc,UC_X86_REG_RSP,&rsp);
            uc_reg_read(uc,UC_X86_REG_RBP,&rbp);
            uc_reg_read(uc,UC_X86_REG_RSI,&rsi);
            uc_reg_read(uc,UC_X86_REG_RDI,&rdi);
            uc_reg_read(uc,UC_X86_REG_RIP,&rip);
            uc_reg_read(uc,UC_X86_REG_R8,&r8);
            uc_reg_read(uc,UC_X86_REG_R9,&r9);
            cout << hex << "------------------- Registers --------------------"<< endl;
            cout << "$rax = " << rax  << " \t$rbx = " << rbx << " \t$rcx = " << rcx << endl;
            cout << "$rdx = " << rdx  << " \t$rsp = " << rsp << " \t$rbp = " << rbp << endl;
            cout << "$rsi = " << rsi  << " \t$rdi = " << rdi << " \t$rip = " << rip << endl;
            //cout << "=================================================="<<endl;
    return ;
}
template<> void register_display<X86>(uc_engine* uc)
{
    printf("X86\n");
    return ;
}

template<class T> void stack_display(uc_engine* uc)
{
    return ;
}
template<> void stack_display<AMD64>(uc_engine* uc)
{
    uint64_t rsp;
    uint64_t stack_0,stack_8,stack_16,stack_24,stack_32,stack_r8;
    uc_reg_read(uc,UC_X86_REG_RSP,&rsp);
    uc_mem_read(uc,rsp-8,&stack_r8,8);
    uc_mem_read(uc,rsp,&stack_0,8);
    uc_mem_read(uc,rsp+8,&stack_8,8);
    uc_mem_read(uc,rsp+16,&stack_16,8);
    uc_mem_read(uc,rsp+24,&stack_24,8);
    uc_mem_read(uc,rsp+32,&stack_32,8);
    cout << "-------------------- Stack -----------------------"<< endl;
    cout << hex <<"0x" << rsp-8 << " \t|\t "  << stack_r8 << endl; 
    cout << hex <<"0x" << rsp << " \t|\t "  << stack_0 << " <-- esp" << endl;
    cout << hex <<"0x" << rsp+8 << " \t|\t " << stack_8 << endl;
    cout << hex <<"0x" << rsp+16 << " \t|\t " << stack_16 << endl;
    cout << hex <<"0x" << rsp+24 << " \t|\t " << stack_24 << endl;
    cout << hex <<"0x" << rsp+32 << " \t|\t " <<stack_32 << endl; 
    cout << "=================================================="<< endl;
    return;
}


#endif
