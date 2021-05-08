#ifndef __RUNTIME__
#define __RUNTIME__

#include <stdint.h>
#include <stddef.h>

/**
定义以及保存“运行时”的一些参数，比如堆栈地址，程序起始地址
*/

class Runtime
{
public:
    Runtime(uint64_t start, uint64_t end):start_(start),end_(end){}
    Runtime(uint64_t start, uint64_t end, uint64_t base ):start_(start),end_(end),base_(base){}
    Runtime(uint64_t start, uint64_t end, uint64_t base , uint64_t data):start_(start),end_(end),data_(data){}
    uint64_t start() const {return start_;}
    uint64_t end() const {return end_;}
    uint64_t base() const {return base_;}
    uint64_t stack_add(uint64_t i) {stack_size_+=i;return 0;}
    uint64_t stack_red(uint64_t i) {stack_size_-=i;return 0;}
    uint64_t stack() const {return stack_;}
    uint64_t stack_size() const {return stack_size_;}
    //uint64_t stack_top() const {return stack_+stack_size_-1;}
    uint64_t stack_top() const {return stack_+stack_size_-1;}
    uint64_t data() const {return data_;}
    void start(uint64_t addr) {start_ = addr ;}
    void end(uint64_t addr) {end_ = addr ;}


private:
    uint64_t start_;      // 程序段开始地址
    uint64_t end_;        // 程序段结束地址
    uint64_t base_ =  0x400000;       // 程序段映射地址
    uint64_t stack_ = 0x0;            // 栈地址
    uint64_t stack_size_ = 1024*100;  //栈大小
    uint64_t data_ = 0x4000;           // 存储传递的数组类型         (溢出检测)
    uint64_t heap_;           // 存储动态分配的heap chunk  (溢出检测)
};


#endif
