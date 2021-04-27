#include "fuzzer/Fuzzer.h"

typedef long clock_t;

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {

    //VulnerableFunctionx(data,size,data);

    static double totalTime=0;
    clock_t startTime,endTime;
    startTime = clock();
    //Fuzzer fuzzer("vuln.so",0x401100,0x40117C,UC_ARCH_X86, UC_MODE_64); //参数意义：fuzz目标、函数入口地址、函数出口地址、处理器架构、运行模式
    Fuzzer fuzzer("vuln2.so",0x400590,0x40064d,UC_ARCH_X86,UC_MODE_64);
    fuzzer.entrance(data,size);     //  void* data,size_t size
    //fuzzer.start(DATA,size,DATA);   //  输入函数对应参数
    fuzzer.start(DATA,size,DATA);

    endTime = clock();//计时结束
    totalTime += (double)(endTime - startTime) / CLOCKS_PER_SEC;
    cout << "\033[1A";
    cout << "\033[K";
    cout << "The run time is: " <<totalTime<< "s" << endl;
    return 0;
}
