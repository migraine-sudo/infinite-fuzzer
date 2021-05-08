/* 用于检测Fuzzer参数调用约定是否运行正确的测试代码*/

#include <stdio.h>

typedef unsigned int uint;

/*使用Infinite Fuzzer对该函数进行fuzz*/
void debug_entrance(int one,uint two,char *three,long four,double five,int six,int seven ,int eight)
{
    printf("one = %d \ntwo = %u\nthree = %s\nfour= %ld\n",one, two, three, four);
    printf("five = %f\nsix = %d\nseven= %d\neight= %d\n",five,six,seven,eight);
}

int main()
{
    debug_entrance(1,2,"3abc",4,5.6,7,8,9);
    return 0;
}
