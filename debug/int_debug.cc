#include <stdio.h>


/*使用Infinite Fuzzer对该函数进行fuzz*/
void debug_entrance(int one,int two,int three,int four,int five,int six,int seven ,int eight)
{
    printf("one = %d \ntwo = %d\nthree = %d\nfour= %d\n",one, two, three, four);
    printf("five = %d\nsix = %d\nseven= %d\neight= %d\n",five,six,seven,eight);
}

int main()
{
    debug_entrance(1,2,3,4,5,6,7,8);
    return 0;
}