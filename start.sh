#!/bin/bash

echo "************欢迎来到Infinite Fuzzer的展示***************"
echo "Infinite Fuzzer是一款针对二进制固件进行灰盒测试的模糊测试框架"
echo "下面请选择我们要Fuzz的目标难度:"
echo "1. level 1"
echo "2. level 2"
echo "3. level 3"
echo -n "请输入选项<<"
read index

if [ $index == "1" ]
then
    make clean && make demo
elif [ $index == "2" ]
then 
    make clean && make demo2
elif [ $index == "3" ]
then
    make clean && make demo3
else
    echo "未知的选择!"
fi

./myfuzzer -max_len=10

