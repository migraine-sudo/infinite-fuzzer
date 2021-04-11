#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

bool VulnerableFunctionx(uint8_t* data, size_t size, uint8_t* data2)
{
   //int *str=(int *)malloc(size+1);
   for(int i=0;i<size;i++)
   {
	data2[i]=data[i];
	if(data2[i] == 65) //data[i] = A
	{
	   data[i+2]=10;
	}
   }
	//free(str);
	return true;
}
