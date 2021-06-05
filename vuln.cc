#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

bool VulnerableFunction1(uint8_t* data, size_t size, uint8_t* data2)
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
bool VulnerableFunction3(uint8_t* data, size_t size, uint8_t* data2)
{
   //int *str=(int *)malloc(size+1);
   for(int i=0;i<size;i++)
   {
	data2[i]=data[i];
	if(data2[i] == 65) //data[i] = A
	{
			if(data2[i+1] == 66) //data[i] = B
			{
					if(data2[i+2] == 67) //data[i] = C
		   			{	
					data[i+3]=10;
					data[i+4]=10;
					data[i+5]=10;
					}
			}

	}
   }
	//free(str);
	return true;
}