#include <stdio.h>

int main()
{
	unsigned short p=0x0800;
	unsigned char q;
	unsigned char r;
	q=(unsigned char)p;
	r=(p>>8)&7;
	printf("%d %d %d\n",p,q,r);
}