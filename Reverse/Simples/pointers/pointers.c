#include <stdio.h>

int main(){
	int a = 10;
	int *a_p;
	a_p = &a;

	printf("a equal: %d\n",a);
	printf("a address: %x\n",&a);
	printf("a_p equals: %d\n",*a_p);
	printf("a_p adderss: %x\n",a_p);

	return 0;
}
