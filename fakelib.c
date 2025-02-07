#include <stdio.h>

int __attribute__((constructor)) ctor()
{
	printf("Hello from fakelib!\n");
	return 0;
}
