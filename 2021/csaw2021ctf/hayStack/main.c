#include <stdio.h>
#include <stdlib.h>

int main(int argc,char** argv) {
	int result;
	int seed = atoi(argv[1]);
	srand(seed);
	result = rand() % 0x100000;
	printf("%d\n", result);
}
