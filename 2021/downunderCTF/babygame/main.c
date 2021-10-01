#include <stdio.h>
#include <stdlib.h>
int main() {
    int num;
    FILE* f;
    f = fopen("/dev/urandom", "rb");
    fread(&num,1, 4, f);
    printf("%d", num);
    return 0;
}