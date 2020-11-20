#include <stdint.h>
#include <stdio.h>
#include "include/iota_crypto.h"

int main() {
    command c;
    c.feature = "rand";
    char* res = sync(c);
    printf("Response: %s\n", res);
    return 0;
}
