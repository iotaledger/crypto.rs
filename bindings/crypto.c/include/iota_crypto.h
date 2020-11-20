#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Cmd {
  const char* feature;
  const char* function;
  double size;
  const char* payload;
  const char* returns;
} command;

extern void *sync(command cmd);
