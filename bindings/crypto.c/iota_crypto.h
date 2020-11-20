/* Copyright 2020 IOTA Stiftung */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Cmd {
  const char *feature;
  const char *function;
  double size;
  const char *payload;
  const char *returns;
} command;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

const char *sync(command cmd);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
