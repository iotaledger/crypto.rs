/* Copyright 2020 IOTA Stiftung */
/* SPDX-License-Identifier: Apache-2.0 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct String String;

typedef struct {
  String feature;
  String function;
  double size;
  String payload;
  String returns;
} Cmd;

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

const char *sync(Cmd cmd);

#ifdef __cplusplus
} // extern "C"
#endif // __cplusplus
