#include <stddef.h>

#include "../../include/common/common.h"

const size_t arrlen(const char array[LOOP_MAX][MAX_ARGSIZE]) {
    size_t i = 0;
    while (i < LOOP_MAX && array[i][0] != 0) i++;

    return i - 1;
}
