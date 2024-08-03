#include <stdio.h>

#pragma once

typedef struct {
     char **redundant;
     size_t redundant_len;
} filter_t;

const char *filter_data(char *restrict haystack, filter_t *restrict config);
