#include <stdio.h>

#pragma once

typedef struct {
    char **redundant;
    size_t redundant_len;
    char **redundant_exact;
    size_t redundant_exact_len;
} filter_t;

const char *filter_data(char *restrict haystack, filter_t *restrict config);
const char *filter_data_exact(char *restrict haystack, filter_t *restrict config);
filter_t *read_config(const char *restrict filename);
void free_filter(filter_t *filter);
