#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../include/userspace/filter.h"

/*
 * typedef struct {
 *     char **redundant;
 *     size_t redundant_len;
 * } filter_t
 *
 *
 *
 */

const char *filter_data(char *restrict haystack, filter_t *restrict config) {
    char *res = NULL;

    for (size_t i = 0; i < config->redundant_len; i++) {
        char *tmp = strstr(haystack, config->redundant[i]);
        if (tmp != NULL) {
            return NULL;
        }
    }

    return haystack;
}
