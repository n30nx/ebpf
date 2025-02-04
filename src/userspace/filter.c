#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "../../include/userspace/filter.h"

static inline bool conf_null(filter_t *restrict config) {
    if (config == NULL) {
        printf("redundant = NULL, returning...\n");
        return false;
    }
    return true;
}

const char *filter_data(char *restrict haystack, filter_t *restrict config) {
    char *res = NULL;

    for (size_t i = 0; conf_null(config) && i < config->redundant_len; i++) {
        /*if (config == NULL) {
            printf("redundant = NULL, returning...");
            return NULL;
        }*/
        char *tmp = strstr(haystack, config->redundant[i]);
        if (tmp != NULL) {
            return NULL;
        }
    }

    return haystack;
}

const char *filter_data_exact(char *restrict haystack, filter_t *restrict config) {
    for (size_t i = 0; conf_null(config) && i < config->redundant_exact_len; i++) {
        /*if (config == NULL) {
            printf("redundant = NULL, returning...");
            return NULL;
        }*/
        if (strcmp(haystack, config->redundant_exact[i]) == 0) {
            return NULL;
        }
    }

    return haystack;
}

filter_t *read_config(const char *restrict filename) {
    FILE *file = fopen(filename, "r");
    assert(file);

    filter_t *filter = malloc(sizeof(filter_t));
    assert(filter);

    filter->redundant = NULL;
    filter->redundant_len = 0;
    filter->redundant_exact = NULL;
    filter->redundant_exact_len = 0;

    char line[1024];
    while (fgets(line, sizeof(line), file)) {
        char *token = strtok(line, "=");
        if (token && strcmp(token, "REDUNDANT") == 0) {
            token = strtok(NULL, "\n");
            if (token) {
                char *value = strdup(token);
                assert(value);

                size_t count = 0;
                char *ptr = value;
                while (*ptr) {
                    if (*ptr == ',') count++;
                    ptr++;
                }
                count++;

                filter->redundant = malloc(count * sizeof(char *));
                assert(filter->redundant != NULL);

                filter->redundant_len = count;

                size_t i = 0;
                char *item = strtok(value, ",");
                while (item) {
                    filter->redundant[i] = strdup(item);
                    assert(filter->redundant[i]);
                    item = strtok(NULL, ",");
                    i++;
                }
                free(value);
            }
        } else if (token && strcmp(token, "REDUNDANT_EXACT") == 0) {
            token = strtok(NULL, "\n");
            if (token) {
                char *value = strdup(token);
                assert(value);

                size_t count = 0;
                char *ptr = value;
                while (*ptr) {
                    if (*ptr == ',') count++;
                    ptr++;
                }
                count++;

                filter->redundant_exact = malloc(count * sizeof(char *));
                assert(filter->redundant_exact != NULL);

                filter->redundant_exact_len = count;

                size_t i = 0;
                char *item = strtok(value, ",");
                while (item) {
                    filter->redundant_exact[i] = strdup(item);
                    assert(filter->redundant_exact[i]);
                    item = strtok(NULL, ",");
                    i++;
                }
                free(value);
            }
        }
    }

    fclose(file);
    return filter;
}

void free_filter(filter_t *filter) {
    if (!filter) {
        return;
    }
    for (size_t i = 0; i < filter->redundant_len; i++) {
        free(filter->redundant[i]);
    }
    free(filter->redundant);
    
    for (size_t i = 0; i < filter->redundant_exact_len; i++) {
        free(filter->redundant_exact[i]);
    }
    free(filter->redundant_exact);

    free(filter);
    filter = NULL;
}
