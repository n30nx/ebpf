#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>

#include "../../include/common/common.h"

// #define max(a, b) ((a > b) ? (a) : (b))
#define checkerr() { if (res < 0) return false; }

/*
 * struct data {
 *     map_t *maps;
 *     size_t size;
 *     size_t _last_key_index;
 * }
 *
 * struct map {
 *     char *key;
 *     char **values;
 * }
 *
 *
 */

static inline const int writecur(FILE *f, const char *restrict data, int indent) {
    if (indent < 0) {
        return -1;
    }

    for (int i = 0; i < indent; i++) {
        fprintf(f, "\t");
    }
    int res = fprintf(f, "%s", data);
    return res;
}

__attribute__((always_inline))
static inline const int envsep(const char *arg) {
    int idx = (int)(strchr(arg, '=') - arg);

    return idx;
}

const bool write_json(FILE *file, struct execve_event *event) {
    static bool initialized = false;
    if (initialized == false) {
        writecur(file, "{\n", 0);
        initialized = true;
    }

    const time_t key = time(NULL);
    
    char *start = (char*)malloc(sizeof(char) * 70); // \t + 64 bit unix time + : + ' ' + { + \n
    assert(start);

    sprintf(start, "\t%lu: {\n", key);
    int res = writecur(file, start, 0);
    checkerr();
    free(start);

    char *program = (char*)malloc(sizeof(char) * (strlen(event->filename) + 24));
    sprintf(program, "\"filename\": \"%s\",\n", event->filename);
    res = writecur(file, program, 2);
    checkerr();
    free(program);

    char *pid = (char*)malloc(sizeof(char) * 64);
    sprintf(pid, "\"pid\": %u,\n", event->pid);
    res = writecur(file, pid, 2);
    checkerr();
    free(pid);

    char *tgid = (char*)malloc(sizeof(char) * 64);
    sprintf(tgid, "\"tgid\": %u,\n", event->tgid);
    res = writecur(file, tgid, 2);
    checkerr();
    free(tgid);

    char *syscall_nr = (char*)malloc(sizeof(char) * 64);
    sprintf(syscall_nr, "\"syscall_nr\": %d,\n", event->syscall_nr);
    res = writecur(file, syscall_nr, 2);
    checkerr();
    free(syscall_nr);

    res = writecur(file, "\"arguments\": [\n", 2);
    checkerr();

    const size_t argvlen = arrlen(event->argv);

    int i;
    for (i = 0; i < argvlen; i++) { 
        char *tmp = (char*)malloc(sizeof(char) * (24 + strlen(event->envp[i]))); // "env": "env",\n
        sprintf(tmp, "\"%s\"", event->argv[i]);
        res = writecur(file, tmp, 3);
        if ((i + 1) == argvlen) {
            fprintf(file, "\n");
        } else {
            fprintf(file, ",\n");
        }
        checkerr();
        free(tmp);
    }

    res = writecur(file, "],\n", 2);
    checkerr();

    res = writecur(file, "\"environment\": {\n", 2);
    checkerr();

    const size_t envplen = arrlen(event->envp);

    for (i = 0; i < envplen; i++) {
        int sep = envsep(event->envp[i]);
        char *tmp = (char*)malloc(sizeof(char) * (10 + strlen(event->envp[i]))); // "env": "env",\n
        assert(tmp);

        snprintf(tmp, sep + 2, "\"%s", event->envp[i]);
        sprintf(tmp + sep + 1, "\": \"%s\"", event->envp[i] + sep + 1);
        res = writecur(file, tmp, 3);
        if ((i + 1) == envplen) {
            fprintf(file, "\n");
        } else {
            fprintf(file, ",\n");
        }
        checkerr();
        free(tmp);
    }

    res = writecur(file, "},\n", 1);
    return true;
}
/*
const data_t *create_map(const size_t size) {
    data_t *data = (data_t*)malloc(sizeof(data_t));

    data->maps = (map_t**)malloc(sizeof(map_t*));
    for (size_t i = 0; i < size; i++) {
        data->maps[i] = (map_t*)malloc(sizeof(map_t));
    }
    data->size = size;
    data->_last_key_index = 0;

    return data;
}

static const bool is_present(const data_t *restrict data, const char *restrict key) {
    for (size_t i = 0; i < data->size; i++) {
        size_t len = max(strlen(data->maps[i]->key), strlen(data->key));
        int res = strncmp(data->maps[i]->key, key, len);
        if (res == 0) {
            return true;
        }
    }

    return false;
}

const bool create_key(data_t *data, const char *restrict key, const char **restrict values, size_t values_len) {
    if (data->_last_key_index + 1 >= count) {
        return false;
    }
    if (is_present(data, key)) {
        return false;
    }

    map_t *cur = data->maps[_last_key_index];
    cur->key = (char*)malloc(sizeof(char) * (strlen(key) + 1));
    strncpy(cur->key, key, );

    cur->values = (char**)malloc(sizeof(char*) * values_len);
    for (size_t i = 0; i < values_len; i++) {
        cur->values[i] = (char*)malloc(sizeof(char) * (strlen(values[i]) + 1));
    }

    data->_last_key_index += 1;
}
*/
