#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>
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

__attribute__((always_inline))
static inline const int writecur(FILE *f, const char *restrict data, int indent) {
    if (indent < 0) {
        return -1;
    }

    int i;
    for (i = 0; i < indent; i++) {
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

__attribute__((always_inline))
static inline char* replace_char(const char *str, char find, char replace) {
    size_t len = strlen(str);
    char *new_str = (char*)malloc(len + 1); // Allocate memory for the new string
    if (!new_str) {
        return NULL; // Return NULL if allocation fails
    }

    const char *src = str;
    char *dst = new_str;

    while (*src) {
        *dst = (*src == find) ? replace : *src;
        src++;
        dst++;
    }

    *dst = '\0'; // Null-terminate the new string

    return new_str;
}

const bool write_json_execve(FILE *file, struct execve_event *event) {
    writecur(file, "{", 0);

    const time_t timestamp = time(NULL);
    
    char *start = (char*)malloc(sizeof(char) * 100);
    assert(start);

    sprintf(start, "\"timestamp\":%lu,", timestamp);
    int res = writecur(file, start, 0);
    checkerr();
    free(start);

    char *program = replace_char(event->filename, '"', '\\');
    if (!program) return false;

    char *program_str = (char*)malloc(sizeof(char) * (strlen(program) + 24));
    sprintf(program_str, "\"filename\":\"%s\",", program);
    res = writecur(file, program_str, 0);
    checkerr();
    free(program_str);
    free(program);

    char *pid = (char*)malloc(sizeof(char) * 64);
    sprintf(pid, "\"pid\":%u,", event->pid);
    res = writecur(file, pid, 0);
    checkerr();
    free(pid);

    char *tgid = (char*)malloc(sizeof(char) * 64);
    sprintf(tgid, "\"tgid\":%u,", event->tgid);
    res = writecur(file, tgid, 0);
    checkerr();
    free(tgid);

    char *syscall_nr = (char*)malloc(sizeof(char) * 64);
    sprintf(syscall_nr, "\"syscall_nr\":%d,", event->syscall_nr);
    res = writecur(file, syscall_nr, 0);
    checkerr();
    free(syscall_nr);

    res = writecur(file, "\"arguments\":[", 0);
    checkerr();

    const size_t argvlen = arrlen(event->argv);

    int i;
    for (i = 0; i < event->argv_len; i++) {
        char *tmp = replace_char(event->argv[i], '"', '\\');
        if (!tmp) return false;

        char *arg_str = (char*)malloc(sizeof(char) * (128 + strlen(tmp)));
        assert(arg_str);

        sprintf(arg_str, "\"%s\"", tmp);
        res = writecur(file, arg_str, 0);
        if ((i + 1) != event->argv_len) {
            fprintf(file, ",");
        }
        checkerr();
        free(arg_str);
        free(tmp);
    }

    res = writecur(file, "],", 0);
    checkerr();

    res = writecur(file, "\"environment\":{", 0);
    checkerr();

    const size_t envplen = arrlen(event->envp);

    for (i = 0; i < event->envp_len; i++) {
        if (event->envp[i][0] == 0) {
            fprintf(file, ",");
            checkerr();
            break;
        }

        int sep = envsep(event->envp[i]);
        char *tmp = replace_char(event->envp[i], '"', '\\');
        if (!tmp) return false;

        char *env_str = (char*)malloc(sizeof(char) * (150 + strlen(tmp)));
        assert(env_str);

        snprintf(env_str, sep + 2, "\"%s", tmp);
        if (sep + 1 >= strlen(tmp)) {
            if (sep + 1 >= strlen(env_str)) {
                goto end;
            }
        } else {
            sprintf(env_str + sep + 1, "\":\"%s\"", tmp + sep + 1);
        }
        res = writecur(file, env_str, 0);
        
    end:
        if ((i + 1) != event->envp_len) {
            fprintf(file, ",");
        }
        checkerr();
        free(env_str);
        free(tmp);
    }

    res = writecur(file, "}}", 0);
    return true;
}

const bool write_json_network(FILE *file, struct net_event *event) {
    writecur(file, "{", 0);

    const time_t timestamp = time(NULL);
    
    char *start = (char*)malloc(sizeof(char) * 100);
    assert(start);

    sprintf(start, "\"timestamp\":%lu,", timestamp);
    int res = writecur(file, start, 0);
    checkerr();
    free(start);

    char *pid = (char*)malloc(sizeof(char) * 64);
    sprintf(pid, "\"pid\":%lu,", event->pid);
    res = writecur(file, pid, 0);
    checkerr();
    free(pid);

    char *tgid = (char*)malloc(sizeof(char) * 64);
    sprintf(tgid, "\"tgid\":%lu,", event->tgid);
    res = writecur(file, tgid, 0);
    checkerr();
    free(tgid);

    char *protocol = (char*)malloc(sizeof(char) * 64);
    sprintf(protocol, "\"protocol\":%u,", event->protocol);
    res = writecur(file, protocol, 0);
    checkerr();
    free(protocol);

    char *family = (char*)malloc(sizeof(char) * 64);
    sprintf(family, "\"family\":%u,", event->family);
    res = writecur(file, family, 0);
    checkerr();
    free(family);

    char saddr_str[INET6_ADDRSTRLEN];
    char daddr_str[INET6_ADDRSTRLEN];

    if (event->family == AF_INET) {
        inet_ntop(AF_INET, event->saddr, saddr_str, sizeof(saddr_str));
        inet_ntop(AF_INET, event->daddr, daddr_str, sizeof(daddr_str));
    } else if (event->family == AF_INET6) {
        inet_ntop(AF_INET6, event->saddr, saddr_str, sizeof(saddr_str));
        inet_ntop(AF_INET6, event->daddr, daddr_str, sizeof(daddr_str));
    }

    char *saddr = (char*)malloc(sizeof(char) * (strlen(saddr_str) + 20));
    sprintf(saddr, "\"saddr\":\"%s\",", saddr_str);
    res = writecur(file, saddr, 0);
    checkerr();
    free(saddr);

    char *daddr = (char*)malloc(sizeof(char) * (strlen(daddr_str) + 20));
    sprintf(daddr, "\"daddr\":\"%s\",", daddr_str);
    res = writecur(file, daddr, 0);
    checkerr();
    free(daddr);

    char *dport = (char*)malloc(sizeof(char) * 64);
    sprintf(dport, "\"dport\":%u", ntohs(event->dport));
    res = writecur(file, dport, 0);
    checkerr();
    free(dport);

    res = writecur(file, "}", 0);
    return true;
}

const bool write_json_open(FILE *file, struct open_event *event) {
    fprintf(file, "{");

    const time_t timestamp = time(NULL);
    
    fprintf(file, "\"timestamp\":%lu,", timestamp);
    
    // Safe handling of filename field to escape quotes
    char *escaped_filename = (char*)malloc(strlen(event->filename) * 2);  // Worst case every character needs escaping
    assert(escaped_filename);
    const char *src = event->filename;
    char *dst = escaped_filename;
    while (*src) {
        if (*src == '"') {
            *dst++ = '\\';  // Escape double quotes
        }
        *dst++ = *src++;
    }
    *dst = '\0';

    fprintf(file, "\"filename\":\"%s\",", escaped_filename);
    free(escaped_filename);

    fprintf(file, "\"pid\":%u,", event->pid);
    fprintf(file, "\"tgid\":%u,", event->tgid);
    fprintf(file, "\"flags\":%d,", event->flags);
    fprintf(file, "\"mode\":%u", event->mode);

    fprintf(file, "}");

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
