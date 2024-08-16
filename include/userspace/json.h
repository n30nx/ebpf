#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "../common/common.h"

#pragma once

const bool write_json_execve(FILE *file, uint64_t timestamp, struct execve_event *event);
const bool write_json_open(FILE *file, uint64_t timestamp, struct open_event *event);
