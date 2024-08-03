#include <stdbool.h>
#include <stdio.h>
#include "../common/common.h"

#pragma once

const bool write_json(FILE *file, struct execve_event *event);
