#include <stdbool.h>
#include <stdio.h>
#include "../common/common.h"

#pragma once

const bool write_json_network(FILE *file, struct net_event *event);
const bool write_json_execve(FILE *file, struct execve_event *event);
const bool write_json_open(FILE *file, struct open_event *event);
