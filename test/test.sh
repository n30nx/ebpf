#!/bin/bash
make
sudo ./loader execve.o new.json &
