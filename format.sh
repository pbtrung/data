#!/bin/bash

find ./src ./include ./tests -regex ".*\.\(cpp\|hpp\|c\|h\|cc\|hh\)" -exec echo "{}" \; -exec clang-format -i "{}" \;