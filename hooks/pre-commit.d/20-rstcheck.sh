#!/bin/sh
# SPDX-License-Identifier: MIT

set -efu

ignore_rstcheck=$(git config --type=bool --default="false" hooks.ignorerstcheck)

[ "$ignore_rstcheck" != "true" ] || exit 0

rstfiles=$(git diff --cached --name-only --diff-filter=ACMR -- '*.rst')

[ -n "$rstfiles" ] || exit 0

printf '%s\n' "$rstfiles" |xargs rstcheck
