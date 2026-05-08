#!/bin/sh
# SPDX-License-Identifier: MIT

set -efu

HOOK_DIR="$(dirname "$0")/$(basename "$0").d"

[ -d "$HOOK_DIR" ] || exit 0

for hook in $(set +f && cd "$HOOK_DIR" && echo *.sh); do
	test -x "$HOOK_DIR/$hook" || continue
	sh "$HOOK_DIR/$hook"
done
