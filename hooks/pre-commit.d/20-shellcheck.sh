#!/bin/sh
# SPDX-License-Identifier: MIT

set -efu

ignore_shellcheck=$(git config --type=bool --default="false" hooks.ignoreshellcheck)

[ "$ignore_shellcheck" != "true" ] || exit 0

while read -r file; do
	file -i "$file" |grep -q shellscript ||
		continue
	shellcheck "$file"
done << EOF
	$(git diff --cached --name-only --diff-filter=ACMR)
EOF
