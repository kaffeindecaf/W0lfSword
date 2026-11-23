#!/usr/bin/env bash

if [[ $# -eq 1 && $1 == --help ]]; then
    printf 'Usage: %s BEFORE AFTER\nCompare two regular files side by side.\nExit codes: 0 identical, 1 different, 2 error.\n' "${0##*/}"
    exit 0
fi

if [[ $# -ne 2 ]]; then
    printf 'Usage: %s BEFORE AFTER\n' "${0##*/}" >&2
    exit 2
fi

before=$1
after=$2
for path in "$before" "$after"; do
    if [[ ! -f $path ]]; then
        printf '%s: expected a regular file: %s\n' "${0##*/}" "$path" >&2
        exit 2
    fi
done

# Prefix relative paths so even a file named "-" is read from disk.
[[ $before == /* ]] || before=./$before
[[ $after == /* ]] || after=./$after
exec diff -y "$before" "$after"
