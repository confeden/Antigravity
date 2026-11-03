#!/bin/sh
# Installs a verified helper only into a new private content directory.
set -eu
set -f
umask 077
fail() { printf '%s\n' "install-helper: $*" >&2; exit 1; }
[ "$#" -eq 2 ] || fail 'expected source and SHA-256'
source_file=$1
expected=$2
case "$expected" in *[!0-9a-f]*|'') fail 'invalid SHA-256';; esac
[ "${#expected}" -eq 64 ] || fail 'invalid SHA-256 length'
[ -n "${HOME:-}" ] || fail 'HOME is missing'
case "$HOME" in /*) ;; *) fail 'HOME must be absolute';; esac
uid=$(id -u)
# Every existing ancestor must be an ordinary directory owned by root or the
# current user, with no group/other write bits.  No path component is followed
# through a symbolic link.  A concurrent same-user namespace writer is excluded
# by the operator's clean-window obligation, not by these shell checks.
check_dir() {
    [ ! -L "$1" ] && [ -d "$1" ] || fail "unsafe directory: $1"
    owner=$(stat -c '%u' -- "$1") || fail 'stat failed'
    mode=$(stat -c '%a' -- "$1") || fail 'stat failed'
    [ "$owner" = 0 ] || [ "$owner" = "$uid" ] || fail 'foreign directory owner'
    case "$mode" in *[!0-7]*|'') fail 'invalid mode';; esac
    [ $((0$mode & 0022)) -eq 0 ] || fail 'writable shared ancestor'
}
check_dir /
oldifs=$IFS; IFS=/; set -- $HOME; IFS=$oldifs
path=''
for part do
    [ -n "$part" ] || continue
    case "$part" in .|..) fail 'invalid HOME component';; esac
    path="$path/$part"; check_dir "$path"
done
[ "$(stat -c '%u' -- "$HOME")" = "$uid" ] || fail 'HOME is not owned by current user'
path=$HOME
for part in .local share ag-unlocker wsl; do
    path="$path/$part"
    if [ ! -e "$path" ] && [ ! -L "$path" ]; then mkdir -m 700 -- "$path" || fail 'cannot create private directory'; fi
    check_dir "$path"
    [ "$(stat -c '%u' -- "$path")" = "$uid" ] || fail 'namespace is not owned by current user'
    case "$part" in ag-unlocker|wsl) [ "$(stat -c '%a' -- "$path")" = 700 ] || fail 'namespace mode must be 700';; esac
done
destination="$path/$expected"
verify_existing() {
    check_dir "$destination"
    [ "$(stat -c '%u:%a' -- "$destination")" = "$uid:700" ] || fail 'foreign or unsafe destination'
    leaf="$destination/ag_wsl_launch"
    [ ! -L "$leaf" ] && [ -f "$leaf" ] || fail 'existing helper is not a regular file'
    [ "$(stat -c '%u:%a:%h' -- "$leaf")" = "$uid:500:1" ] || fail 'existing helper owner, mode or links conflict'
    actual=$(sha256sum -- "$leaf") || fail 'existing helper hash failed'
    [ "${actual%% *}" = "$expected" ] || fail 'existing helper hash mismatch'
    printf '%s\n' "$leaf"
}
if [ -e "$destination" ] || [ -L "$destination" ]; then
    verify_existing
    exit 0
fi
if ! mkdir -m 700 -- "$destination" 2>/dev/null; then
    verify_existing
    exit 0
fi
temporary=''
cleanup() {
    [ -z "$temporary" ] || rm -f -- "$temporary"
    rmdir -- "$destination" 2>/dev/null || printf '%s\n' "install-helper: retained $destination" >&2
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
temporary=$(mktemp "$destination/.helper.XXXXXXXX") || fail 'mktemp failed'
cat -- "$source_file" > "$temporary" || fail 'copy failed'
actual=$(sha256sum -- "$temporary") || fail 'hash failed'
actual=${actual%% *}
[ "$actual" = "$expected" ] || fail 'hash mismatch'
# ELF64 little-endian, x86-64 (e_machine = 62).
magic=$(od -An -tx1 -N20 -- "$temporary" | tr -d ' \n')
case "$magic" in 7f454c46020101??????????????????????3e00) ;; *) fail 'unsupported ELF header';; esac
chmod 500 -- "$temporary"
ln -- "$temporary" "$destination/ag_wsl_launch" || fail 'publish failed'
rm -- "$temporary"; temporary=''
[ "$(sha256sum -- "$destination/ag_wsl_launch" | cut -d ' ' -f 1)" = "$expected" ] || fail 'published hash mismatch'
trap - EXIT HUP INT TERM
printf '%s\n' "$destination/ag_wsl_launch"
