#!/bin/sh
# Extract the AFD_CONNECT_INFO declarations from include/wine/afd.h and run the
# structural byte-offset test against them.
set -e
dir=$(cd "$(dirname "$0")" && pwd)
out=${TMPDIR:-/tmp}/afd-connect-layout-test.$$
mkdir -p "$out"
sed -n '/^struct afd_connect_info_params_64$/,/^C_ASSERT( sizeof(struct afd_connect_info_params_32) == 12 );$/p' \
    "$dir/../include/wine/afd.h" > "$out/afd_connect_layout_gen.h"
test -s "$out/afd_connect_layout_gen.h" || { echo "could not extract structs from include/wine/afd.h"; exit 1; }
grep -q 'afd_connect_info_params_64' "$out/afd_connect_layout_gen.h"
grep -q 'afd_connect_info_params_32' "$out/afd_connect_layout_gen.h"
${CC:-gcc} -std=c99 -Wall -Wextra -Wno-unused-function -I "$out" -o "$out/test" "$dir/afd_connect_layout_test.c"
"$out/test"
rc=$?
rm -rf "$out"
exit $rc
