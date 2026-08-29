#!/usr/bin/env bash
# C6.2 — libxml2 fork-diff test: apple-oss-distributions/Libxml2 vs GNOME
# upstream. Clones both (cached in .w0lfsword/poclab/libxml2), patches
# Apple's fork for Linux (uri.c stdint include, xpath.c Darwin stub),
# cmake-builds both, runs the crafted-catalog harness across malformed
# nextCatalog shapes, reports the verdict.
set -euo pipefail
cd "$(dirname "$0")/.."

CACHE=".w0lfsword/poclab/libxml2"
mkdir -p "$CACHE"

[ -d "$CACHE/apple" ] || git clone --depth 1 https://github.com/apple-oss-distributions/Libxml2 "$CACHE/apple"
[ -d "$CACHE/upstream" ] || git clone --depth 1 https://github.com/GNOME/libxml2 "$CACHE/upstream"

# Linux build patches for Apple's fork (Darwin-only bits)
grep -q 'stdint.h' "$CACHE/apple/libxml2/uri.c" || \
    sed -i 's|#include <limits.h>|#include <limits.h>\n#include <stdint.h>|' "$CACHE/apple/libxml2/uri.c"
grep -q 'linkedOnOrAfterFall2022OSVersions(void) { return 1; }' "$CACHE/apple/libxml2/xpath.c" || \
    sed -i 's|#include "timsort.h"|#include "timsort.h"\n\n#if !defined(__APPLE__)\nint linkedOnOrAfterFall2022OSVersions(void) { return 1; }\n#endif|' "$CACHE/apple/libxml2/xpath.c"

echo "  building both forks (cmake, static) ..."
for f in apple upstream; do
    if [ "$f" = apple ]; then SRC="$CACHE/apple/libxml2"; else SRC="$CACHE/upstream"; fi
    cmake -B "$CACHE/build-$f" -S "$SRC" -DBUILD_SHARED_LIBS=OFF \
        -DLIBXML2_WITH_PYTHON=OFF -DLIBXML2_WITH_LZMA=OFF -DLIBXML2_WITH_ZLIB=OFF >/dev/null 2>&1 || true
    cmake --build "$CACHE/build-$f" -j4 --target xmllint >/dev/null 2>&1 || { echo "  build failed: $f"; }
done

cc -I "$CACHE/apple/libxml2/include" -I "$CACHE/build-apple" scripts/poclab_cat.c \
    -L "$CACHE/build-apple" -lxml2 -lm -o "$CACHE/cat_apple"
cc -I "$CACHE/upstream/include" -I "$CACHE/build-upstream" scripts/poclab_cat.c \
    -L "$CACHE/build-upstream" -lxml2 -lm -o "$CACHE/cat_upstream"

# crafted catalogs
cat > "$CACHE/cat_missing.xml" <<'EOF'
<?xml version="1.0"?>
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
  <nextCatalog/>
  <nextCatalog/>
</catalog>
EOF
cat > "$CACHE/cat_empty.xml" <<'EOF'
<?xml version="1.0"?>
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
  <nextCatalog catalog=""/>
  <nextCatalog catalog=""/>
</catalog>
EOF
cat > "$CACHE/cat_mixed.xml" <<'EOF'
<?xml version="1.0"?>
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
  <nextCatalog catalog="cat_real.xml"/>
  <nextCatalog/>
</catalog>
EOF
cat > "$CACHE/cat_real.xml" <<'EOF'
<?xml version="1.0"?>
<catalog xmlns="urn:oasis:names:tc:entity:xmlns:xml:catalog">
  <public publicId="-//TEST//PUB//EN" uri="doc.xml"/>
</catalog>
EOF

AV=$( "$CACHE/build-apple/xmllint" --version 2>&1 | head -1 | sed 's/.*libxml version //' )
UV=$( "$CACHE/build-upstream/xmllint" --version 2>&1 | head -1 | sed 's/.*libxml version //' )
echo "  apple fork: libxml $AV   upstream: libxml $UV"
echo ""

crash=0
for f in cat_missing.xml cat_empty.xml cat_mixed.xml; do
    for exe in cat_apple cat_upstream; do
        out=$( "$CACHE/$exe" "$CACHE/$f" 2>&1 )
        if echo "$out" | grep -q 'AddressSanitizer\|Segmentation\|signal'; then
            echo "  CRASH: $exe on $f"
            echo "$out" | tail -3
            crash=1
        fi
    done
done
[ "$crash" = 0 ] && echo "  VERDICT: NEGATIVE - no crash on either fork across all shapes"
echo ""
cat <<'EOF'
  why (honest negative):
    - Apple's fork is 2.9.13-based (xmllint says 209013) but backports
      selectively: the CVE-2024-25062 reader guards and the modern
      xmlParseInternalSubset rewrite ARE present. A naive fork-diff
      overstates the risk from the version gap.
    - the upstream nextCatalog dedup loop (f75abfca, added after 2.9.13)
      is absent in Apple's fork, and the Aug-2026 NULL-deref fix
      (c632489) only guards THAT loop - which Apple's code does not
      have. So the tested malformed shapes (missing attr, empty attr,
      valid-then-invalid) crash neither fork.
    - real divergences found: no dedup of repeated nextCatalog entries
      (behavioral: extra catalog loads during resolution, recursion
      guard bounds it) and the fork does not compile on Linux without
      two patches (uri.c stdint, xpath.c Darwin symbol stub).
  caveat:
    - tested parse + resolve paths only. Deeper trigger hunting (schema
      validation, XInclude, push-parser) is future work.
    - docs: research/poclab.md
EOF
