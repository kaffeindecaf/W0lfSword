/* PoC lab harness (C6.2): load a crafted XML catalog, resolve a public id,
 * clean up. Exercises xmlParseXMLCatalogNode's nextCatalog handling.
 *
 * Build (per fork):
 *   cc -I<fork>/include -I<builddir> poclab_cat.c -L<builddir> -lxml2 -lm
 * Run:
 *   ./poclab_cat catalog.xml
 */
#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/catalog.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s catalog.xml\n", argv[0]); return 2; }
    xmlInitParser();
    if (xmlLoadCatalog(argv[1]) == 0) {
        printf("catalog load FAILED: %s\n", argv[1]);
    } else {
        printf("catalog loaded: %s\n", argv[1]);
    }
    xmlChar *r = xmlCatalogResolvePublic((const xmlChar *)"-//TEST//PUB//EN");
    printf("resolve public: %s\n", r ? (const char *)r : "(null)");
    if (r) xmlFree(r);
    xmlCatalogCleanup();
    xmlCleanupParser();
    printf("cleanup done\n");
    return 0;
}
