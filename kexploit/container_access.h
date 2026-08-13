// container_access.h — userspace container access layer (FilzaSlop port)
//
// Provides app-container enumeration + sandbox token activation through the
// MobileContainerManager bridge, plus the iOS 26 LaunchServices app
// discovery technique (read the com.apple.lsd service container store).
//
// Pre-exploit, ContainerManager only trusts the MobileHouseArrest identity;
// after W0lfSword's kernel sandbox escape everything below works from Filza.
#ifndef container_access_h
#define container_access_h

#include <stdbool.h>
#include <stdint.h>

// ContainerManager classes (FilzaSlop audit)
enum {
    MCM_CLASS_APP_DATA       = 2,
    MCM_CLASS_EXTENSION_DATA = 4,
    MCM_CLASS_VPN_DATA       = 6,
    MCM_CLASS_APP_GROUP      = 7,
    MCM_CLASS_SERVICE_DATA   = 10,
    MCM_CLASS_SYSTEM_DATA    = 12,
    MCM_CLASS_SYSTEM_GROUP   = 13,
    MCM_CLASS_PROTECTED_DATA = 15,
};

// One-shot capability probe. Logs which classes/identifiers are reachable
// and how many app containers are enumerable. Returns true if any
// container lease activated successfully.
bool userspace_container_probe(void);

// Activate a container lease and return the resolved root path (caller
// frees with free()). Returns NULL on denial.
char *mcm_activate_container(uint64_t container_class, const char *identifier,
                             bool group, uint64_t part, const char *part_domain,
                             uint64_t flags);

// iOS 26 app discovery: activate the com.apple.lsd service container and
// scan its LaunchServices store files for bundle identifier candidates.
// Logs the candidate count; returns the first `limit` identifiers (caller
// frees each string and the array).
char **mcm_lsd_discover_apps(int limit);

#endif /* container_access_h */
