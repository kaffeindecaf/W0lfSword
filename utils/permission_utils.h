#ifndef permission_utils_h
#define permission_utils_h

#import <Foundation/Foundation.h>
#import <stdbool.h>
#import <sys/stat.h>
#import <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

int apply_parent_permissions(const char *path);
bool force_chown_root_wheel(const char *path);
bool is_ssv_protected_path(const char *path);
bool get_parent_dir_info(const char *path, uid_t *uid, gid_t *gid, mode_t *mode);
void apply_permissions_after_operation(const char *path, const char *operation);

#ifdef __cplusplus
}
#endif

#endif
