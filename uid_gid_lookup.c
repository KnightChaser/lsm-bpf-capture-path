// uid_gid_lookup.c

#include "uid_gid_lookup.h"
#include <grp.h>
#include <pwd.h>
#include <string.h>

static struct {
    uid_t uid;
    char name[NAME_LEN];
    bool valid;
} uid_cache[UID_CACHE_SIZE];

/**
 * @brief Return pointer to a null-terminated string in cache
 *
 * @param uid User ID to resolve
 * @return Pointer to the username string
 */
const char *uid_to_name(uid_t uid) {
    for (size_t i = 0; i < UID_CACHE_SIZE; i++) {
        if (uid_cache[i].valid && uid_cache[i].uid == uid)
            return uid_cache[i].name;
    }
    struct passwd *pw = getpwuid(uid);
    const char *nm = pw ? pw->pw_name : "unknown";
    for (size_t i = 0; i < UID_CACHE_SIZE; i++) {
        if (!uid_cache[i].valid) {
            uid_cache[i].valid = true;
            uid_cache[i].uid = uid;
            strncpy(uid_cache[i].name, nm, NAME_LEN - 1);
            uid_cache[i].name[NAME_LEN - 1] = '\0';
            break;
        }
    }
    return nm;
}

static struct {
    gid_t gid;
    char name[NAME_LEN];
    bool valid;
} gid_cache[GID_CACHE_SIZE];

/**
 * @brief Return pointer to a null-terminated string in cache
 *
 * @param gid Group ID to resolve
 * @return Pointer to the group name string
 */
const char *gid_to_name(gid_t gid) {
    for (size_t i = 0; i < GID_CACHE_SIZE; i++) {
        if (gid_cache[i].valid && gid_cache[i].gid == gid)
            return gid_cache[i].name;
    }
    struct group *gr = getgrgid(gid);
    const char *nm = gr ? gr->gr_name : "unknown";
    for (size_t i = 0; i < GID_CACHE_SIZE; i++) {
        if (!gid_cache[i].valid) {
            gid_cache[i].valid = true;
            gid_cache[i].gid = gid;
            strncpy(gid_cache[i].name, nm, NAME_LEN - 1);
            gid_cache[i].name[NAME_LEN - 1] = '\0';
            break;
        }
    }
    return nm;
}
