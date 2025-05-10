// uid_gid_lookup.h

#ifndef UID_GID_LOOKUP_H
#define UID_GID_LOOKUP_H

#include <stdbool.h>
#include <sys/types.h>

#define UID_CACHE_SIZE 64
#define GID_CACHE_SIZE 64
#define NAME_LEN 32

/* Resolve UID to username, caching up to UID_CACHE_SIZE entries */
const char *uid_to_name(uid_t uid);

/* Resolve GID to groupname, caching up to GID_CACHE_SIZE entries */
const char *gid_to_name(gid_t gid);

#endif // UID_GID_LOOKUP_H
