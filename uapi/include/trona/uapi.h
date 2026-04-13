/* trona-uapi public header
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef TRONA_UAPI_H
#define TRONA_UAPI_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define TRONA_UAPI_VERSION 1u

typedef uint64_t trona_cap_t;

typedef struct trona_sysret {
    uint64_t error;
    uint64_t value;
} trona_sysret_t;

enum trona_syscall {
    TRONA_SYS_SEND = 0,
    TRONA_SYS_RECV = 1,
    TRONA_SYS_CALL = 2,
    TRONA_SYS_REPLY_RECV = 3,
    TRONA_SYS_NBSEND = 4,
    TRONA_SYS_SIGNAL = 5,
    TRONA_SYS_WAIT = 6,
    TRONA_SYS_POLL = 7,
    TRONA_SYS_YIELD = 8,
    TRONA_SYS_INVOKE = 9,
    TRONA_SYS_FUTEX = 18,
    TRONA_SYS_GETRANDOM = 19,
};

enum trona_error {
    TRONA_OK = 0,
    TRONA_INVALID_CAPABILITY = 1,
    TRONA_INVALID_OPERATION = 2,
    TRONA_INSUFFICIENT_RIGHTS = 3,
    TRONA_INVALID_ARGUMENT = 4,
    TRONA_OUT_OF_MEMORY = 5,
    TRONA_NOT_FOUND = 6,
    TRONA_BUSY = 7,
    TRONA_ALREADY_EXISTS = 8,
    TRONA_WOULD_BLOCK = 9,
    TRONA_INTERRUPTED = 15,
    TRONA_SLOT_OCCUPIED = 0x18,
    TRONA_ALREADY_MAPPED = 0x19,
    TRONA_ALREADY_BOUND = 0x1A,
    TRONA_IN_PROGRESS = 0x10,
};

#ifdef __cplusplus
}
#endif

#endif /* TRONA_UAPI_H */
