/* SaltyOS kernel32.dll - PE Win32 compatibility layer */

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef signed int int32_t;
typedef signed long long int64_t;
typedef __SIZE_TYPE__ size_t;
typedef __UINTPTR_TYPE__ uintptr_t;

typedef int32_t BOOL;
typedef uint32_t DWORD;
typedef int64_t HANDLE;
typedef uint64_t cap_t;

#define TRUE 1
#define FALSE 0

#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define CURRENT_PROCESS_PSEUDO_HANDLE ((HANDLE)-1)

#define STD_INPUT_HANDLE  0xFFFFFFF6u
#define STD_OUTPUT_HANDLE 0xFFFFFFF5u
#define STD_ERROR_HANDLE  0xFFFFFFF4u

#define ERROR_SUCCESS 0u
#define ERROR_INVALID_FUNCTION 1u
#define ERROR_INVALID_HANDLE 6u
#define ERROR_NOT_ENOUGH_MEMORY 8u
#define ERROR_INVALID_PARAMETER 87u

#define TRONA_OK 0u

#define SYS_SEND 0u
#define SYS_NBSEND 4u
#define SYS_CALL 2u
#define SYS_YIELD 8u
#define SYS_DEBUG_PUTBUF 15u

#define CAP_PROCMGR_EP 3u

#define PM_EXIT 2u
#define PM_GETPID 4u

#define W32_CONSOLE_WRITE 0x101u
#define W32_CONSOLE_READ 0x102u
#define W32_GET_CONSOLE_MODE 0x103u
#define W32_SET_CONSOLE_MODE 0x104u
#define W32_CLIENT_EXIT 0x106u

#define DEFAULT_INPUT_MODE 0x0007u
#define DEFAULT_OUTPUT_MODE 0x0003u

#define KERNEL32_MAX_INLINE_BYTES 144u

typedef struct {
    uint64_t error;
    uint64_t value;
} TronaResult;

typedef struct {
    uint64_t label;
    uint64_t length;
    uint64_t regs[20];
} TronaMsg;

typedef struct {
    uint64_t msg[22];
    uint64_t badge;
    uint64_t caps[4];
    uint64_t receive_cnode;
    uint64_t receive_index;
    uint64_t receive_depth;
    uint64_t reserved[478];
} IpcBuffer;

typedef struct {
    IpcBuffer *ipc_buffer;
    int32_t send_cap_count;
    int32_t _pad;
} IpcContext;

IpcContext __trona_ipc_ctx = { 0, 0, 0 };
uint64_t __win32srv_ep = 0;

static DWORD g_last_error = 0;

static inline uint64_t msginfo(uint64_t label, uint64_t length, uint64_t caps) {
    return (label << 12) | (caps << 7) | (length & 0x7F);
}

static inline void mem_zero(void *ptr, size_t len) {
    uint8_t *p = (uint8_t *)ptr;
    size_t i;
    for (i = 0; i < len; i++) {
        p[i] = 0;
    }
}

static inline void mem_copy(void *dst, const void *src, size_t len) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    size_t i;
    for (i = 0; i < len; i++) {
        d[i] = s[i];
    }
}

static inline size_t min_size(size_t a, size_t b) {
    return a < b ? a : b;
}

static inline TronaResult trona_syscall(
    uint64_t num,
    uint64_t a0,
    uint64_t a1,
    uint64_t a2,
    uint64_t a3,
    uint64_t a4,
    uint64_t a5
) {
    TronaResult result;
#if defined(__x86_64__)
    __asm__ volatile(
        "mov %2, %%rax\n"
        "mov %3, %%rdi\n"
        "mov %4, %%rsi\n"
        "mov %5, %%rdx\n"
        "mov %6, %%r10\n"
        "mov %7, %%r8\n"
        "mov %8, %%r9\n"
        "syscall\n"
        : "=a"(result.error), "=d"(result.value)
        : "r"(num), "r"(a0), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
        : "rcx", "r11", "rdi", "rsi", "r10", "r8", "r9", "memory"
    );
#elif defined(__aarch64__)
    register uint64_t x0 __asm__("x0") = a0;
    register uint64_t x1 __asm__("x1") = a1;
    register uint64_t x2 __asm__("x2") = a2;
    register uint64_t x3 __asm__("x3") = a3;
    register uint64_t x4 __asm__("x4") = a4;
    register uint64_t x5 __asm__("x5") = a5;
    register uint64_t x8 __asm__("x8") = num;
    __asm__ volatile(
        "svc #0"
        : "+r"(x0), "+r"(x1)
        : "r"(x2), "r"(x3), "r"(x4), "r"(x5), "r"(x8)
        : "memory"
    );
    result.error = x0;
    result.value = x1;
#else
#error Unsupported architecture
#endif
    return result;
}

static inline void write_overflow(const TronaMsg *msg) {
    IpcBuffer *ipc_buffer = __trona_ipc_ctx.ipc_buffer;
    uint64_t i;
    if (ipc_buffer == (IpcBuffer *)0 || msg->length <= 4) {
        return;
    }
    for (i = 0; i < msg->length - 4 && i < 16; i++) {
        ipc_buffer->msg[6 + i] = msg->regs[4 + i];
    }
}

static inline void copy_reply(TronaMsg *reply) {
    IpcBuffer *ipc_buffer = __trona_ipc_ctx.ipc_buffer;
    uint64_t i;
    if (reply == (TronaMsg *)0 || ipc_buffer == (IpcBuffer *)0) {
        return;
    }
    reply->label = ipc_buffer->msg[0];
    reply->length = ipc_buffer->msg[1];
    for (i = 0; i < 4; i++) {
        reply->regs[i] = ipc_buffer->msg[2 + i];
    }
    for (i = 0; i < 16; i++) {
        reply->regs[4 + i] = ipc_buffer->msg[6 + i];
    }
}

static inline int trona_call(cap_t ep, const TronaMsg *msg, TronaMsg *reply) {
    TronaResult result;
    uint64_t info = msginfo(msg->label, msg->length, 0);
    write_overflow(msg);
    result = trona_syscall(
        SYS_CALL,
        ep,
        info,
        msg->regs[0],
        msg->regs[1],
        msg->regs[2],
        msg->regs[3]
    );
    __trona_ipc_ctx.send_cap_count = 0;
    if (result.error == 0) {
        copy_reply(reply);
    }
    return (int)result.error;
}

static inline int trona_send(cap_t ep, const TronaMsg *msg) {
    TronaResult result;
    uint64_t info = msginfo(msg->label, msg->length, 0);
    write_overflow(msg);
    result = trona_syscall(
        SYS_SEND,
        ep,
        info,
        msg->regs[0],
        msg->regs[1],
        msg->regs[2],
        msg->regs[3]
    );
    __trona_ipc_ctx.send_cap_count = 0;
    return (int)result.error;
}

static inline int trona_nbsend(cap_t ep, const TronaMsg *msg) {
    TronaResult result;
    uint64_t info = msginfo(msg->label, msg->length, 0);
    write_overflow(msg);
    result = trona_syscall(
        SYS_NBSEND,
        ep,
        info,
        msg->regs[0],
        msg->regs[1],
        msg->regs[2],
        msg->regs[3]
    );
    __trona_ipc_ctx.send_cap_count = 0;
    return (int)result.error;
}

static inline void debug_putbuf(const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        size_t chunk = min_size(len - off, 256);
        (void)trona_syscall(SYS_DEBUG_PUTBUF, (uint64_t)(uintptr_t)(buf + off), (uint64_t)chunk, 0, 0, 0, 0);
        off += chunk;
    }
}

static inline BOOL set_error_false(DWORD err) {
    g_last_error = err;
    return FALSE;
}

static inline void clear_error(void) {
    g_last_error = ERROR_SUCCESS;
}

static inline HANDLE std_handle_to_handle(DWORD which) {
    switch (which) {
    case STD_INPUT_HANDLE:
        return 4;
    case STD_OUTPUT_HANDLE:
        return 8;
    case STD_ERROR_HANDLE:
        return 12;
    default:
        return INVALID_HANDLE_VALUE;
    }
}

static inline int handle_to_fd(HANDLE handle) {
    if (handle == 4) {
        return 0;
    }
    if (handle == 8) {
        return 1;
    }
    if (handle == 12) {
        return 2;
    }
    return -1;
}

static inline BOOL is_console_output(HANDLE handle) {
    return handle == 8 || handle == 12;
}

static inline BOOL is_console_input(HANDLE handle) {
    return handle == 4;
}

DWORD GetLastError(void) {
    return g_last_error;
}

void SetLastError(DWORD err) {
    g_last_error = err;
}

HANDLE GetStdHandle(DWORD which) {
    HANDLE handle = std_handle_to_handle(which);
    if (handle == INVALID_HANDLE_VALUE) {
        g_last_error = ERROR_INVALID_HANDLE;
    } else {
        clear_error();
    }
    return handle;
}

BOOL WriteConsoleA(
    HANDLE h_console_output,
    const uint8_t *lp_buffer,
    DWORD n_number_of_chars_to_write,
    DWORD *lp_number_of_chars_written,
    const uint8_t *lp_reserved
) {
    size_t total = 0;
    (void)lp_reserved;

    if (lp_buffer == (const uint8_t *)0) {
        return set_error_false(ERROR_INVALID_PARAMETER);
    }
    if (!is_console_output(h_console_output)) {
        return set_error_false(ERROR_INVALID_HANDLE);
    }

    while (total < (size_t)n_number_of_chars_to_write) {
        size_t chunk = min_size((size_t)n_number_of_chars_to_write - total, KERNEL32_MAX_INLINE_BYTES);
        TronaMsg msg;
        TronaMsg reply;
        uint8_t *dst;

        mem_zero(&msg, sizeof(msg));
        mem_zero(&reply, sizeof(reply));
        msg.label = W32_CONSOLE_WRITE;
        msg.length = 1 + ((uint64_t)chunk + 7u) / 8u;
        msg.regs[0] = (uint64_t)chunk;
        dst = (uint8_t *)&msg.regs[1];
        mem_copy(dst, lp_buffer + total, chunk);

        if (__win32srv_ep != 0 && trona_call(__win32srv_ep, &msg, &reply) == 0 && reply.label == TRONA_OK) {
            size_t written = (size_t)reply.regs[0];
            if (written == 0) {
                break;
            }
            total += written;
        } else {
            debug_putbuf(lp_buffer + total, chunk);
            total += chunk;
        }
    }

    if (lp_number_of_chars_written != (DWORD *)0) {
        *lp_number_of_chars_written = (DWORD)total;
    }
    clear_error();
    return TRUE;
}

BOOL WriteConsoleW(
    HANDLE h_console_output,
    const uint16_t *lp_buffer,
    DWORD n_number_of_chars_to_write,
    DWORD *lp_number_of_chars_written,
    const uint8_t *lp_reserved
) {
    DWORD total = 0;
    uint8_t ascii_buf[KERNEL32_MAX_INLINE_BYTES];

    if (lp_buffer == (const uint16_t *)0) {
        return set_error_false(ERROR_INVALID_PARAMETER);
    }

    while (total < n_number_of_chars_to_write) {
        size_t chunk = min_size((size_t)(n_number_of_chars_to_write - total), (size_t)KERNEL32_MAX_INLINE_BYTES);
        DWORD written = 0;
        size_t i;
        for (i = 0; i < chunk; i++) {
            uint16_t ch = lp_buffer[total + (DWORD)i];
            ascii_buf[i] = ch < 128 ? (uint8_t)ch : (uint8_t)'?';
        }
        if (!WriteConsoleA(h_console_output, ascii_buf, (DWORD)chunk, &written, lp_reserved)) {
            if (lp_number_of_chars_written != (DWORD *)0) {
                *lp_number_of_chars_written = total;
            }
            return FALSE;
        }
        total += written;
        if (written == 0) {
            break;
        }
    }

    if (lp_number_of_chars_written != (DWORD *)0) {
        *lp_number_of_chars_written = total;
    }
    clear_error();
    return TRUE;
}

BOOL ReadConsoleA(
    HANDLE h_console_input,
    uint8_t *lp_buffer,
    DWORD n_number_of_chars_to_read,
    DWORD *lp_number_of_chars_read,
    const uint8_t *lp_input_control
) {
    size_t total = 0;
    (void)lp_input_control;

    if (lp_buffer == (uint8_t *)0) {
        return set_error_false(ERROR_INVALID_PARAMETER);
    }
    if (!is_console_input(h_console_input)) {
        return set_error_false(ERROR_INVALID_HANDLE);
    }
    if (__win32srv_ep == 0 || __trona_ipc_ctx.ipc_buffer == (IpcBuffer *)0) {
        return set_error_false(ERROR_INVALID_FUNCTION);
    }

    while (total < (size_t)n_number_of_chars_to_read) {
        size_t chunk = min_size((size_t)n_number_of_chars_to_read - total, KERNEL32_MAX_INLINE_BYTES);
        TronaMsg msg;
        TronaMsg reply;
        size_t actual;

        mem_zero(&msg, sizeof(msg));
        mem_zero(&reply, sizeof(reply));
        msg.label = W32_CONSOLE_READ;
        msg.length = 1;
        msg.regs[0] = (uint64_t)chunk;

        if (trona_call(__win32srv_ep, &msg, &reply) != 0 || reply.label != TRONA_OK) {
            if (lp_number_of_chars_read != (DWORD *)0) {
                *lp_number_of_chars_read = (DWORD)total;
            }
            return set_error_false(ERROR_INVALID_FUNCTION);
        }

        actual = (size_t)reply.regs[0];
        if (actual > chunk) {
            actual = chunk;
        }
        mem_copy(lp_buffer + total, (const uint8_t *)&reply.regs[1], actual);
        total += actual;
        if (actual < chunk) {
            break;
        }
    }

    if (lp_number_of_chars_read != (DWORD *)0) {
        *lp_number_of_chars_read = (DWORD)total;
    }
    clear_error();
    return TRUE;
}

BOOL GetConsoleMode(HANDLE h_console_handle, DWORD *lp_mode) {
    TronaMsg msg;
    TronaMsg reply;

    if (lp_mode == (DWORD *)0) {
        return set_error_false(ERROR_INVALID_PARAMETER);
    }
    if (!is_console_input(h_console_handle) && !is_console_output(h_console_handle)) {
        return set_error_false(ERROR_INVALID_HANDLE);
    }

    if (__win32srv_ep == 0 || __trona_ipc_ctx.ipc_buffer == (IpcBuffer *)0) {
        *lp_mode = is_console_input(h_console_handle) ? DEFAULT_INPUT_MODE : DEFAULT_OUTPUT_MODE;
        clear_error();
        return TRUE;
    }

    mem_zero(&msg, sizeof(msg));
    mem_zero(&reply, sizeof(reply));
    msg.label = W32_GET_CONSOLE_MODE;
    msg.length = 1;
    msg.regs[0] = is_console_input(h_console_handle) ? 0u : 1u;

    if (trona_call(__win32srv_ep, &msg, &reply) != 0 || reply.label != TRONA_OK) {
        return set_error_false(ERROR_INVALID_FUNCTION);
    }

    *lp_mode = (DWORD)reply.regs[0];
    clear_error();
    return TRUE;
}

BOOL SetConsoleMode(HANDLE h_console_handle, DWORD dw_mode) {
    TronaMsg msg;
    TronaMsg reply;

    if (!is_console_input(h_console_handle) && !is_console_output(h_console_handle)) {
        return set_error_false(ERROR_INVALID_HANDLE);
    }

    if (__win32srv_ep == 0 || __trona_ipc_ctx.ipc_buffer == (IpcBuffer *)0) {
        clear_error();
        return TRUE;
    }

    mem_zero(&msg, sizeof(msg));
    mem_zero(&reply, sizeof(reply));
    msg.label = W32_SET_CONSOLE_MODE;
    msg.length = 2;
    msg.regs[0] = is_console_input(h_console_handle) ? 0u : 1u;
    msg.regs[1] = (uint64_t)dw_mode;

    if (trona_call(__win32srv_ep, &msg, &reply) != 0 || reply.label != TRONA_OK) {
        return set_error_false(ERROR_INVALID_FUNCTION);
    }

    clear_error();
    return TRUE;
}

BOOL CloseHandle(HANDLE h_object) {
    if (h_object == CURRENT_PROCESS_PSEUDO_HANDLE || h_object == 4 || h_object == 8 || h_object == 12) {
        clear_error();
        return TRUE;
    }
    return set_error_false(ERROR_INVALID_HANDLE);
}

void ExitProcess(uint32_t u_exit_code) {
    TronaMsg msg;
    TronaMsg reply;

    if (__win32srv_ep != 0 && __trona_ipc_ctx.ipc_buffer != (IpcBuffer *)0) {
        mem_zero(&msg, sizeof(msg));
        msg.label = W32_CLIENT_EXIT;
        msg.length = 1;
        msg.regs[0] = (uint64_t)u_exit_code;
        for (int tries = 0; tries < 16; tries++) {
            if (trona_nbsend(__win32srv_ep, &msg) == 0) {
                break;
            }
            (void)trona_syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
        }
    }

    mem_zero(&msg, sizeof(msg));
    mem_zero(&reply, sizeof(reply));
    msg.label = PM_EXIT;
    msg.length = 1;
    msg.regs[0] = (uint64_t)u_exit_code;
    (void)trona_call(CAP_PROCMGR_EP, &msg, &reply);

    for (;;) {
        (void)trona_syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
    }
}

HANDLE GetCurrentProcess(void) {
    return CURRENT_PROCESS_PSEUDO_HANDLE;
}

DWORD GetCurrentProcessId(void) {
    TronaMsg msg;
    TronaMsg reply;

    if (__trona_ipc_ctx.ipc_buffer == (IpcBuffer *)0) {
        return 0;
    }

    mem_zero(&msg, sizeof(msg));
    mem_zero(&reply, sizeof(reply));
    msg.label = PM_GETPID;
    msg.length = 0;
    if (trona_call(CAP_PROCMGR_EP, &msg, &reply) == 0 && reply.label == TRONA_OK) {
        clear_error();
        return (DWORD)reply.regs[0];
    }
    return 0;
}