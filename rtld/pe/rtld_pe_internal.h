/* SaltyOS PE Runtime Loader (ld-trona-pe.so) - Internal Header
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Self-contained header: pe_rtld has NO external dependencies.
 * Reuses the same syscall stubs and primitives as the ELF rtld.
 */

#ifndef RTLD_PE_INTERNAL_H
#define RTLD_PE_INTERNAL_H

#include <stdint.h>
#include <stddef.h>

/* ============================================================
 * Debug output (via DebugPutBuf batch syscall)
 * ============================================================ */

#define SYS_DEBUG_PUTCHAR  10
#define SYS_DEBUG_PUTBUF   15

struct rtld_syscall_result {
    uint64_t error;
    uint64_t value;
};

/* Architecture-specific syscall primitives */
#if defined(__x86_64__)
#include "../elf/arch/x86_64/rtld_syscall.h"
#define PE_KERNEL32_CALL __attribute__((ms_abi))
#elif defined(__aarch64__)
#include "../elf/arch/aarch64/rtld_syscall.h"
#define PE_KERNEL32_CALL
#else
#error "Unsupported architecture"
#endif

static inline void pe_rtld_putc(char c) {
    rtld_putc_arch(c);
}

static inline void pe_rtld_puts(const char *s) {
    size_t len = 0;
    const char *p = s;
    while (*p++) len++;
    size_t off = 0;
    while (off < len) {
        size_t chunk = len - off;
        if (chunk > 256) chunk = 256;
        rtld_putbuf_arch(s + off, chunk);
        off += chunk;
    }
}

static inline void pe_rtld_hex(uint64_t val) {
    static const char hextab[] = "0123456789abcdef";
    char buf[18];
    buf[0] = '0';
    buf[1] = 'x';
    if (val == 0) {
        buf[2] = '0';
        buf[3] = '\0';
        pe_rtld_puts(buf);
        return;
    }
    char tmp[16];
    int pos = 15;
    while (val > 0 && pos >= 0) {
        tmp[pos--] = hextab[val & 0xF];
        val >>= 4;
    }
    int idx = 2;
    for (int i = pos + 1; i < 16; i++)
        buf[idx++] = tmp[i];
    buf[idx] = '\0';
    pe_rtld_puts(buf);
}

/* ============================================================
 * String/memory functions
 * ============================================================ */

static inline size_t pe_strlen(const char *s) {
    size_t len = 0;
    while (s[len]) len++;
    return len;
}

static inline int pe_strcmp(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *(unsigned char *)a - *(unsigned char *)b;
}

static inline void *pe_memcpy(void *dst, const void *src, size_t n) {
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (n--) *d++ = *s++;
    return dst;
}

static inline void *pe_memset(void *dst, int c, size_t n) {
    unsigned char *p = (unsigned char *)dst;
    while (n--) *p++ = (unsigned char)c;
    return dst;
}

/* Case-insensitive compare (for DLL name matching) */
static inline int pe_strcasecmp(const char *a, const char *b) {
    while (*a && *b) {
        unsigned char ca = *(const unsigned char *)a;
        unsigned char cb = *(const unsigned char *)b;
        if (ca >= 'A' && ca <= 'Z') ca += 'a' - 'A';
        if (cb >= 'A' && cb <= 'Z') cb += 'a' - 'A';
        if (ca != cb) return (int)ca - (int)cb;
        a++;
        b++;
    }
    return *(const unsigned char *)a - *(const unsigned char *)b;
}

/* ============================================================
 * SaltyOS Syscall ABI
 * ============================================================ */

#define SYS_SEND        0
#define SYS_RECV        1
#define SYS_CALL        2
#define SYS_REPLY_RECV  3
#define SYS_YIELD       8
#define SYS_INVOKE      9

#define MM_MPROTECT         0x86

#define VSPACE_MAP            0x50
#define VSPACE_UNMAP          0x51
#define VSPACE_PROTECT_RANGE  0x5F

#define VSPACE_FLAG_WRITABLE    (1 << 0)
#define VSPACE_FLAG_USER        (1 << 1)
#define VSPACE_FLAG_EXECUTABLE  (1 << 2)

#define PAGE_SIZE 4096

#define PROT_READ   0x1
#define PROT_WRITE  0x2
#define PROT_EXEC   0x4

typedef uint64_t cap_t;

#define PM_EXIT_LABEL     2

static inline struct rtld_syscall_result pe_syscall(
    uint64_t syscall_num, uint64_t a0, uint64_t a1,
    uint64_t a2, uint64_t a3, uint64_t a4, uint64_t a5
) {
    return rtld_syscall_arch(syscall_num, a0, a1, a2, a3, a4, a5);
}

static inline uint64_t pe_invoke(cap_t cap, uint64_t label,
                                  uint64_t a0, uint64_t a1,
                                  uint64_t a2, uint64_t a3) {
    uint64_t msginfo = (label << 12) | 4; /* 4 MRs, 0 extra caps */
    struct rtld_syscall_result r = pe_syscall(SYS_INVOKE, cap, msginfo,
                                               a0, a1, a2, a3);
    return r.error;
}

static inline uint64_t pe_vspace_map(cap_t vspace, cap_t frame,
                                      uint64_t vaddr, uint64_t flags) {
    return pe_invoke(vspace, VSPACE_MAP, frame, vaddr, flags, 0);
}

static inline uint64_t pe_vspace_unmap(cap_t vspace, uint64_t vaddr) {
    return pe_invoke(vspace, VSPACE_UNMAP, vaddr, 0, 0, 0);
}

static inline uint64_t pe_vspace_protect_range(cap_t vspace, uint64_t vaddr,
                                                uint64_t count, uint64_t flags) {
    return pe_invoke(vspace, VSPACE_PROTECT_RANGE, vaddr, count, flags, 0);
}

static inline void pe_yield(void) {
    pe_syscall(SYS_YIELD, 0, 0, 0, 0, 0, 0);
}

/* Defined in rtld_pe_main.c; reads g_pe_rtld.cap_procmgr_ep. */
void __attribute__((noreturn)) pe_exit(int code);

/* ============================================================
 * PE/COFF Types
 * ============================================================ */

#define PE_DOS_MAGIC       0x5A4D
#define PE_SIGNATURE       0x00004550
#define PE_OPT_MAGIC_64    0x020B
#define PE_MACHINE_AMD64   0x8664
#define PE_MACHINE_ARM64   0xAA64

#if defined(__x86_64__)
#define PE_MACHINE_NATIVE  PE_MACHINE_AMD64
#elif defined(__aarch64__)
#define PE_MACHINE_NATIVE  PE_MACHINE_ARM64
#endif

/* Section characteristics */
#define IMAGE_SCN_MEM_EXECUTE    0x20000000
#define IMAGE_SCN_MEM_READ       0x40000000
#define IMAGE_SCN_MEM_WRITE      0x80000000
#define IMAGE_SCN_MEM_DISCARDABLE 0x02000000

/* Data directory indices */
#define IMAGE_DIRECTORY_ENTRY_EXPORT   0
#define IMAGE_DIRECTORY_ENTRY_IMPORT   1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5

/* Base relocation types */
#define IMAGE_REL_BASED_ABSOLUTE 0
#define IMAGE_REL_BASED_DIR64    10

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    uint32_t e_lfanew;
} DosHeader;

typedef struct {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
} CoffHeader;

typedef struct {
    uint32_t virtual_address;
    uint32_t size;
} DataDirectory;

typedef struct {
    uint16_t magic;
    uint8_t  major_linker_version;
    uint8_t  minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_os_version;
    uint16_t minor_os_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
    /* DataDirectory entries follow inline */
} OptionalHeader64;

typedef struct {
    uint8_t  name[8];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
} SectionHeader;

typedef struct {
    uint32_t original_first_thunk;
    uint32_t time_date_stamp;
    uint32_t forwarder_chain;
    uint32_t name_rva;
    uint32_t first_thunk;
} ImportDescriptor;

typedef struct {
    uint32_t characteristics;
    uint32_t time_date_stamp;
    uint16_t major_version;
    uint16_t minor_version;
    uint32_t name;
    uint32_t base;
    uint32_t number_of_functions;
    uint32_t number_of_names;
    uint32_t address_of_functions;
    uint32_t address_of_names;
    uint32_t address_of_name_ordinals;
} ExportDirectory;

typedef struct {
    uint32_t virtual_address;
    uint32_t size_of_block;
} BaseRelocation;

/* ELF types needed for self-relocation */
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

typedef struct {
    int64_t  d_tag;
    uint64_t d_val;
} Elf64_Dyn;

typedef struct {
    uint64_t r_offset;
    uint64_t r_info;
    int64_t  r_addend;
} Elf64_Rela;

#define PT_DYNAMIC  2
#define DT_NULL     0
#define DT_RELA     7
#define DT_RELASZ   8

#if defined(__x86_64__)
#include "../elf/arch/x86_64/rtld_reloc_types.h"
#elif defined(__aarch64__)
#include "../elf/arch/aarch64/rtld_reloc_types.h"
#endif

#define ELF64_R_TYPE(info) ((uint32_t)((info) & 0xFFFFFFFF))

/* ============================================================
 * Auxiliary vector types
 * ============================================================ */

#define AT_NULL   0
#define AT_BASE   7
#define AT_ENTRY  9

/* SaltyOS PE-specific auxv types */
#define AT_SALTYOS_PE_BASE     0x2000
#define AT_SALTYOS_PE_SIZE     0x2001
#define AT_SALTYOS_WIN32SRV    0x2002
#define AT_TRONA_VSPACE        0x1001
#define AT_TRONA_SCRATCH       0x1002
#define AT_TRONA_IPC_BUFFER    0x100C
#define AT_TRONA_CSPACE_LAYOUT 0x1005
#define AT_TRONA_CSPACE_NTFN   0x100A
#define AT_TRONA_SC_CAP        0x100E

/* Legacy per-cap AT_TRONA_*_EP / _NTFN / _UNTYPED / _IOPORT tags have
 * been removed — every role-bearing cap is now delivered via the
 * role-based startup cap_table (AT_TRONA_CAP_TABLE). */
#define AT_SALTYOS_KERNEL32_BASE 0x2003
#define AT_SALTYOS_KERNEL32_SIZE 0x2004

/* `AT_TRONA_CAP_TABLE`, magic/version, all `ROLE_*`,
 * `LOCAL_ROLE_BASE/END`, and `CAP_TBL_{RIGHT,FLAG}_*` are generated
 * from `lib/trona/uapi/consts/kernel.rs`. meson adds the build dir
 * to this translation unit's include path via `rtld_generated_dir`. */
#include "cap_table_roles.h"

struct trona_cap_entry_v1 {
    uint32_t role_id;
    uint32_t slot;
    uint32_t rights;
    uint32_t flags;
};

struct trona_cap_table_v1 {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
    uint32_t reserved;
    /* Flexible array: `count` `trona_cap_entry_v1` records follow. */
};

struct trona_cspace_layout_v1 {
    uint64_t version;
    uint64_t flags;
    uint64_t cnode_bits;
    uint64_t frame_slot_base;
    uint64_t alloc_base;
    uint64_t alloc_limit;
    uint64_t recv_base;
    uint64_t recv_limit;
    uint64_t expand_base;
    uint64_t expand_limit;
};

struct kernel32_ipc_context {
    void *ipc_buffer;
    int32_t send_cap_count;
    int32_t _pad;
};

/* ============================================================
 * PE rtld state
 * ============================================================ */

struct pe_rtld_state {
    /* From auxv */
    uint64_t pe_base;        /* VA where PE image is mapped read-only */
    uint64_t pe_size;        /* Size of the PE image in memory */
    uint64_t win32srv_ep;    /* Win32 subsystem server endpoint cap */
    uint64_t kernel32_base;  /* Base VA of mapped kernel32.dll PE image */
    uint64_t kernel32_size;  /* Size of mapped kernel32.dll image */
    cap_t    vspace;         /* Self VSpace cap */
    uint64_t scratch_vaddr;  /* Scratch page VA */
    uint64_t ipc_buffer_vaddr; /* IPC buffer page VA */
    uint64_t rtld_base;      /* Load base of this rtld ELF */
    struct trona_cspace_layout_v1 *cspace_layout;
    uint64_t cspace_ntfn;
    uint64_t sc_cap;

    /* Cap slots PE rtld needs for its own operations (as opposed to
     * writing into kernel32.dll or libtrona exports). Populated from
     * the `ROLE_*` entries of the startup cap_table.
     *
     * - `cap_procmgr_ep`: used by `pe_exit` to send PM_EXIT and also
     *   mirrored into kernel32.dll's `__trona_cap_procmgr_ep` export
     *   during `initialize_kernel32_runtime`.
     * - `cap_mmsrv_ep`:   used by PE rtld's own MAP_MO calls to lay
     *   out the PE image / kernel32.dll mapping.
     * - `cap_vfs_ep`:     mirrored into kernel32.dll's
     *   `__trona_cap_vfs_ep` export for its file I/O shim.
     *
     * All other role-bearing caps (namesrv, signal, rsrcsrv, console,
     * readiness, initrd_untyped, fb_untyped, pci/com1 ioports,
     * service_ep) do not need a g_pe_rtld field — they are written
     * straight into their libtrona / kernel32 weak symbols by the
     * walker without a per-field mirror in rtld state. */
    uint64_t cap_procmgr_ep;
    uint64_t cap_mmsrv_ep;
    uint64_t cap_vfs_ep;

    /* Pointer to the child's startup capability table, from
     * AT_TRONA_CAP_TABLE. NULL until stage-1 spawners emit it. Stage 2
     * readers prefer this over the individual cap_* fields above. */
    struct trona_cap_table_v1 *cap_table;
};

/* Convert PE section characteristics to VSpace flags (W^X enforced) */
static inline uint64_t pe_section_to_vspace_flags(uint32_t chars) {
    uint64_t flags = VSPACE_FLAG_USER;
    if (chars & IMAGE_SCN_MEM_WRITE)
        flags |= VSPACE_FLAG_WRITABLE;
    if (chars & IMAGE_SCN_MEM_EXECUTE)
        flags |= VSPACE_FLAG_EXECUTABLE;
    return flags;
}

static inline uint64_t pe_page_align_down(uint64_t v) {
    return v & ~(uint64_t)(PAGE_SIZE - 1);
}

static inline uint64_t pe_page_align_up(uint64_t v) {
    return (v + PAGE_SIZE - 1) & ~(uint64_t)(PAGE_SIZE - 1);
}

#endif /* RTLD_PE_INTERNAL_H */
