/* SaltyOS Runtime Dynamic Linker - Entry Point
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Entry point for ld-trona.so. Parses the initial stack (argc/argv/envp/auxv),
 * self-relocates, loads shared libraries from the CPIO initrd, applies
 * relocations, sets up PLT lazy binding, and jumps to the executable entry.
 */

#include "rtld_internal.h"

struct rtld_state g_rtld;

struct link_map *find_loaded_object(struct rtld_state *st, const char *name) {
    char canonical_name[RTLD_MAX_OBJECT_NAME];

    if (!rtld_make_canonical_object_name(name, canonical_name, sizeof(canonical_name)))
        return NULL;

    struct link_map *cur = st->head;
    while (cur) {
        if (cur->name && rtld_strcmp(cur->name, canonical_name) == 0)
            return cur;
        cur = cur->next;
    }
    return NULL;
}

static uint64_t resolve_symbol_addr_in_object(
    struct rtld_state *st,
    const char *object_name,
    const char *symbol_name
) {
    struct link_map *map = find_loaded_object(st, object_name);
    if (!map)
        return resolve_symbol_addr(st, symbol_name);

    uint64_t addr = gnu_hash_lookup(map, symbol_name);
    if (addr)
        return addr;
    return linear_lookup(map, symbol_name);
}

static void install_cap_table_via_libtrona(struct rtld_state *st, const uint64_t *auxv) {
    typedef void (*trona_runtime_set_auxv_fn)(const uint64_t *auxv);
    const char *libtrona_name = RTLD_INITRD_LIB_PREFIX "libtrona.so";

    uint64_t addr = resolve_symbol_addr_in_object(st, libtrona_name, "trona_runtime_set_auxv");
    if (addr != 0) {
        ((trona_runtime_set_auxv_fn)addr)(auxv);
    }
}

/* Exported pointer to g_rtld for libc dladdr()/dl_iterate_phdr().
 * libc declares this as `extern` and uses it to walk the link_map chain. */
__attribute__((visibility("default")))
struct rtld_state *__rtld_global = &g_rtld;

/* Exported so applications can continue allocating frame slots after rtld */
uint64_t __trona_next_frame_slot = 0;

uint64_t __trona_cspace_ntfn = 0;
uint64_t __trona_sc_cap = 0;

/* rtld keeps no local `__trona_cap_*` mirrors — the startup cap_table
 * walker below writes directly into libtrona.so's weak symbols. */

/* Exported ELF TLS info so libtrona can set up the TLS data area */
uint64_t __trona_tls_template = 0;  /* Runtime address of .tdata template */
uint64_t __trona_tls_filesz = 0;    /* Size of .tdata (initialized data) */
uint64_t __trona_tls_memsz = 0;     /* Total static TLS block size */
uint64_t __trona_tls_align = 1;     /* Maximum static TLS alignment */
uint64_t __trona_tls_module_count = 0;
struct rtld_tls_module __trona_tls_modules[RTLD_MAX_OBJECTS];

void __attribute__((naked, noreturn)) _start(void) {
#if defined(__x86_64__)
    __asm__ volatile(
        "xor %%ebp, %%ebp\n"
        "mov %%rsp, %%rdi\n"
        "andq $-16, %%rsp\n"
        "call rtld_main\n"
        : : : "memory"
    );
#elif defined(__aarch64__)
    __asm__ volatile(
        "mov x0, sp\n"
        "bl rtld_main\n"
        : : : "memory"
    );
#endif
}

/* Self-relocate the rtld's own R_RELATIVE entries.
 * Called before any global data can be accessed reliably.
 */
static void self_relocate(uint64_t base, Elf64_Dyn *dyn) {
    Elf64_Rela *rela = NULL;
    uint64_t rela_size = 0;
    uint64_t rela_ent_size = sizeof(Elf64_Rela);

    for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
        if (dyn[i].d_tag == DT_RELA)
            rela = (Elf64_Rela *)(base + dyn[i].d_val);
        else if (dyn[i].d_tag == DT_RELASZ)
            rela_size = dyn[i].d_val;
        else if (dyn[i].d_tag == DT_RELAENT && dyn[i].d_val >= sizeof(Elf64_Rela))
            rela_ent_size = dyn[i].d_val;
    }

    if (!rela || rela_size == 0 || rela_ent_size < sizeof(Elf64_Rela))
        return;

    uint64_t count = rela_size / rela_ent_size;
    for (uint64_t i = 0; i < count; i++) {
        Elf64_Rela entry;
        rtld_memcpy(&entry, (const uint8_t *)rela + rela_ent_size * i, sizeof(entry));
        uint32_t type = ELF64_R_TYPE(entry.r_info);
        if (type == R_RELATIVE) {
            uint64_t *target = (uint64_t *)(base + entry.r_offset);
            *target = base + (uint64_t)entry.r_addend;
        }
    }
}

/* Find PT_DYNAMIC in program headers at a given base */
static Elf64_Dyn *find_dynamic(uint64_t base) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(base + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC)
            return (Elf64_Dyn *)(base + phdrs[i].p_vaddr);
    }
    return NULL;
}

static void finalize_static_tls_layout(struct rtld_state *st) {
#if defined(__aarch64__)
    uint64_t total = 16; /* AArch64 ABI TP header (two machine words). */
    uint64_t max_align = 16;
#else
    uint64_t total = 0;
    uint64_t max_align = 1;
#endif
    uint64_t module_id = 1;

    for (struct link_map *map = st->head; map; map = map->next) {
        map->tls_module_id = 0;
        map->tls_tpoff = 0;
        if (map->tls_memsz == 0)
            continue;

        uint64_t align = map->tls_align ? map->tls_align : 1;
#if defined(__aarch64__)
        if (align > 1)
            total = (total + align - 1) & ~(align - 1);
        if (align > max_align)
            max_align = align;

        map->tls_module_id = module_id++;
        map->tls_tpoff = (int64_t)total;
        total += map->tls_memsz;
#else
        uint64_t next_total = total + map->tls_memsz;
        if (align > 1)
            next_total = (next_total + align - 1) & ~(align - 1);
        total = next_total;
        if (align > max_align)
            max_align = align;

        map->tls_module_id = module_id++;
        map->tls_tpoff = -(int64_t)total;
#endif
    }

#if defined(__aarch64__)
    st->tls_memsz = total - 16;
#else
    st->tls_memsz = total;
#endif
    st->tls_align = max_align;
    st->tls_module_count = module_id - 1;
}

static void export_static_tls_layout(struct rtld_state *st) {
    const char *libtrona_name = RTLD_INITRD_LIB_PREFIX "libtrona.so";
    const char *libc_name = RTLD_INITRD_LIB_PREFIX "libc.so";

    __trona_tls_template = st->exe_tls_vaddr;
    __trona_tls_filesz = st->exe_tls_filesz;
    __trona_tls_memsz = st->tls_memsz;
    __trona_tls_align = st->tls_align;
    __trona_tls_module_count = st->tls_module_count;
    rtld_memset(__trona_tls_modules, 0, sizeof(__trona_tls_modules));

    uint64_t tls_index = 0;
    for (struct link_map *map = st->head; map && tls_index < RTLD_MAX_OBJECTS; map = map->next) {
        if (map->tls_module_id == 0)
            continue;

        __trona_tls_modules[tls_index].module_id = map->tls_module_id;
        __trona_tls_modules[tls_index].template_addr = map->tls_template;
        __trona_tls_modules[tls_index].filesz = map->tls_filesz;
        __trona_tls_modules[tls_index].memsz = map->tls_memsz;
        __trona_tls_modules[tls_index].tpoff = map->tls_tpoff;
        tls_index++;
    }

    uint64_t tmpl_addr = resolve_symbol_addr_in_object(st, libtrona_name, "__trona_tls_template");
    if (tmpl_addr != 0)
        *(volatile uint64_t *)tmpl_addr = __trona_tls_template;
    uint64_t fsz_addr = resolve_symbol_addr_in_object(st, libtrona_name, "__trona_tls_filesz");
    if (fsz_addr != 0)
        *(volatile uint64_t *)fsz_addr = __trona_tls_filesz;
    uint64_t msz_addr = resolve_symbol_addr_in_object(st, libtrona_name, "__trona_tls_memsz");
    if (msz_addr != 0)
        *(volatile uint64_t *)msz_addr = __trona_tls_memsz;
    uint64_t align_addr = resolve_symbol_addr_in_object(st, libtrona_name, "__trona_tls_align");
    if (align_addr != 0)
        *(volatile uint64_t *)align_addr = __trona_tls_align;
    uint64_t count_addr = resolve_symbol_addr_in_object(st, libtrona_name, "__trona_tls_module_count");
    if (count_addr != 0)
        *(volatile uint64_t *)count_addr = __trona_tls_module_count;
    uint64_t mods_addr = resolve_symbol_addr_in_object(st, libtrona_name, "__trona_tls_modules");
    if (mods_addr != 0)
        rtld_memcpy((void *)(uintptr_t)mods_addr, __trona_tls_modules,
                    sizeof(__trona_tls_modules));
}

void __attribute__((noreturn)) rtld_main(uint64_t *sp) {
    /* 1. Parse initial stack: argc, argv[], NULL, envp[], NULL, auxv[] */
    uint64_t argc = sp[0];
    uint64_t *argv = &sp[1];

    /* Skip past argv (argc entries + NULL terminator) */
    uint64_t *p = argv + argc + 1;

    /* Skip past envp (entries until NULL) */
    while (*p != 0) p++;
    p++;  /* skip the NULL terminator */
    const uint64_t *auxv = p;

    /* Now p points to auxv array (key/value pairs, terminated by AT_NULL) */
    uint64_t at_phdr = 0;
    uint64_t at_phent = 0;
    uint64_t at_phnum = 0;
    uint64_t at_entry = 0;
    uint64_t at_base = 0;

    for (; p[0] != AT_NULL; p += 2) {
        switch (p[0]) {
        case AT_PHDR:            at_phdr = p[1]; break;
        case AT_PHENT:           at_phent = p[1]; break;
        case AT_PHNUM:           at_phnum = p[1]; break;
        case AT_ENTRY:           at_entry = p[1]; break;
        case AT_BASE:            at_base = p[1]; break;
        case AT_TRONA_UNTYPED:   g_rtld.untyped = p[1]; break;
        case AT_TRONA_VSPACE:    g_rtld.vspace = p[1]; break;
        case AT_TRONA_SCRATCH:   g_rtld.scratch_vaddr = p[1]; break;
        case AT_TRONA_IPC_BUFFER:g_rtld.ipc_buffer_vaddr = p[1]; break;
        case AT_TRONA_INITRD:    g_rtld.initrd_base = p[1]; break;
        case AT_TRONA_INITRD_SZ: g_rtld.initrd_size = p[1]; break;
        case AT_TRONA_CSPACE_LAYOUT:
            g_rtld.cspace_layout = (struct trona_cspace_layout_v1 *)(uintptr_t)p[1];
            if (g_rtld.cspace_layout && g_rtld.cspace_layout->version == 1)
                g_rtld.next_frame_slot = g_rtld.cspace_layout->frame_slot_base;
            break;
        case AT_TRONA_SHARED_LIB_BASE: g_rtld.shared_lib_base = p[1]; break;
        case AT_TRONA_CSPACE_NTFN: g_rtld.cspace_ntfn = p[1]; break;
        case AT_TRONA_SC_CAP:  g_rtld.sc_cap = p[1]; break;
        case AT_TRONA_CAP_TABLE:
            g_rtld.cap_table = (struct trona_cap_table_v1 *)(uintptr_t)p[1];
            break;
        }
    }

    if (!g_rtld.cspace_layout || g_rtld.cspace_layout->version != 1) {
        rtld_puts("[RTLD] FATAL: missing AT_TRONA_CSPACE_LAYOUT\n");
        rtld_exit(127);
    }

    /* 2. Self-relocate.
     * at_base is the load address of the rtld itself.
     * Find our own PT_DYNAMIC and apply R_RELATIVE.
     */
    g_rtld.rtld_base = at_base;
    if (at_base != 0) {
        Elf64_Dyn *own_dyn = find_dynamic(at_base);
        if (own_dyn)
            self_relocate(at_base, own_dyn);
    }

    /* Now global data is safe to use */
    rtld_puts("[RTLD] SaltyOS dynamic linker starting\n");

    g_rtld.exe_entry = at_entry;
    g_rtld.exe_phdr = at_phdr;
    g_rtld.exe_phent = at_phent;
    g_rtld.exe_phnum = at_phnum;

    /* 3. Parse executable's .dynamic section.
     * AT_PHDR points to the exe's program headers (already mapped).
     * Walk them to find PT_DYNAMIC.
     */
    Elf64_Phdr *exe_phdrs = (Elf64_Phdr *)at_phdr;
    Elf64_Dyn *exe_dyn = NULL;
    uint64_t exe_base = 0;

    /* Determine exe min vaddr and find PT_DYNAMIC/PT_PHDR.
     * Note: the in-memory phdrs contain original file vaddrs (not relocated),
     * so we need to compute the load delta from PT_PHDR.
     */
    uint64_t exe_min_vaddr = UINT64_MAX;
    uint64_t exe_phdr_vaddr = 0;
    int have_phdr = 0;
    for (uint64_t i = 0; i < at_phnum; i++) {
        Elf64_Phdr *ph = (Elf64_Phdr *)((uint8_t *)exe_phdrs + i * at_phent);
        if (ph->p_type == PT_LOAD && ph->p_vaddr < exe_min_vaddr)
            exe_min_vaddr = ph->p_vaddr;
        if (ph->p_type == PT_DYNAMIC)
            exe_dyn = (Elf64_Dyn *)ph->p_vaddr;
        if (ph->p_type == PT_PHDR) {
            exe_phdr_vaddr = ph->p_vaddr;
            have_phdr = 1;
        }
        if (ph->p_type == PT_TLS) {
            g_rtld.exe_tls_filesz = ph->p_filesz;
            g_rtld.exe_tls_memsz  = ph->p_memsz;
            g_rtld.exe_tls_align  = ph->p_align ? ph->p_align : 1;
            /* vaddr needs load delta applied — done below */
            g_rtld.exe_tls_vaddr  = ph->p_vaddr;
        }
    }

    /* Compute the executable load bias: AT_PHDR is the actual runtime address
     * of the phdrs, while exe_phdr_vaddr is the ELF virtual address from the
     * PT_PHDR entry. Dynamic tags, relocation offsets, and symbol values are
     * all expressed in that ELF virtual-address space, so the runtime linker
     * must add the load bias rather than the mapped image start address.
     */
    uint64_t exe_load_bias = 0;
    if (have_phdr) {
        exe_load_bias = at_phdr - exe_phdr_vaddr;
    } else if (at_phdr >= sizeof(Elf64_Ehdr)) {
        /* Fallback: if no PT_PHDR, try reading the ELF header which is
         * expected immediately before the phdrs (e_phoff == sizeof(Elf64_Ehdr)
         * for all standard ELF64 binaries). Verify via magic bytes.
         */
        Elf64_Ehdr *exe_ehdr = (Elf64_Ehdr *)(at_phdr - sizeof(Elf64_Ehdr));
        if (exe_ehdr->e_ident[0] == 0x7F && exe_ehdr->e_ident[1] == 'E' &&
            exe_ehdr->e_ident[2] == 'L'  && exe_ehdr->e_ident[3] == 'F') {
            exe_load_bias = at_phdr - exe_ehdr->e_phoff;
            rtld_dbg_puts("[RTLD] PT_PHDR missing, computed delta from ELF header\n");
        } else {
            rtld_puts("[RTLD] WARN: no PT_PHDR and ELF header not found\n");
        }
    }

    /* Apply the load bias to PT_DYNAMIC (which was captured as an ELF vaddr). */
    if (exe_dyn)
        exe_dyn = (Elf64_Dyn *)((uint64_t)exe_dyn + exe_load_bias);
    exe_base = exe_load_bias;
    g_rtld.exe_phdr = at_phdr;

    /* Apply delta to TLS template address */
    if (g_rtld.exe_tls_memsz > 0)
        g_rtld.exe_tls_vaddr += exe_load_bias;

    /* Create link_map for executable */
    struct link_map *exe_map = &g_rtld.objects[0];
    exe_map->name = "executable";
    g_rtld.nobjects = 1;
    g_rtld.head = exe_map;

    if (exe_dyn) {
        parse_dynamic(exe_map, exe_dyn, exe_base);
        exe_map->dyn_section = exe_dyn;
    }
    exe_map->tls_template = g_rtld.exe_tls_vaddr;
    exe_map->tls_filesz = g_rtld.exe_tls_filesz;
    exe_map->tls_memsz = g_rtld.exe_tls_memsz;
    exe_map->tls_align = g_rtld.exe_tls_align ? g_rtld.exe_tls_align : 1;

    /* 4. Load shared libraries: walk exe's DT_NEEDED entries */
    uint64_t lib_load_addr;
    if (g_rtld.shared_lib_base != 0) {
        /* Pre-mapped path: procmgr computed the shared lib base address */
        lib_load_addr = g_rtld.shared_lib_base;
    } else {
        /* Self-loading fallback: compute lib base from RTLD's own load extent.
         * Walk RTLD's phdrs to find max_end, then start libs after a 1-page gap.
         */
        Elf64_Ehdr *rtld_ehdr = (Elf64_Ehdr *)g_rtld.rtld_base;
        Elf64_Phdr *rtld_phdrs = (Elf64_Phdr *)(g_rtld.rtld_base + rtld_ehdr->e_phoff);
        uint64_t rtld_min_vaddr = UINT64_MAX;
        for (int i = 0; i < rtld_ehdr->e_phnum; i++) {
            if (rtld_phdrs[i].p_type == PT_LOAD && rtld_phdrs[i].p_vaddr < rtld_min_vaddr)
                rtld_min_vaddr = rtld_phdrs[i].p_vaddr;
        }
        uint64_t rtld_delta = g_rtld.rtld_base - rtld_min_vaddr;
        uint64_t rtld_max_end = 0;
        for (int i = 0; i < rtld_ehdr->e_phnum; i++) {
            if (rtld_phdrs[i].p_type == PT_LOAD) {
                uint64_t mapped_end = rtld_page_align_up(
                    rtld_phdrs[i].p_vaddr + rtld_delta + rtld_phdrs[i].p_memsz
                );
                if (mapped_end > rtld_max_end) rtld_max_end = mapped_end;
            }
        }
        if (rtld_max_end == 0)
            rtld_max_end = g_rtld.rtld_base + 0x80000ULL; /* conservative fallback */
        lib_load_addr = rtld_max_end + PAGE_SIZE; /* 1-page gap */
    }

    if (exe_dyn) {
        for (int i = 0; exe_dyn[i].d_tag != DT_NULL; i++) {
            if (exe_dyn[i].d_tag == DT_NEEDED) {
                const char *lib_name = exe_map->strtab + exe_dyn[i].d_val;
                int err = load_shared_library(&g_rtld, lib_name, lib_load_addr);
                if (err != 0) {
                    struct rtld_linebuf lb;
                    rtld_lb_init(&lb);
                    rtld_lb_str(&lb, "[RTLD] FATAL: failed to load ");
                    rtld_lb_str(&lb, lib_name);
                    rtld_lb_str(&lb, " err=");
                    rtld_lb_hex(&lb, (uint64_t)err);
                    rtld_lb_str(&lb, "\n");
                    rtld_lb_flush(&lb);
                    rtld_exit(127);
                }

                /* Advance load address by actual library footprint + 1-page gap */
                struct link_map *loaded_map = &g_rtld.objects[g_rtld.nobjects - 1];
                {
                    struct rtld_linebuf dlb;
                    rtld_dbg_lb_init(&dlb);
                    rtld_dbg_lb_str(&dlb, "[RTLD] loaded ");
                    rtld_dbg_lb_str(&dlb, lib_name);
                    rtld_dbg_lb_str(&dlb, " req=");
                    rtld_dbg_lb_hex(&dlb, lib_load_addr);
                    rtld_dbg_lb_str(&dlb, " base=");
                    rtld_dbg_lb_hex(&dlb, loaded_map->base);
                    rtld_dbg_lb_str(&dlb, " span=[");
                    rtld_dbg_lb_hex(&dlb, loaded_map->base);
                    rtld_dbg_lb_str(&dlb, ",");
                    rtld_dbg_lb_hex(&dlb, loaded_map->base + loaded_map->load_size);
                    rtld_dbg_lb_str(&dlb, ")\n");
                    rtld_dbg_lb_flush(&dlb);
                }
                uint64_t advance = loaded_map->load_size;
                if (advance == 0) advance = 0x80000ULL; /* fallback */
                lib_load_addr += advance + PAGE_SIZE;
            }
        }
    }

    /* 4b. BFS: process transitive DT_NEEDED from loaded libraries.
     * Walk objects[1..] (libraries); newly loaded objects are appended
     * to the array and will be visited in subsequent iterations.
     */
    {
        int processed = 1;
        while (processed < g_rtld.nobjects) {
            struct link_map *map = &g_rtld.objects[processed];
            if (map->dyn_section && map->strtab) {
                for (int di = 0; map->dyn_section[di].d_tag != DT_NULL; di++) {
                    if (map->dyn_section[di].d_tag != DT_NEEDED)
                        continue;
                    const char *dep_name = map->strtab + map->dyn_section[di].d_val;
                    if (find_loaded_object(&g_rtld, dep_name))
                        continue;
                    int err = load_shared_library(&g_rtld, dep_name, lib_load_addr);
                    if (err != 0) {
                        struct rtld_linebuf lb;
                        rtld_lb_init(&lb);
                        rtld_lb_str(&lb, "[RTLD] FATAL: transitive dep ");
                        rtld_lb_str(&lb, dep_name);
                        rtld_lb_str(&lb, " err=");
                        rtld_lb_hex(&lb, (uint64_t)err);
                        rtld_lb_str(&lb, "\n");
                        rtld_lb_flush(&lb);
                        rtld_exit(127);
                    }
                    struct link_map *dep_map = &g_rtld.objects[g_rtld.nobjects - 1];
                    uint64_t advance = dep_map->load_size;
                    if (advance == 0) advance = 0x80000ULL;
                    lib_load_addr += advance + PAGE_SIZE;
                }
            }
            processed++;
        }
    }

    finalize_static_tls_layout(&g_rtld);

    /* 5. Process relocations for all loaded objects (libs first, then exe) */
    for (int i = g_rtld.nobjects - 1; i >= 0; i--) {
        struct link_map *map = &g_rtld.objects[i];
        process_relocations(&g_rtld, map);
    }

    /* 6. Setup PLT lazy binding for executable.
     * GOT[0] = address of .dynamic (already set by linker)
     * GOT[1] = pointer to this object's link_map
     * GOT[2] = address of _dl_runtime_resolve
     */
    if (exe_map->pltgot) {
        exe_map->pltgot[1] = (uint64_t)exe_map;
        exe_map->pltgot[2] = (uint64_t)_dl_runtime_resolve;
    }

    /* Also setup lazy binding for loaded libraries */
    for (int i = 1; i < g_rtld.nobjects; i++) {
        struct link_map *map = &g_rtld.objects[i];
        if (map->pltgot) {
            map->pltgot[1] = (uint64_t)map;
            map->pltgot[2] = (uint64_t)_dl_runtime_resolve;
        }
    }

    /* 7. Export frame slot so user code can allocate after rtld.
     * __trona_next_frame_slot references in user code resolve to libtrona,
     * so update that symbol explicitly if present. */
    const char *libtrona_name = RTLD_INITRD_LIB_PREFIX "libtrona.so";
    const char *libc_name = RTLD_INITRD_LIB_PREFIX "libc.so";

    __trona_next_frame_slot = g_rtld.next_frame_slot;
    {
        uint64_t slot_addr = resolve_symbol_addr_in_object(&g_rtld, libtrona_name, "__trona_next_frame_slot");
        if (slot_addr != 0)
            *(volatile uint64_t *)slot_addr = g_rtld.next_frame_slot;
    }

    /* 7b. Advance the shared CSpace layout descriptor past the frame slots
     * consumed by RTLD itself so later runtime code sees the post-RTLD truth. */
    if (g_rtld.next_frame_slot > g_rtld.cspace_layout->alloc_base) {
        if (g_rtld.next_frame_slot < g_rtld.cspace_layout->alloc_limit)
            g_rtld.cspace_layout->alloc_base = g_rtld.next_frame_slot;
        else
            g_rtld.cspace_layout->alloc_base = g_rtld.cspace_layout->alloc_limit;
    }

    /* 7c. Export CSpace expansion notification cap for slot_alloc. */
    __trona_cspace_ntfn = g_rtld.cspace_ntfn;
    {
        uint64_t ntfn_addr = resolve_symbol_addr_in_object(&g_rtld, libtrona_name, "__trona_cspace_ntfn");
        if (ntfn_addr != 0)
            *(volatile uint64_t *)ntfn_addr = g_rtld.cspace_ntfn;
    }

    /* 7c2. Export SchedContext cap slot for thread pool. */
    __trona_sc_cap = g_rtld.sc_cap;
    {
        uint64_t sc_addr = resolve_symbol_addr_in_object(&g_rtld, libtrona_name, "__trona_sc_cap");
        if (sc_addr != 0)
            *(volatile uint64_t *)sc_addr = g_rtld.sc_cap;
    }

    /* 7c3. Delegate startup cap-table installation to libtrona's shared
     * substrate helper. That helper saves the auxv pointer and performs
     * the single authoritative role->`__trona_cap_*` install sweep,
     * including any generated `svc_caps` hook.
     *
     * rtld still caches the two slots it uses directly:
     *   ROLE_PROCMGR_CONTROL  -> g_rtld.cap_procmgr_ep
     *   ROLE_INITRD_UNTYPED   -> g_rtld.cap_initrd_untyped
     */
    install_cap_table_via_libtrona(&g_rtld, auxv);
    if (g_rtld.cap_table != NULL
        && g_rtld.cap_table->magic == TRONA_CAP_TABLE_MAGIC
        && g_rtld.cap_table->version == TRONA_CAP_TABLE_VERSION) {
        const struct trona_cap_entry_v1 *entries =
            (const struct trona_cap_entry_v1 *)(g_rtld.cap_table + 1);
        for (uint32_t i = 0; i < g_rtld.cap_table->count; i++) {
            const struct trona_cap_entry_v1 *e = &entries[i];
            switch (e->role_id) {
            case ROLE_PROCMGR_CONTROL: g_rtld.cap_procmgr_ep = e->slot;    break;
            case ROLE_INITRD_UNTYPED:  g_rtld.cap_initrd_untyped = e->slot; break;
            default: break;
            }
        }
    }

    /* 7c3. Export rtld state pointer into libc's local __rtld_global slot.
     * libc's dlopen/dladdr helpers use this to walk the startup link-map chain,
     * but the interpreter symbol is not wired into DSOs automatically here. */
    {
        uint64_t rtld_global_addr = resolve_symbol_addr_in_object(&g_rtld, libc_name, "__rtld_global");
        if (rtld_global_addr != 0)
            *(volatile uint64_t *)rtld_global_addr = (uint64_t)&g_rtld;
    }

    /* 7d. Export combined static TLS layout for libtrona. */
    export_static_tls_layout(&g_rtld);

    /* 7e. Call shared library constructors (DT_INIT + DT_INIT_ARRAY).
     * Skip index 0 (the executable) -- its .init_array is called by the CRT.
     * Forward order matches dependency order for flat DT_NEEDED loading.
     */
    for (int i = 1; i < g_rtld.nobjects; i++) {
        struct link_map *map = &g_rtld.objects[i];
        if (map->init_fn) {
            struct rtld_linebuf lb;
            rtld_dbg_lb_init(&lb);
            rtld_dbg_lb_str(&lb, "[RTLD] calling DT_INIT for ");
            rtld_dbg_lb_str(&lb, map->name ? map->name : "(unnamed)");
            rtld_dbg_lb_str(&lb, "\n");
            rtld_dbg_lb_flush(&lb);
            map->init_fn();
        }
        for (uint64_t j = 0; j < map->init_array_count; j++) {
            if (map->init_array[j]) {
                struct rtld_linebuf lb;
                rtld_dbg_lb_init(&lb);
                rtld_dbg_lb_str(&lb, "[RTLD] calling DT_INIT_ARRAY for ");
                rtld_dbg_lb_str(&lb, map->name ? map->name : "(unnamed)");
                rtld_dbg_lb_str(&lb, " idx=");
                rtld_dbg_lb_hex(&lb, j);
                rtld_dbg_lb_str(&lb, "\n");
                rtld_dbg_lb_flush(&lb);
                map->init_array[j]();
            }
        }
    }

    /* 8. Jump to executable entry point.
     * Process-entry ABI in SaltyOS:
     *   - [RSP+0] = argc
     *   - RSP % 16 == 8 at entry
     * Startup code for both C and Rust relies on this contract.
     */
    rtld_jump_entry((uint64_t)(uintptr_t)sp, (void *)(uintptr_t)g_rtld.exe_entry);
}
