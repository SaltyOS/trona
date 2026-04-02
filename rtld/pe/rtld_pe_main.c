/* SaltyOS PE Runtime Loader (ld-trona-pe.so) - Main Entry
 * SPDX-License-Identifier: GPL-2.0-only
 *
 * Entry point for the PE runtime loader. This is an ELF binary (static PIE)
 * that loads and executes PE/COFF binaries on SaltyOS.
 *
 * Flow:
 *  1. Parse initial stack (argc/argv/envp/auxv)
 *  2. Self-relocate own R_RELATIVE entries
 *  3. Validate the PE image (already mapped read-only by procmgr)
 *  4. Apply base relocations (IMAGE_REL_BASED_DIR64)
 *  5. Resolve imports from the mapped kernel32.dll export directory
 *  6. Jump to PE entry point
 *
 * The PE image is pre-mapped by procmgr at the address given in
 * AT_SALTYOS_PE_BASE. Sections are mapped with appropriate permissions
 * (W^X enforced). This loader only needs to:
 *  - Apply base relocations if image_base != actual load address
 *  - Resolve import table entries via the mapped kernel32.dll export table
 *  - Transfer control to AddressOfEntryPoint
 */

#include "rtld_pe_internal.h"

/* ============================================================
 * Global state
 * ============================================================ */

static struct pe_rtld_state g_pe_rtld;

/* ============================================================
 * _start — naked entry, calls pe_rtld_main
 * ============================================================ */

void __attribute__((naked, noreturn)) _start(void) {
#if defined(__x86_64__)
    __asm__ volatile(
        "xor %%ebp, %%ebp\n"
        "mov %%rsp, %%rdi\n"
        "andq $-16, %%rsp\n"
        "call pe_rtld_main\n"
        : : : "memory"
    );
#elif defined(__aarch64__)
    __asm__ volatile(
        "mov x0, sp\n"
        "bl pe_rtld_main\n"
        : : : "memory"
    );
#endif
}

/* ============================================================
 * Self-relocation (same approach as ELF rtld)
 * ============================================================ */

static void self_relocate(uint64_t base, Elf64_Dyn *dyn) {
    Elf64_Rela *rela = NULL;
    uint64_t rela_size = 0;

    for (int i = 0; dyn[i].d_tag != DT_NULL; i++) {
        if (dyn[i].d_tag == DT_RELA)
            rela = (Elf64_Rela *)(base + dyn[i].d_val);
        else if (dyn[i].d_tag == DT_RELASZ)
            rela_size = dyn[i].d_val;
    }

    if (!rela || rela_size == 0)
        return;

    uint64_t count = rela_size / sizeof(Elf64_Rela);
    for (uint64_t i = 0; i < count; i++) {
        uint32_t type = ELF64_R_TYPE(rela[i].r_info);
        if (type == R_RELATIVE) {
            uint64_t *target = (uint64_t *)(base + rela[i].r_offset);
            *target = base + (uint64_t)rela[i].r_addend;
        }
    }
}

static Elf64_Dyn *find_dynamic(uint64_t base) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)base;
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(base + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdrs[i].p_type == PT_DYNAMIC)
            return (Elf64_Dyn *)(base + phdrs[i].p_vaddr);
    }
    return NULL;
}

static uint64_t pe_mm_mprotect(uint64_t addr, uint64_t length, uint64_t flags) {
    cap_t mm_ep = g_pe_rtld.mm_ep != 0 ? g_pe_rtld.mm_ep : CAP_MMSRV_EP;
    uint64_t prot = PROT_READ;

    if (mm_ep == 0 || g_pe_rtld.ipc_buffer_vaddr == 0)
        return (uint64_t)-1;

    if (flags & VSPACE_FLAG_WRITABLE)
        prot |= PROT_WRITE;
    if (flags & VSPACE_FLAG_EXECUTABLE)
        prot |= PROT_EXEC;

    struct rtld_syscall_result r = pe_syscall(
        SYS_CALL,
        mm_ep,
        ((uint64_t)MM_MPROTECT << 12) | 3,
        addr,
        length,
        prot,
        0
    );
    if (r.error != 0)
        return r.error;

    return ((uint64_t *)g_pe_rtld.ipc_buffer_vaddr)[0];
}

/* ============================================================
 * PE validation
 * ============================================================ */

static int pe_validate(const uint8_t *base, uint64_t size,
                       const DosHeader **out_dos,
                       const CoffHeader **out_coff,
                       const OptionalHeader64 **out_opt,
                       const SectionHeader **out_sections,
                       uint16_t *out_num_sections) {
    if (size < sizeof(DosHeader))
        return -1;

    const DosHeader *dos = (const DosHeader *)base;
    if (dos->e_magic != PE_DOS_MAGIC)
        return -1;

    uint32_t pe_off = dos->e_lfanew;
    if (pe_off + 4 + sizeof(CoffHeader) + sizeof(OptionalHeader64) > size)
        return -2;

    const uint32_t *sig = (const uint32_t *)(base + pe_off);
    if (*sig != PE_SIGNATURE)
        return -2;

    const CoffHeader *coff = (const CoffHeader *)(base + pe_off + 4);
#if defined(__x86_64__)
    if (coff->machine != PE_MACHINE_AMD64)
        return -3;
#elif defined(__aarch64__)
    if (coff->machine != PE_MACHINE_ARM64)
        return -3;
#endif

    const OptionalHeader64 *opt =
        (const OptionalHeader64 *)(base + pe_off + 4 + sizeof(CoffHeader));
    if (opt->magic != PE_OPT_MAGIC_64)
        return -4;

    const SectionHeader *sections =
        (const SectionHeader *)((const uint8_t *)opt + coff->size_of_optional_header);

    *out_dos = dos;
    *out_coff = coff;
    *out_opt = opt;
    *out_sections = sections;
    *out_num_sections = coff->number_of_sections;
    return 0;
}

/* ============================================================
 * RVA to file offset conversion
 * ============================================================ */

static uint64_t rva_to_offset(const SectionHeader *sections, uint16_t num_sections,
                               uint32_t rva) {
    for (uint16_t i = 0; i < num_sections; i++) {
        uint32_t sec_rva = sections[i].virtual_address;
        uint32_t sec_size = sections[i].virtual_size;
        if (rva >= sec_rva && rva < sec_rva + sec_size) {
            return sections[i].pointer_to_raw_data + (rva - sec_rva);
        }
    }
    return 0;
}

/* ============================================================
 * Base relocation processing
 *
 * Walk the .reloc section's base relocation blocks. Each block
 * covers a 4K page and contains type/offset entries. We only
 * handle IMAGE_REL_BASED_DIR64 (type 10) for 64-bit addresses.
 * ============================================================ */

static int apply_base_relocations(uint8_t *image_base, uint64_t image_size,
                                   const OptionalHeader64 *opt,
                                   const SectionHeader *sections,
                                   uint16_t num_sections,
                                   int64_t delta) {
    if (delta == 0)
        return 0;

    /* Data directory entry 5 = base relocations */
    if (opt->number_of_rva_and_sizes <= IMAGE_DIRECTORY_ENTRY_BASERELOC)
        return 0;

    const DataDirectory *dirs =
        (const DataDirectory *)((const uint8_t *)opt +
         __builtin_offsetof(OptionalHeader64, number_of_rva_and_sizes) +
         sizeof(uint32_t));
    const DataDirectory *reloc_dir = &dirs[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (reloc_dir->virtual_address == 0 || reloc_dir->size == 0)
        return 0;

    uint64_t reloc_offset = rva_to_offset(sections, num_sections,
                                            reloc_dir->virtual_address);
    if (reloc_offset == 0)
        return -1;

    const uint8_t *reloc_data = image_base + reloc_dir->virtual_address;
    const uint8_t *reloc_end = reloc_data + reloc_dir->size;

    while (reloc_data + sizeof(BaseRelocation) <= reloc_end) {
        const BaseRelocation *block = (const BaseRelocation *)reloc_data;
        if (block->size_of_block == 0)
            break;
        if (block->size_of_block < sizeof(BaseRelocation))
            break;

        uint32_t num_entries =
            (block->size_of_block - sizeof(BaseRelocation)) / sizeof(uint16_t);
        const uint16_t *entries =
            (const uint16_t *)(reloc_data + sizeof(BaseRelocation));

        for (uint32_t i = 0; i < num_entries; i++) {
            uint16_t type = entries[i] >> 12;
            uint16_t offset = entries[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_ABSOLUTE)
                continue;

            if (type == IMAGE_REL_BASED_DIR64) {
                uint64_t target_rva = block->virtual_address + offset;
                if (target_rva + 8 > image_size) {
                    pe_rtld_puts("[PE-RTLD] WARN: reloc target out of bounds\n");
                    continue;
                }
                uint64_t *target = (uint64_t *)(image_base + target_rva);
                *target += (uint64_t)delta;
            } else {
                pe_rtld_puts("[PE-RTLD] WARN: unsupported reloc type ");
                pe_rtld_hex((uint64_t)type);
                pe_rtld_puts("\n");
            }
        }

        reloc_data += block->size_of_block;
    }

    return 0;
}

/* ============================================================
 * Import resolution
 *
 * kernel32.dll is mapped as a real PE image in the process's
 * shared-library window. Import resolution first checks that
 * mapped image's export directory directly. When that misses,
 * the Win32 server can re-parse the initrd kernel32 image and
 * return the export RVA for the loader to rebase locally.
 * ============================================================ */

#define W32_RESOLVE_IMPORT_LABEL  0x100

static uint64_t resolve_single_import(cap_t win32srv_ep,
                                      const char *func_name, uint16_t ordinal) {
    if (win32srv_ep == 0)
        return 0;

    size_t name_len = pe_strlen(func_name);
    uint64_t regs[20];
    for (size_t i = 0; i < 20; i++) {
        regs[i] = 0;
    }
    if (name_len > 144)
        return 0;

    regs[0] = (uint64_t)name_len;
    regs[1] = (uint64_t)ordinal;
    if (name_len > 0) {
        pe_memcpy((void *)&regs[2], func_name, name_len);
    }

    uint64_t length = 2 + ((uint64_t)name_len + 7) / 8;
    if (length > 4 && g_pe_rtld.ipc_buffer_vaddr != 0) {
        uint64_t *ipc_msg = (uint64_t *)g_pe_rtld.ipc_buffer_vaddr;
        for (uint64_t i = 0; i < length - 4 && i < 16; i++) {
            ipc_msg[6 + i] = regs[4 + i];
        }
    }

    uint64_t msg_info = ((uint64_t)W32_RESOLVE_IMPORT_LABEL << 12) | length;
    struct rtld_syscall_result r = pe_syscall(
        SYS_CALL,
        win32srv_ep,
        msg_info,
        regs[0],
        regs[1],
        regs[2],
        regs[3]
    );

    if (r.error != 0)
        return 0;

    /* Reply MR0 contains the resolved export RVA. */
    return r.value;
}

static const ExportDirectory *find_export_directory(uint8_t *image_base,
                                                    const OptionalHeader64 *opt) {
    const DataDirectory *dirs;
    const DataDirectory *export_dir;

    if (opt->number_of_rva_and_sizes <= IMAGE_DIRECTORY_ENTRY_EXPORT)
        return NULL;

    dirs = (const DataDirectory *)((const uint8_t *)opt +
        __builtin_offsetof(OptionalHeader64, number_of_rva_and_sizes) +
        sizeof(uint32_t));
    export_dir = &dirs[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_dir->virtual_address == 0 || export_dir->size < sizeof(ExportDirectory))
        return NULL;

    return (const ExportDirectory *)(image_base + export_dir->virtual_address);
}

static uint64_t lookup_export_by_ordinal(uint8_t *image_base,
                                         const ExportDirectory *export_dir,
                                         uint16_t ordinal) {
    const uint32_t *functions;
    uint32_t index;

    if (export_dir == NULL)
        return 0;
    if (ordinal < export_dir->base)
        return 0;

    index = ordinal - export_dir->base;
    if (index >= export_dir->number_of_functions)
        return 0;

    functions = (const uint32_t *)(image_base + export_dir->address_of_functions);
    if (functions[index] == 0)
        return 0;

    return (uint64_t)(image_base + functions[index]);
}

static uint64_t lookup_export_by_name(uint8_t *image_base,
                                      const ExportDirectory *export_dir,
                                      const char *name) {
    const uint32_t *names;
    const uint16_t *ordinals;
    const uint32_t *functions;
    uint32_t i;

    if (export_dir == NULL || name == NULL || *name == '\0')
        return 0;

    names = (const uint32_t *)(image_base + export_dir->address_of_names);
    ordinals = (const uint16_t *)(image_base + export_dir->address_of_name_ordinals);
    functions = (const uint32_t *)(image_base + export_dir->address_of_functions);

    for (i = 0; i < export_dir->number_of_names; i++) {
        const char *export_name = (const char *)(image_base + names[i]);
        uint16_t ordinal_index;

        if (pe_strcmp(export_name, name) != 0)
            continue;

        ordinal_index = ordinals[i];
        if (ordinal_index >= export_dir->number_of_functions)
            return 0;
        if (functions[ordinal_index] == 0)
            return 0;

        return (uint64_t)(image_base + functions[ordinal_index]);
    }

    return 0;
}

static uint64_t resolve_kernel32_export(const char *func_name, uint16_t ordinal) {
    const DosHeader *dos;
    const CoffHeader *coff;
    const OptionalHeader64 *opt;
    const SectionHeader *sections;
    uint16_t num_sections;
    uint8_t *image_base;
    const ExportDirectory *export_dir;

    if (g_pe_rtld.kernel32_base == 0 || g_pe_rtld.kernel32_size == 0)
        return 0;

    image_base = (uint8_t *)g_pe_rtld.kernel32_base;
    if (pe_validate(image_base, g_pe_rtld.kernel32_size,
                    &dos, &coff, &opt, &sections, &num_sections) != 0)
        return 0;

    export_dir = find_export_directory(image_base, opt);
    if (func_name != NULL && *func_name != '\0')
        return lookup_export_by_name(image_base, export_dir, func_name);

    return lookup_export_by_ordinal(image_base, export_dir, ordinal);
}

static void initialize_kernel32_runtime(void) {
    struct kernel32_ipc_context *ipc_ctx;
    uint64_t *win32srv_ep;

    ipc_ctx = (struct kernel32_ipc_context *)resolve_kernel32_export("__trona_ipc_ctx", 0);
    if (ipc_ctx != NULL) {
        ipc_ctx->ipc_buffer = (void *)g_pe_rtld.ipc_buffer_vaddr;
        ipc_ctx->send_cap_count = 0;
    }

    win32srv_ep = (uint64_t *)resolve_kernel32_export("__win32srv_ep", 0);
    if (win32srv_ep != NULL)
        *win32srv_ep = g_pe_rtld.win32srv_ep;
}

static int resolve_imports(uint8_t *image_base, uint64_t image_size,
                           const OptionalHeader64 *opt,
                           const SectionHeader *sections,
                           uint16_t num_sections,
                           cap_t win32srv_ep, uint64_t scratch) {
    if (opt->number_of_rva_and_sizes <= IMAGE_DIRECTORY_ENTRY_IMPORT)
        return 0;

    const DataDirectory *dirs =
        (const DataDirectory *)((const uint8_t *)opt +
         __builtin_offsetof(OptionalHeader64, number_of_rva_and_sizes) +
         sizeof(uint32_t));
    const DataDirectory *import_dir = &dirs[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (import_dir->virtual_address == 0 || import_dir->size == 0)
        return 0;

    const ImportDescriptor *desc =
        (const ImportDescriptor *)(image_base + import_dir->virtual_address);

    for (; desc->name_rva != 0; desc++) {
        const char *dll_name = (const char *)(image_base + desc->name_rva);

        pe_rtld_puts("[PE-RTLD] importing from: ");
        pe_rtld_puts(dll_name);
        pe_rtld_puts("\n");

        /* ILT (Import Lookup Table) — used to determine import names/ordinals.
         * IAT (Import Address Table) — patched with resolved addresses.
         *
         * IMPORTANT: When original_first_thunk != 0, ILT and IAT are separate
         * tables. ILT entries are NOT subject to base relocation and contain
         * raw RVAs. When original_first_thunk == 0, ILT == IAT and entries
         * MAY have been corrupted by base relocation (if the relocation table
         * contains fixups for IAT entries). */
        uint32_t ilt_rva = desc->original_first_thunk;
        uint32_t iat_rva = desc->first_thunk;

        if (ilt_rva == 0)
            ilt_rva = iat_rva;
        if (iat_rva == 0)
            continue;

        const uint64_t *ilt = (const uint64_t *)(image_base + ilt_rva);
        uint64_t *iat = (uint64_t *)(image_base + iat_rva);

        for (int idx = 0; ilt[idx] != 0; idx++) {
            uint64_t entry = ilt[idx];
            const char *func_name = NULL;
            uint16_t ordinal = 0;

            if (entry & ((uint64_t)1 << 63)) {
                /* Import by ordinal */
                ordinal = (uint16_t)(entry & 0xFFFF);
            } else {
                /* Import by name — entry is RVA to hint/name table entry.
                 * Hint/Name: uint16_t hint, then null-terminated ASCII name. */
                uint32_t hint_rva = (uint32_t)(entry & 0x7FFFFFFF);
                if (hint_rva + 2 < image_size) {
                    func_name = (const char *)(image_base + hint_rva + 2);
                    ordinal = *(const uint16_t *)(image_base + hint_rva);
                }
            }

            uint64_t resolved = 0;

            if (pe_strcasecmp(dll_name, "kernel32.dll") == 0) {
                resolved = resolve_kernel32_export(func_name, ordinal);
                if (resolved == 0) {
                    uint64_t export_rva = resolve_single_import(
                        win32srv_ep, func_name ? func_name : "", ordinal
                    );
                    if (export_rva != 0) {
                        resolved = g_pe_rtld.kernel32_base + export_rva;
                    }
                }
            }

            if (resolved != 0) {
                iat[idx] = resolved;
            } else {
                pe_rtld_puts("[PE-RTLD] WARN: unresolved import ");
                if (func_name)
                    pe_rtld_puts(func_name);
                else {
                    pe_rtld_puts("ordinal ");
                    pe_rtld_hex((uint64_t)ordinal);
                }
                pe_rtld_puts(" (ilt_entry=");
                pe_rtld_hex(entry);
                pe_rtld_puts(")\n");
            }
        }
    }

    return 0;
}

/* ============================================================
 * Jump to PE entry point
 *
 * PE entry point signature (for executables):
 *   void mainCRTStartup(void);
 * or for DLLs:
 *   BOOL DllMain(HINSTANCE, DWORD, LPVOID);
 *
 * We use the same assembly trampoline as the ELF rtld to
 * restore the original stack pointer and jump.
 * ============================================================ */

static void __attribute__((noreturn)) pe_jump_entry(uint64_t sp, void *entry) {
#if defined(__x86_64__)
    __asm__ volatile(
        "movq %0, %%rsp\n"
        "xorq %%rbp, %%rbp\n"
        "jmpq *%1\n"
        : : "r"(sp), "r"(entry) : "memory"
    );
#elif defined(__aarch64__)
    __asm__ volatile(
        "dsb ish\n"
        "isb\n"
        "mov sp, %0\n"
        "mov x29, xzr\n"
        "mov x30, xzr\n"
        "br %1\n"
        : : "r"(sp), "r"(entry) : "memory"
    );
#endif
    __builtin_unreachable();
}

/* ============================================================
 * pe_rtld_main — entry point called from _start
 * ============================================================ */

void __attribute__((noreturn)) pe_rtld_main(uint64_t *sp) {
    /* 1. Parse initial stack: argc, argv[], NULL, envp[], NULL, auxv[] */
    uint64_t argc = sp[0];
    uint64_t *argv = &sp[1];

    /* Skip past argv + NULL */
    uint64_t *p = argv + argc + 1;

    /* Skip past envp + NULL */
    while (*p != 0) p++;
    p++;

    /* Parse auxv */
    for (; p[0] != AT_NULL; p += 2) {
        switch (p[0]) {
        case AT_BASE:
            g_pe_rtld.rtld_base = p[1];
            break;
        case AT_SALTYOS_PE_BASE:
            g_pe_rtld.pe_base = p[1];
            break;
        case AT_SALTYOS_PE_SIZE:
            g_pe_rtld.pe_size = p[1];
            break;
        case AT_SALTYOS_WIN32SRV:
            g_pe_rtld.win32srv_ep = p[1];
            break;
        case AT_SALTYOS_KERNEL32_BASE:
            g_pe_rtld.kernel32_base = p[1];
            break;
        case AT_SALTYOS_KERNEL32_SIZE:
            g_pe_rtld.kernel32_size = p[1];
            break;
        case AT_TRONA_VSPACE:
            g_pe_rtld.vspace = p[1];
            break;
        case AT_TRONA_MM_EP:
            g_pe_rtld.mm_ep = p[1];
            break;
        case AT_TRONA_SCRATCH:
            g_pe_rtld.scratch_vaddr = p[1];
            break;
        case AT_TRONA_IPC_BUFFER:
            g_pe_rtld.ipc_buffer_vaddr = p[1];
            break;
        case AT_TRONA_SLOT_BASE:
            g_pe_rtld.slot_base = p[1];
            break;
        case AT_TRONA_SLOT_COUNT:
            g_pe_rtld.slot_count = p[1];
            break;
        case AT_TRONA_CSPACE_NTFN:
            g_pe_rtld.cspace_ntfn = p[1];
            break;
        }
    }

    /* 2. Self-relocate */
    if (g_pe_rtld.rtld_base != 0) {
        Elf64_Dyn *own_dyn = find_dynamic(g_pe_rtld.rtld_base);
        if (own_dyn)
            self_relocate(g_pe_rtld.rtld_base, own_dyn);
    }

    /* Now global data is safe */
    pe_rtld_puts("[PE-RTLD] SaltyOS PE runtime loader starting\n");

    /* 3. Validate PE image */
    if (g_pe_rtld.pe_base == 0 || g_pe_rtld.pe_size == 0) {
        pe_rtld_puts("[PE-RTLD] FATAL: no PE image (AT_SALTYOS_PE_BASE missing)\n");
        pe_exit(127);
    }

    pe_rtld_puts("[PE-RTLD] PE image at ");
    pe_rtld_hex(g_pe_rtld.pe_base);
    pe_rtld_puts(" size ");
    pe_rtld_hex(g_pe_rtld.pe_size);
    pe_rtld_puts("\n");

    uint8_t *image = (uint8_t *)g_pe_rtld.pe_base;
    uint64_t image_size = g_pe_rtld.pe_size;

    const DosHeader *dos;
    const CoffHeader *coff;
    const OptionalHeader64 *opt;
    const SectionHeader *sections;
    uint16_t num_sections;

    int err = pe_validate(image, image_size,
                          &dos, &coff, &opt, &sections, &num_sections);
    if (err != 0) {
        pe_rtld_puts("[PE-RTLD] FATAL: PE validation failed, error=");
        pe_rtld_hex((uint64_t)(uint32_t)(-err));
        pe_rtld_puts("\n");
        pe_exit(126);
    }

    pe_rtld_puts("[PE-RTLD] PE validated: ");
    pe_rtld_hex((uint64_t)num_sections);
    pe_rtld_puts(" sections, entry RVA ");
    pe_rtld_hex((uint64_t)opt->address_of_entry_point);
    pe_rtld_puts("\n");

    /* 4. Apply base relocations */
    int64_t delta = (int64_t)g_pe_rtld.pe_base - (int64_t)opt->image_base;
    if (delta != 0) {
        pe_rtld_puts("[PE-RTLD] applying base relocations, delta=");
        pe_rtld_hex((uint64_t)delta);
        pe_rtld_puts("\n");

        err = apply_base_relocations(image, image_size, opt,
                                      sections, num_sections, delta);
        if (err != 0) {
            pe_rtld_puts("[PE-RTLD] FATAL: base relocation failed\n");
            pe_exit(125);
        }
    }

    if (g_pe_rtld.kernel32_base == 0 || g_pe_rtld.kernel32_size == 0) {
        pe_rtld_puts("[PE-RTLD] FATAL: kernel32.dll mapping missing\n");
        pe_exit(124);
    }

    initialize_kernel32_runtime();

    /* 5. Resolve imports */
    pe_rtld_puts("[PE-RTLD] resolving imports from kernel32.dll @ ");
    pe_rtld_hex(g_pe_rtld.kernel32_base);
    pe_rtld_puts("\n");

    err = resolve_imports(image, image_size, opt, sections, num_sections,
                          (cap_t)g_pe_rtld.win32srv_ep,
                          g_pe_rtld.scratch_vaddr);
    if (err != 0) {
        pe_rtld_puts("[PE-RTLD] FATAL: import resolution failed\n");
        pe_exit(124);
    }

    /* 6. Apply section permissions (W^X) now that IAT writes are done.
     * Use MM_MPROTECT so mmsrv updates both region metadata and any
     * currently-present PTEs for the mapped image.
     */
    {
        uint64_t pe_base = g_pe_rtld.pe_base;

        /* Headers: read-only */
        uint64_t hdr_pages = pe_page_align_up(opt->size_of_headers) / PAGE_SIZE;
        if (hdr_pages > 0) {
            uint64_t ret = pe_mm_mprotect(pe_base, hdr_pages * PAGE_SIZE, VSPACE_FLAG_USER);
            if (ret != 0) {
                pe_rtld_puts("[PE-RTLD] FATAL: header mprotect failed ret=");
                pe_rtld_hex(ret);
                pe_rtld_puts("\n");
                pe_exit(123);
            }
        }

        /* Per-section permissions */
        for (uint16_t si = 0; si < num_sections; si++) {
            uint64_t sec_base = pe_base + sections[si].virtual_address;
            uint32_t sec_sz = sections[si].virtual_size > 0
                ? sections[si].virtual_size
                : sections[si].size_of_raw_data;
            uint64_t sec_pages = pe_page_align_up(sec_sz) / PAGE_SIZE;
            if (sec_pages == 0)
                continue;

            uint64_t flags = pe_section_to_vspace_flags(sections[si].characteristics);
            uint64_t ret = pe_mm_mprotect(sec_base, sec_pages * PAGE_SIZE, flags);
            pe_rtld_puts("[PE-RTLD] protect ");
            pe_rtld_hex(sec_base);
            pe_rtld_puts(" pages=");
            pe_rtld_hex(sec_pages);
            pe_rtld_puts(" flags=");
            pe_rtld_hex(flags);
            pe_rtld_puts(" ret=");
            pe_rtld_hex(ret);
            pe_rtld_puts("\n");
            if (ret != 0) {
                pe_rtld_puts("[PE-RTLD] FATAL: section mprotect failed\n");
                pe_exit(123);
            }
        }
    }

    /* 6b. Apply section permissions for kernel32.dll using the same path. */
    if (g_pe_rtld.kernel32_base != 0 && g_pe_rtld.kernel32_size != 0) {
        const DosHeader *k32_dos;
        const CoffHeader *k32_coff;
        const OptionalHeader64 *k32_opt;
        const SectionHeader *k32_sections;
        uint16_t k32_num_sections;
        uint8_t *k32_base = (uint8_t *)g_pe_rtld.kernel32_base;

        int k32_err = pe_validate(k32_base, g_pe_rtld.kernel32_size,
                                  &k32_dos, &k32_coff, &k32_opt,
                                  &k32_sections, &k32_num_sections);
        if (k32_err == 0) {
            /* Headers: read-only */
            uint64_t k32_hdr_pages =
                pe_page_align_up(k32_opt->size_of_headers) / PAGE_SIZE;
            if (k32_hdr_pages > 0)
                pe_mm_mprotect(g_pe_rtld.kernel32_base,
                               k32_hdr_pages * PAGE_SIZE, VSPACE_FLAG_USER);

            for (uint16_t si = 0; si < k32_num_sections; si++) {
                uint64_t sec_base =
                    g_pe_rtld.kernel32_base + k32_sections[si].virtual_address;
                uint32_t sec_sz = k32_sections[si].virtual_size > 0
                    ? k32_sections[si].virtual_size
                    : k32_sections[si].size_of_raw_data;
                uint64_t sec_pages = pe_page_align_up(sec_sz) / PAGE_SIZE;
                if (sec_pages == 0)
                    continue;

                uint64_t flags =
                    pe_section_to_vspace_flags(k32_sections[si].characteristics);
                pe_mm_mprotect(sec_base, sec_pages * PAGE_SIZE, flags);
            }
        }
    }

    /* 7. Jump to PE entry point */
    uint64_t entry_va = g_pe_rtld.pe_base + opt->address_of_entry_point;
    pe_rtld_puts("[PE-RTLD] jumping to entry ");
    pe_rtld_hex(entry_va);
    pe_rtld_puts("\n");

    pe_jump_entry((uint64_t)(uintptr_t)sp, (void *)(uintptr_t)entry_va);
}
