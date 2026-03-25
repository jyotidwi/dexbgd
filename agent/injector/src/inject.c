/*
 * dexbgd-inject  –  ptrace-inject a .so into a running arm64 Android process
 *
 * Usage (as root):
 *   dexbgd-inject <pid> <absolute_path_to_so>
 *
 * How it works:
 *   1.  PTRACE_SEIZE + PTRACE_INTERRUPT  – stop the main thread
 *   2.  Save all registers (NT_PRSTATUS)
 *   3.  Resolve dlopen() in libdl and mmap() in libc via ELF PT_DYNAMIC
 *   4.  Write the .so path onto the target's stack (data only, never executed)
 *   5.  Phase 1 – mmap injection:
 *         Write BRK #0 at saved_pc; hijack regs to call
 *         mmap(NULL, 4096, PROT_READ|PROT_EXEC, MAP_ANON|MAP_PRIVATE, -1, 0).
 *         mmap is a single syscall so the patched window is ~microseconds.
 *         Catch the SIGTRAP return; read trampoline page address from x0.
 *         Restore saved_pc's original instruction immediately.
 *   6.  Write BRK #0 onto the fresh anonymous page via PTRACE_POKEDATA
 *       (unique – no other thread will ever execute this page).
 *   7.  Phase 2 – dlopen injection:
 *         Hijack regs to call dlopen(path, RTLD_NOW) with LR = trampoline.
 *         No shared-library code is patched during the slow dlopen call.
 *   8.  SIGTRAP fires at the private trampoline; read x0 (handle).
 *   9.  Restore trampoline page word, restore all registers, PTRACE_DETACH.
 *
 * The 4 KB trampoline page is leaked intentionally (munmap would need a
 * third injection pass; 4 KB is acceptable overhead for a debug tool).
 *
 * Fallback: if mmap injection fails, falls back to the original unsafe
 * approach (BRK at saved_pc for the full dlopen duration) with a warning.
 */

#include <dirent.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef NT_PRSTATUS
#  define NT_PRSTATUS 1
#endif
#ifndef PTRACE_SEIZE
#  define PTRACE_SEIZE        0x4206
#endif
#ifndef PTRACE_INTERRUPT
#  define PTRACE_INTERRUPT    0x4207
#endif
#ifndef PTRACE_O_TRACECLONE
#  define PTRACE_O_TRACECLONE 0x00000008
#endif
#ifndef PTRACE_EVENT_CLONE
#  define PTRACE_EVENT_CLONE  3
#endif
#ifndef __WALL
#  define __WALL              0x40000000
#endif

typedef struct {
    uint64_t x[31];   /* x0..x30 (x30 = LR) */
    uint64_t sp;
    uint64_t pc;
    uint64_t pstate;
} Arm64Regs;

/* -------------------------------------------------------------------------
 * /proc/pid/mem helpers – read/write data pages (stack, writable mappings).
 * Note: does NOT work on read-only executable pages; use PTRACE_POKEDATA for those.
 * ---------------------------------------------------------------------- */

static int mem_write(pid_t pid, uint64_t addr, const void *buf, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    int fd = open(path, O_WRONLY);
    if (fd < 0) { perror("[inject] open mem(w)"); return -1; }
    if (lseek64(fd, (off64_t)addr, SEEK_SET) < 0) {
        perror("[inject] lseek"); close(fd); return -1;
    }
    ssize_t n = write(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

static int mem_read(pid_t pid, uint64_t addr, void *buf, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) { perror("[inject] open mem(r)"); return -1; }
    if (lseek64(fd, (off64_t)addr, SEEK_SET) < 0) {
        perror("[inject] lseek"); close(fd); return -1;
    }
    ssize_t n = read(fd, buf, len);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

/* -------------------------------------------------------------------------
 * ELF symbol resolution via PT_DYNAMIC (works without section headers)
 * ---------------------------------------------------------------------- */

static uint64_t va_to_foff(Elf64_Phdr *loads, int nloads, uint64_t va)
{
    for (int i = 0; i < nloads; i++) {
        Elf64_Phdr *p = &loads[i];
        if (va >= p->p_vaddr && va < p->p_vaddr + p->p_memsz)
            return p->p_offset + (va - p->p_vaddr);
    }
    return (uint64_t)-1;
}

static uint64_t elf_find_sym(const char *elf_path, const char *sym_name)
{
    int fd = open(elf_path, O_RDONLY);
    if (fd < 0) { perror("[inject] open elf"); return 0; }

    Elf64_Ehdr eh;
    if (pread(fd, &eh, sizeof(eh), 0) != sizeof(eh)
        || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0
        || eh.e_ident[EI_CLASS] != ELFCLASS64) {
        fprintf(stderr, "[inject] not ELF64: %s\n", elf_path);
        close(fd); return 0;
    }

    int nph = (eh.e_phnum < 32) ? eh.e_phnum : 32;
    Elf64_Phdr ph[32];
    pread(fd, ph, nph * sizeof(Elf64_Phdr), eh.e_phoff);

    Elf64_Phdr loads[8]; int nloads = 0;
    uint64_t dyn_va = 0, dyn_filesz = 0;
    for (int i = 0; i < nph; i++) {
        if (ph[i].p_type == PT_LOAD   && nloads < 8) loads[nloads++] = ph[i];
        if (ph[i].p_type == PT_DYNAMIC) {
            dyn_va    = ph[i].p_vaddr;
            dyn_filesz = ph[i].p_filesz;
        }
    }
    if (!dyn_va || !nloads) { close(fd); return 0; }

    uint64_t dyn_off = va_to_foff(loads, nloads, dyn_va);
    size_t   ndyn    = dyn_filesz / sizeof(Elf64_Dyn);
    Elf64_Dyn *dyn   = malloc(dyn_filesz);
    if (!dyn || pread(fd, dyn, dyn_filesz, dyn_off) != (ssize_t)dyn_filesz) {
        free(dyn); close(fd); return 0;
    }

    uint64_t symtab_va = 0, strtab_va = 0, strtab_sz = 0;
    uint64_t hash_va = 0, gnuhash_va = 0;
    for (size_t i = 0; i < ndyn; i++) {
        switch (dyn[i].d_tag) {
            case DT_SYMTAB:   symtab_va  = dyn[i].d_un.d_ptr; break;
            case DT_STRTAB:   strtab_va  = dyn[i].d_un.d_ptr; break;
            case DT_STRSZ:    strtab_sz  = dyn[i].d_un.d_val; break;
            case DT_HASH:     hash_va    = dyn[i].d_un.d_ptr; break;
            case DT_GNU_HASH: gnuhash_va = dyn[i].d_un.d_ptr; break;
        }
    }
    free(dyn);

    if (!symtab_va || !strtab_va) { close(fd); return 0; }

    /* Symbol count: prefer DT_HASH (nchain = total syms), then DT_GNU_HASH,
     * then a large fallback (pread past EOF breaks the loop gracefully). */
    uint32_t nsyms = 65535;
    if (hash_va) {
        uint32_t hdr[2];
        if (pread(fd, hdr, 8, va_to_foff(loads, nloads, hash_va)) == 8)
            nsyms = hdr[1];
    } else if (gnuhash_va) {
        /* GNU_HASH: [nbuckets, symoffset, bloom_size, bloom_shift, bloom[], buckets[], chains[]]
         * Walk every bucket chain to find the highest symbol index. */
        uint32_t ghdr[4];
        uint64_t gh_off = va_to_foff(loads, nloads, gnuhash_va);
        if (pread(fd, ghdr, 16, gh_off) == 16) {
            uint32_t nb = ghdr[0], symoff = ghdr[1], bloom_sz = ghdr[2];
            uint64_t bkt_off = gh_off + 16 + (uint64_t)bloom_sz * 8;
            uint64_t chn_off = bkt_off + (uint64_t)nb * 4;
            uint32_t max_sym = symoff;
            uint32_t *bkts = malloc((size_t)nb * 4);
            if (bkts && pread(fd, bkts, nb * 4, bkt_off) == (ssize_t)(nb * 4)) {
                for (uint32_t k = 0; k < nb; k++)
                    if (bkts[k] > max_sym) max_sym = bkts[k];
            }
            free(bkts);
            /* Walk chain from max_sym until stop bit */
            if (max_sym >= symoff) {
                uint32_t cidx = max_sym - symoff;
                for (;;) {
                    uint32_t c;
                    if (pread(fd, &c, 4, chn_off + (uint64_t)cidx * 4) != 4) break;
                    cidx++;
                    if (c & 1) break;
                }
                nsyms = symoff + cidx;
            }
        }
    }

    /* Allow strtab up to 2 MB; bionic libc's strtab is ~60-100 KB */
    if (!strtab_sz || strtab_sz > (2u << 20)) strtab_sz = 65536;
    char *strtab = malloc(strtab_sz + 1);
    uint64_t strtab_off = va_to_foff(loads, nloads, strtab_va);
    if (!strtab || pread(fd, strtab, strtab_sz, strtab_off) <= 0) {
        free(strtab); close(fd); return 0;
    }
    strtab[strtab_sz] = '\0';

    uint64_t symtab_off = va_to_foff(loads, nloads, symtab_va);
    uint64_t result = 0;
    for (uint32_t i = 0; i < nsyms && !result; i++) {
        Elf64_Sym sym;
        if (pread(fd, &sym, sizeof(sym), symtab_off + i * sizeof(sym)) != sizeof(sym))
            break;
        if (!sym.st_value) continue;
        if (sym.st_name >= strtab_sz) continue;
        if (strcmp(strtab + sym.st_name, sym_name) == 0)
            result = sym.st_value;
    }

    free(strtab);
    close(fd);
    return result;
}

/* Resolve a symbol from the first mapping whose path contains lib_substr. */
static uint64_t resolve_sym_in_lib(pid_t pid, const char *lib_substr,
                                    const char *sym_name)
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
    FILE *f = fopen(maps_path, "r");
    if (!f) { perror("[inject] open maps"); return 0; }

    char line[640], elf_path[512];
    uint64_t elf_base = 0;

    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, lib_substr)) continue;
        uint64_t lo, hi, foff; unsigned long inode;
        char perms[8], dev[16], fpath[512];
        int n = sscanf(line, "%lx-%lx %7s %lx %15s %lu %511s",
                       &lo, &hi, perms, &foff, dev, &inode, fpath);
        if (n < 7 || foff != 0) continue;
        elf_base = lo;
        strncpy(elf_path, fpath, sizeof(elf_path) - 1);
        elf_path[sizeof(elf_path) - 1] = '\0';
        break;
    }
    fclose(f);

    if (!elf_base) {
        fprintf(stderr, "[inject] %s not found in /proc/%d/maps\n",
                lib_substr, (int)pid);
        return 0;
    }
    printf("[inject] %s  base=0x%lx  %s\n", lib_substr, elf_base, elf_path);

    uint64_t sym_off = elf_find_sym(elf_path, sym_name);
    if (!sym_off) {
        fprintf(stderr, "[inject] '%s' not found in %s\n", sym_name, elf_path);
        return 0;
    }
    printf("[inject] %s  offset=0x%lx  va=0x%lx\n",
           sym_name, sym_off, elf_base + sym_off);
    return elf_base + sym_off;
}

/* -------------------------------------------------------------------------
 * Patch / restore a 4-byte arm64 instruction at an arbitrary address.
 * Uses PTRACE_PEEKDATA / PTRACE_POKEDATA which bypass page permissions
 * (the process must be ptrace-stopped).
 * ---------------------------------------------------------------------- */

static int poke_insn(pid_t pid, uint64_t addr, uint32_t insn, long *saved_word_out)
{
    /* arm64 instructions are 4-byte aligned; PTRACE_PEEK/POKEDATA is 8-byte */
    uint64_t word_addr = addr & ~(uint64_t)7;
    int      hi_half   = (addr & 4) != 0;   /* instruction in high 32 bits? */

    errno = 0;
    long orig = ptrace(PTRACE_PEEKDATA, pid, (void *)(uintptr_t)word_addr, NULL);
    if (errno) { perror("[inject] PEEKDATA"); return -1; }

    if (saved_word_out) *saved_word_out = orig;

    long patched;
    if (!hi_half)
        patched = (orig & (long)~(uint64_t)0xffffffffu) | (long)insn;
    else
        patched = (orig & (long)0xffffffff) | ((long)insn << 32);

    if (ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)word_addr, patched) != 0) {
        perror("[inject] POKEDATA"); return -1;
    }
    return 0;
}

static void restore_insn(pid_t pid, uint64_t addr, long orig_word)
{
    uint64_t word_addr = addr & ~(uint64_t)7;
    ptrace(PTRACE_POKEDATA, pid, (void *)(uintptr_t)word_addr, orig_word);
}

/* -------------------------------------------------------------------------
 * Main
 * ---------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    if (argc < 3) {
        fprintf(stderr, "Usage: dexbgd-inject <pid> <path_to_so>\n");
        return 1;
    }

    pid_t       pid    = (pid_t)atoi(argv[1]);
    const char *so     = argv[2];
    size_t      so_len = strlen(so) + 1;

    if (so_len > 512) { fprintf(stderr, "[inject] path too long\n"); return 1; }
    printf("[inject] pid=%d  so=%s\n", (int)pid, so);
    fflush(stdout);

    int       wstatus = 0, result = 0;
    int       brk_patched = 0, trampoline_patched = 0;
    uint64_t  scratch = 0, dlopen_va = 0, mmap_va = 0;
    uint64_t  trampoline = 0, handle = 0;
    long      orig_code_word = 0, saved_trampoline_word = 0;
    Arm64Regs regs, saved;
    /* Threads cloned during dlopen that we keep frozen until detach */
    pid_t     frozen[64]; int nfrozen = 0;
    struct iovec iov;
    enum { SCRATCH_SZ = 512 };
    uint8_t   backup[SCRATCH_SZ];

    memset(&regs, 0, sizeof(regs)); memset(&saved, 0, sizeof(saved));
    memset(&iov,  0, sizeof(iov));  memset(backup, 0, sizeof(backup));

    /* 1. Attach */
    if (ptrace(PTRACE_SEIZE, pid, 0, 0) != 0) {
        perror("[inject] PTRACE_SEIZE"); return 1;
    }

    /* 2. Stop */
    if (ptrace(PTRACE_INTERRUPT, pid, 0, 0) != 0) {
        perror("[inject] PTRACE_INTERRUPT");
        ptrace(PTRACE_DETACH, pid, 0, 0); return 1;
    }
    /* PTRACE_INTERRUPT on a running tracee delivers SIGTRAP|PTRACE_EVENT_STOP.
     * PTRACE_INTERRUPT on a group-stopped tracee (SIGSTOP'd from outside)
     * correctly reports SIGSTOP (sig=19) -- that IS the valid ptrace-stop;
     * do not drain it. */
    if (waitpid(pid, &wstatus, 0) < 0 || !WIFSTOPPED(wstatus)) {
        fprintf(stderr, "[inject] not stopped (0x%x)\n", wstatus);
        ptrace(PTRACE_DETACH, pid, 0, 0); return 1;
    }
    printf("[inject] stopped (sig=%d)\n", WSTOPSIG(wstatus));

    /* 3. Save registers */
    iov.iov_base = &regs; iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov) != 0) {
        perror("[inject] GETREGSET");
        ptrace(PTRACE_DETACH, pid, 0, 0); return 1;
    }
    saved = regs;
    printf("[inject] pc=0x%016lx  sp=0x%016lx\n", regs.pc, regs.sp);

    /* 4. Resolve symbols */
    dlopen_va = resolve_sym_in_lib(pid, "libdl", "dlopen");
    if (!dlopen_va) { result = 1; goto restore; }

    mmap_va = resolve_sym_in_lib(pid, "libc.so", "mmap");
    if (!mmap_va) { result = 1; goto restore; }

    /* 5. Write .so path onto target's stack (just data, not executed) */
    scratch = (saved.sp - 4096) & ~(uint64_t)0xf;
    if (mem_read(pid, scratch, backup, so_len < SCRATCH_SZ ? so_len : SCRATCH_SZ) != 0)
        { result = 1; goto restore; }
    if (mem_write(pid, scratch, so, so_len) != 0)
        { result = 1; goto restore; }

    /* 6. Phase 1: inject mmap() to obtain a unique executable trampoline page.
     *
     *    BRK #0 is written at saved_pc only during this fast syscall wrapper
     *    call (~microseconds), so the window where shared code is patched is
     *    negligible compared to the full dlopen duration (~milliseconds). */
    if (poke_insn(pid, saved.pc, 0xD4200000u, &orig_code_word) != 0)
        { result = 1; goto restore; }
    brk_patched = 1;

    regs = saved;
    regs.x[0]  = 0;                                /* addr   = NULL           */
    regs.x[1]  = 0x1000;                           /* length = 4096           */
    regs.x[2]  = 5;                                /* prot   = READ|EXEC      */
    regs.x[3]  = 0x22;                             /* flags  = PRIVATE|ANON   */
    regs.x[4]  = (uint64_t)-1;                     /* fd     = -1             */
    regs.x[5]  = 0;                                /* offset = 0              */
    regs.x[30] = saved.pc;                         /* LR -> BRK trap          */
    regs.sp    = (scratch - 256) & ~(uint64_t)0xf;
    regs.pc    = mmap_va;
    iov.iov_base = &regs; iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov) != 0) {
        perror("[inject] SETREGSET mmap"); result = 1; goto restore;
    }

    if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) {
        perror("[inject] CONT mmap"); result = 1; goto restore;
    }
    /* Drain SIGSTOP deliveries before the mmap SIGTRAP arrives (max 8). */
    for (int _i = 0; _i < 8; _i++) {
        if (waitpid(pid, &wstatus, 0) < 0) {
            perror("[inject] waitpid mmap"); result = 1; goto restore;
        }
        if (WIFSTOPPED(wstatus) && WSTOPSIG(wstatus) == SIGSTOP) {
            ptrace(PTRACE_CONT, pid, 0, 0);
            continue;
        }
        break;
    }
    if (!WIFSTOPPED(wstatus) || WSTOPSIG(wstatus) != SIGTRAP) {
        fprintf(stderr, "[inject] mmap phase: unexpected stop (sig=%d, 0x%x) -- "
                        "falling back to unsafe mode\n",
                WSTOPSIG(wstatus), wstatus);
        /* Keep brk_patched=1 so restore cleans up; fall through to dlopen
         * with LR=saved_pc (original behaviour, now with a warning). */
        goto do_dlopen;
    }

    {
        Arm64Regs mret; struct iovec mriov = { &mret, sizeof(mret) };
        ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &mriov);
        trampoline = mret.x[0];
    }

    if (!trampoline || (int64_t)trampoline < 0) {
        fprintf(stderr, "[inject] mmap returned 0x%lx -- falling back to unsafe mode\n",
                trampoline);
        trampoline = 0;
        /* brk_patched still set; fall through with LR=saved_pc */
    } else {
        printf("[inject] trampoline page=0x%lx\n", trampoline);

        /* Restore original instruction at saved_pc -- no longer needed */
        restore_insn(pid, saved.pc, orig_code_word);
        brk_patched = 0;

        /* Write BRK #0 onto the unique trampoline page.
         * PTRACE_POKEDATA bypasses PROT_WRITE restriction (FOLL_FORCE). */
        if (poke_insn(pid, trampoline, 0xD4200000u, &saved_trampoline_word) != 0)
            { result = 1; goto restore; }
        trampoline_patched = 1;
    }

do_dlopen:
    /* 7. Phase 2: dlopen injection.
     *    LR = trampoline (unique private page) if mmap succeeded,
     *    otherwise LR = saved_pc with BRK (original unsafe fallback). */
    regs = saved;
    regs.x[0]  = scratch;                                   /* path          */
    regs.x[1]  = 2;                                         /* RTLD_NOW      */
    regs.x[30] = trampoline ? trampoline : saved.pc;        /* LR            */
    regs.sp    = (scratch - 256) & ~(uint64_t)0xf;
    regs.pc    = dlopen_va;
    iov.iov_base = &regs; iov.iov_len = sizeof(regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov) != 0) {
        perror("[inject] SETREGSET dlopen"); result = 1; goto restore;
    }

    /* In fallback mode the BRK at saved_pc was already written in phase 1;
     * it is still there (brk_patched=1) so no re-patch needed. */

    if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) {
        perror("[inject] CONT dlopen"); result = 1; goto restore;
    }
    /* dlopen wait: suppress all signals on main thread.
     * Anti-tamper heartbeat (sig 35) is suppressed so it cannot call kill().
     * New threads run freely -- freezing them (PTRACE_O_TRACECLONE) deadlocks
     * dlopen because ART/JIT threads it spawns never complete. */
    for (int _i = 0; _i < 64; _i++) {
        if (waitpid(pid, &wstatus, 0) < 0) {
            perror("[inject] waitpid dlopen"); result = 1; goto restore;
        }
        if (!WIFSTOPPED(wstatus)) {
            fprintf(stderr, "[inject] process terminated (0x%x)!\n", wstatus);
            return 1;
        }
        int dsig = WSTOPSIG(wstatus);
        if (dsig == SIGTRAP) {
            /* Verify PC is at our trampoline (or saved_pc in fallback).
             * ART JIT emits spurious BRK instructions -- ignore those. */
            uint64_t brk_addr = trampoline ? trampoline : saved.pc;
            Arm64Regs cur; struct iovec ciov = { &cur, sizeof(cur) };
            ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &ciov);
            if (cur.pc == brk_addr) break;  /* our BRK -- dlopen returned */
            printf("[inject] dlopen: spurious SIGTRAP at 0x%lx (expected 0x%lx), continuing\n",
                   cur.pc, brk_addr);
            fflush(stdout);
            ptrace(PTRACE_CONT, pid, 0, 0);
            continue;
        }
        printf("[inject] dlopen: suppressing signal %d\n", dsig);
        fflush(stdout);
        ptrace(PTRACE_CONT, pid, 0, 0);
    }

    /* 8. Read dlopen return value (x0) */
    {
        Arm64Regs ret; struct iovec riov = { &ret, sizeof(ret) };
        ptrace(PTRACE_GETREGSET, pid, (void *)(long)NT_PRSTATUS, &riov);
        handle = ret.x[0];
    }
    if (handle) {
        printf("[inject] dlopen OK  handle=0x%lx\n", handle);
        /* The process was group-stopped (SIGSTOP) before injection.
         * The main thread is paused under ptrace, but all other threads
         * (including the agent's socket thread) are still group-stopped.
         * Send SIGCONT to unfreeze them so the socket thread can start. */
        kill(pid, SIGCONT);
        printf("[inject] sent SIGCONT -- agent socket thread unfrozen\n");
        /* Poll for agent socket — the socket thread runs freely (only main is stopped) */
        printf("[inject] Waiting for agent socket @dexbgd...\n");
        fflush(stdout);
        int sock_found = 0;
        for (int i = 0; i < 50; i++) {
            FILE *uf = fopen("/proc/net/unix", "r");
            if (uf) {
                char ul[256];
                while (fgets(ul, sizeof(ul), uf))
                    if (strstr(ul, "dexbgd")) { sock_found = 1; break; }
                fclose(uf);
                if (sock_found) { printf("[inject] socket ready\n"); break; }
            }
            usleep(100000); /* 100 ms */
        }
        if (!sock_found)
            printf("[inject] WARNING: socket @dexbgd not found -- check logcat -s ArtJitTracer\n");

        /* Wait for resume sentinel: main thread stays paused, socket thread runs freely */
        const char *sentinel = "/data/local/tmp/.dexbgd_resume";
        unlink(sentinel); /* clear any stale sentinel */
        printf("[inject] Main thread paused. Agent socket thread is running.\n");
        printf("[inject] 1. Connect TUI and set breakpoints\n");
        printf("[inject] 2. Then run:  adb shell su -c 'touch %s'\n", sentinel);
        fflush(stdout);
        while (access(sentinel, F_OK) != 0)
            usleep(200000); /* poll every 200 ms */
        unlink(sentinel);
        printf("[inject] Resume sentinel received.\n");
    } else {
        fprintf(stderr, "[inject] dlopen returned NULL\n");
        fprintf(stderr, "[inject] check: adb logcat -s ArtJitTracer,linker\n");
        result = 1;
    }

restore:
    /* Detach any threads frozen via PTRACE_O_TRACECLONE.
     * They start running after detach; by then TracerPid = 0 so
     * anti-tamper checks see a clean process. */
    for (int i = 0; i < nfrozen; i++)
        ptrace(PTRACE_DETACH, frozen[i], 0, 0);

    /* Restore trampoline page word (if patched) */
    if (trampoline_patched)
        restore_insn(pid, trampoline, saved_trampoline_word);
    /* Trampoline page itself is leaked (4 KB) -- acceptable for a debug tool */

    /* Restore patched code word at saved_pc (fallback / error paths) */
    if (brk_patched)
        restore_insn(pid, saved.pc, orig_code_word);

    /* Restore stack scratch */
    if (scratch)
        mem_write(pid, scratch, backup, so_len < SCRATCH_SZ ? so_len : SCRATCH_SZ);

    /* Restore registers (PC goes back to saved_pc, instruction restored above) */
    iov.iov_base = &saved; iov.iov_len = sizeof(saved);
    ptrace(PTRACE_SETREGSET, pid, (void *)(long)NT_PRSTATUS, &iov);

    ptrace(PTRACE_DETACH, pid, 0, 0);
    printf("[inject] detached, process resumed\n");
    return result;
}
