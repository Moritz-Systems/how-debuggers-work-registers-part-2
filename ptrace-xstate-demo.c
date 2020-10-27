/**
 * An example how to get and set registers via PT_{G,S}ETXSTATE requests
 * on FreeBSD, NetBSD and Linux.
 *
 * To the extent possible under law, Moritz Systems has waived all
 * copyright and related or neighboring rights to this work.
 */

#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/wait.h>

#if defined(__NetBSD__)
#   include <x86/cpu_extended_state.h>
#   include <x86/specialreg.h>
#elif defined(__FreeBSD__)
#   include <x86/fpu.h>
#   include <x86/specialreg.h>
#elif defined(__linux__)
#   include <linux/elf.h>
#else
#   error "unsupported platform"
#endif

#include <assert.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include <cpuid.h>

void print_ymm(const char* name,
               uint8_t xmm[16],
               uint8_t ymm_hi[16]) {
    int i;
    printf("%20s: {", name);
    for (i = 0; i < 16; ++i)
        printf(" 0x%02x", xmm[i]);
    for (i = 0; i < 16; ++i)
        printf(" 0x%02x", ymm_hi[i]);
    printf(" }\n");
}

int main() {
    /* verify that AVX is supported */
    uint32_t eax, ebx, ecx, edx;
    if (!__get_cpuid(0x01, &eax, &ebx, &ecx, &edx) ||
            !(ecx & bit_AVX)) {
        printf("AVX not supported\n");
        return 1;
    }

#if !defined(__NetBSD__)
    /* get the YMM offset for systems using the raw XSAVE Area */
    assert (__get_cpuid_count(0x0d, 0x02, &eax, &ebx, &ecx, &edx));
    uint32_t avx_offset = ebx;
#endif
#if defined(__linux__)
    /* get the size of the XSAVE Area */
    assert (__get_cpuid_count(0x0d, 0x00, &eax, &ebx, &ecx, &edx));
    uint32_t xsave_size = ebx;
#endif

    int ret;
    pid_t pid = fork();
    assert(pid != -1);

    if (pid == 0) {
        /* child -- debugged program */
        uint8_t avx_bytes[32];
        int i;
        for (i = 0; i < sizeof(avx_bytes); ++i)
            avx_bytes[i] = i;

        /* request tracing */
#if !defined(__linux__)
        ret = ptrace(PT_TRACE_ME, 0, NULL, 0);
#else
        ret = ptrace(PTRACE_TRACEME, 0, NULL, 0);
#endif
        assert(ret != -1);

        print_ymm("in child, initial", avx_bytes, avx_bytes+16);

        __asm__ __volatile__ (
            "vmovups (%0), %%ymm0\n\t"
            "int3\n\t"
            "vmovups %%ymm0, (%0)\n\t"
            :
            : "b"(avx_bytes)
            : "%ymm0", "memory"
        );

        print_ymm("in child, modified", avx_bytes, avx_bytes+16);

        _exit(0);
    }

    /* parent -- the debugger */
    /* wait for the child to become ready for tracing */
    pid_t waited = waitpid(pid, &ret, 0);
    assert(waited == pid);
    assert(WIFSTOPPED(ret));
    assert(WSTOPSIG(ret) == SIGTRAP);

    /* get registers */
#if defined(__NetBSD__)
    struct xstate xst;
    struct iovec iov = { &xst, sizeof(xst) };
    ret = ptrace(PT_GETXSTATE, pid, &iov, 0);
#elif defined(__FreeBSD__)
    struct ptrace_xstate_info info;
    ret = ptrace(PT_GETXSTATE_INFO, pid,
                 (caddr_t)&info, sizeof(info));
    assert(ret == 0);

    char buf[info.xsave_len];
    ret = ptrace(PT_GETXSTATE, pid, buf, sizeof(buf));
#elif defined(__linux__)
    char buf[xsave_size];
    struct iovec iov = { buf, sizeof(buf) };
    ret = ptrace(PTRACE_GETREGSET, pid, NT_X86_XSTATE, &iov);
#endif
    assert(ret == 0);

    /* SSE+AVX registers should have been requested */
#if defined(__NetBSD__)
    assert(xst.xs_rfbm & XCR0_SSE);
    assert(xst.xs_rfbm & XCR0_YMM_Hi128);
#elif defined(__FreeBSD__)
    assert(info.xsave_mask & XFEATURE_ENABLED_SSE);
    assert(info.xsave_mask & XFEATURE_ENABLED_YMM_HI128);
#endif

    /* SSE+AVX registers should be in modified state */
#if defined(__NetBSD__)
    assert(xst.xs_xstate_bv & XCR0_SSE);
    assert(xst.xs_xstate_bv & XCR0_YMM_Hi128);
#elif defined(__FreeBSD__)
    struct xstate_hdr* xst = (struct xstate_hdr*)&buf[512];
    assert(xst->xstate_bv & XFEATURE_ENABLED_SSE);
    assert(xst->xstate_bv & XFEATURE_ENABLED_YMM_HI128);
#elif defined(__linux__)
    uint64_t xstate_bv = *((uint64_t*)&buf[512]);
    assert(xstate_bv & 2); /* SSE */
    assert(xstate_bv & 4); /* YMM_Hi128 */
#endif

#if defined(__NetBSD__)
    uint8_t* xmm = xst.xs_fxsave.fx_xmm[0].xmm_bytes;
    uint8_t* ymm_hi = xst.xs_ymm_hi128.xs_ymm[0].ymm_bytes;
#elif defined(__FreeBSD__)
    uint8_t* xmm =
        ((struct savexmm*)buf)->sv_xmm[0].xmm_bytes;
    uint8_t* ymm_hi =
        ((struct ymmacc*)&buf[avx_offset])[0].ymm_bytes;
#elif defined(__linux__)
    uint8_t* xmm = &buf[160];
    uint8_t* ymm_hi = &buf[avx_offset];
#endif

    print_ymm("from PT_GETXSTATE", xmm, ymm_hi);
    int i;
    for (i = 0; i < 16; ++i) {
        xmm[i] += 0x80;
        ymm_hi[i] += 0x80;
    }
    print_ymm("set via PT_SETXSTATE", xmm, ymm_hi);

    /* update the registers and resume the program */
#if defined(__NetBSD__)
    ret = ptrace(PT_SETXSTATE, pid, &iov, 0);
#elif defined(__FreeBSD__)
    ret = ptrace(PT_SETXSTATE, pid, buf, sizeof(buf));
#elif defined(__linux__)
    ret = ptrace(PTRACE_SETREGSET, pid, NT_X86_XSTATE, &iov);
#endif
    assert(ret == 0);
    ret = ptrace(PT_CONTINUE, pid, (void*)1, 0);
    assert(ret == 0);

    /* wait for the child to exit */
    waited = waitpid(pid, &ret, 0);
    assert(waited == pid);
    assert(WIFEXITED(ret));
    assert(WEXITSTATUS(ret) == 0);

    return 0;
}
