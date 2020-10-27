/**
 * An example how to use XSAVE to dump the state of the FPU and extended
 * registers into buffers, and print a variable.
 *
 * To the extent possible under law, Moritz Systems has waived all
 * copyright and related or neighboring rights to this work.
 */

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

struct xsave {
    uint8_t legacy_area[512];
    union {
        struct {
            uint64_t xstate_bv;
            uint64_t xcomp_bv;
        };
        uint8_t header_area[64];
    };
    uint8_t extended_area[];
};

int main() {
    uint32_t buf_size = 0;
    uint32_t avx_offset = 0;
    uint8_t avx_bytes[32];
    struct xsave* buf[3];
    int i;
    for (i = 0; i < sizeof(avx_bytes); ++i)
        avx_bytes[i] = i;

    __asm__ __volatile__ (
        /* check CPUID support for XSAVE and AVX */
        "mov $0x01, %%eax\n\t"
        "cpuid\n\t"
        "mov $0x04000000, %%eax\n\t"  /* bit 26 - XSAVE */
        "and %%ecx, %%eax\n\t"
        "jz .cpuid_end\n\t"
        "mov $0x10000000, %%eax\n\t"  /* bit 28 - AVX */
        "and %%ecx, %%eax\n\t"
        "jz .no_avx\n\t"
        /* get AVX offset */
        "mov $0x0d, %%eax\n\t"
        "mov $0x02, %%ecx\n\t"
        "cpuid\n\t"
        "mov %%ebx, %1\n\t"
        "\n"
        ".no_avx:\n\t"
        /* get XSAVE area size for current XCR0 */
        "mov $0x0d, %%eax\n\t"
        "xor %%ecx, %%ecx\n\t"
        "cpuid\n\t"
        "mov %%ebx, %0\n\t"
        "\n"
        ".cpuid_end:\n\t"
        : "=m"(buf_size), "=m"(avx_offset)
        :
        : "%eax", "%ebx", "%ecx", "%edx"
    );

    if (buf_size == 0) {
        printf("no xsave support\n");
        return 1;
    }

    printf("has avx: %s\n", avx_offset != 0 ? "yes" : "no");
    printf("xsave area size: %d bytes\n", buf_size);

    for (i = 0; i < 3; ++i) {
        buf[i] = aligned_alloc(64, buf_size);
        assert(buf[i]);
    }

    __asm__ __volatile__ (
        "mov $0x07, %%eax\n\t"
        "xor %%edx, %%edx\n\t"
        "xsave (%0)\n\t"
        "movd %%eax, %%mm0\n\t"
        "xsave (%1)\n\t"
        "and %3, %3\n\t"
        "jz .xsave_end\n\t"
        "vmovups (%3), %%ymm0\n\t"
        "xsave (%2)\n\t"
        "\n"
        ".xsave_end:\n\t"
        :
        : "r"(buf[0]), "r"(buf[1]), "r"(buf[2]),
          "c"(avx_offset != 0 ? avx_bytes : 0)
        : "%eax", "%edx", "%mm0", "%ymm0", "memory"
    );

    printf("XSTATE_BV (initial): %#018" PRIx64 "\n",
           buf[0]->xstate_bv);
    printf("XSTATE_BV (with MMX): %#018" PRIx64 "\n",
           buf[1]->xstate_bv);
    if (avx_offset != 0) {
        printf("XSTATE_BV (with AVX): %#018" PRIx64 "\n",
               buf[2]->xstate_bv);
        printf("YMM0 most significant quadword: %#018" PRIx64 "\n",
               *((uint64_t*)(((char*)buf[2]) + avx_offset)));
    }

    for (i = 0; i < 3; ++i)
        free(buf[i]);
    return 0;
}
