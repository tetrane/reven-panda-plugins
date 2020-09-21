#ifndef H_REVEN_TRACER_CPU_HELP
#define H_REVEN_TRACER_CPU_HELP

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct CPUX86State;
typedef struct CPUX86State CPUX86State;

struct X86CPU;
typedef struct X86CPU X86CPU;

uint64_t cpu_get_apic_base_cpu(X86CPU *cpu);
uint8_t cpu_get_apic_tpr_cpu(X86CPU *cpu);
uint32_t cpu_get_phys_bits_cpu(const X86CPU *cpu);

#ifdef __cplusplus
}
#endif

#endif // H_REVEN_TRACER_CPU_HELP
