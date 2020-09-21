#include "cpu_help.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <qemu/osdep.h>
#include <hw/i386/apic.h>
#include <target/i386/cpu.h>

#ifdef __cplusplus
}
#endif


uint64_t cpu_get_apic_base_cpu(X86CPU *cpu)
{
	return cpu_get_apic_base(cpu->apic_state);
}

uint8_t cpu_get_apic_tpr_cpu(X86CPU *cpu)
{
	return cpu_get_apic_tpr(cpu->apic_state);
}

uint32_t cpu_get_phys_bits_cpu(const X86CPU *cpu)
{
	return cpu->phys_bits;
}
