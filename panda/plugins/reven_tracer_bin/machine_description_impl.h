#include <panda/plugin.h>
#include <panda/plugin_plugin.h>

#include "custom_cpu_context.h"

// This method is a copy/paste of void helper_rdmsr(CPUX86State *env) from misc_helper.c
// Notable modifications, useful for maintenance:
// - `env` is a `CPUX86State_CPPversion`, because we're in a cpp file
// - every instance of `(uint32_t)env->regs[R_ECX]` is replaced with the template parameter `MsrIndex`
//     Using a template instead of a regular parameter allows the compiler to heavily optimize the call + switch case
//     into basically a direct access to the underlying structure. This allows to keep the code as close as possible
//     to the original version(easier to maintain) while still having performance close to what we could get if we
//     manually mapped every msr index to a structure member, the latter being harder to get right and maintain.
// - we return `val` instead of changing the context.
// - removed call to `cpu_svm_check_intercept_param`, which is empty if compiling with CONFIG_USER_ONLY
template<std::uint32_t MsrIndex>
std::uint64_t read_msr(CPUX86State_CPPversion* env)
{
    uint64_t val;

    switch (MsrIndex) {
    case MSR_IA32_SYSENTER_CS:
        val = env->sysenter_cs;
        break;
    case MSR_IA32_SYSENTER_ESP:
        val = env->sysenter_esp;
        break;
    case MSR_IA32_SYSENTER_EIP:
        val = env->sysenter_eip;
        break;
    case MSR_IA32_APICBASE:
        val = cpu_get_apic_base(x86_env_get_cpu(reinterpret_cast<CPUX86State*>(env))->apic_state);
        break;
    case MSR_EFER:
        val = env->efer;
        break;
    case MSR_STAR:
        val = env->star;
        break;
    case MSR_PAT:
        val = env->pat;
        break;
    case MSR_VM_HSAVE_PA:
        val = env->vm_hsave;
        break;
    case MSR_IA32_PERF_STATUS:
        /* tsc_increment_by_tick */
        val = 1000ULL;
        /* CPU multiplier */
        val |= (((uint64_t)4ULL) << 40);
        break;
#ifdef TARGET_X86_64
    case MSR_LSTAR:
        val = env->lstar;
        break;
    case MSR_CSTAR:
        val = env->cstar;
        break;
    case MSR_FMASK:
        val = env->fmask;
        break;
    case MSR_FSBASE:
        val = env->segs[R_FS].base;
        break;
    case MSR_GSBASE:
        val = env->segs[R_GS].base;
        break;
    case MSR_KERNELGSBASE:
        val = env->kernelgsbase;
        break;
    case MSR_TSC_AUX:
        val = env->tsc_aux;
        break;
#endif
    case MSR_MTRRphysBase(0):
    case MSR_MTRRphysBase(1):
    case MSR_MTRRphysBase(2):
    case MSR_MTRRphysBase(3):
    case MSR_MTRRphysBase(4):
    case MSR_MTRRphysBase(5):
    case MSR_MTRRphysBase(6):
    case MSR_MTRRphysBase(7):
		val = env->mtrr_var[(MsrIndex - MSR_MTRRphysBase(0)) / 2].base;
		break;
    case MSR_MTRRphysMask(0):
	case MSR_MTRRphysMask(1):
	case MSR_MTRRphysMask(2):
	case MSR_MTRRphysMask(3):
	case MSR_MTRRphysMask(4):
	case MSR_MTRRphysMask(5):
	case MSR_MTRRphysMask(6):
	case MSR_MTRRphysMask(7):
		val = env->mtrr_var[(MsrIndex - MSR_MTRRphysMask(0)) / 2].mask;
		break;
	case MSR_MTRRfix64K_00000:
		val = env->mtrr_fixed[0];
		break;
	case MSR_MTRRfix16K_80000:
	case MSR_MTRRfix16K_A0000:
		val = env->mtrr_fixed[MsrIndex - MSR_MTRRfix16K_80000 + 1];
		break;
	case MSR_MTRRfix4K_C0000:
	case MSR_MTRRfix4K_C8000:
	case MSR_MTRRfix4K_D0000:
	case MSR_MTRRfix4K_D8000:
	case MSR_MTRRfix4K_E0000:
	case MSR_MTRRfix4K_E8000:
	case MSR_MTRRfix4K_F0000:
	case MSR_MTRRfix4K_F8000:
		val = env->mtrr_fixed[MsrIndex - MSR_MTRRfix4K_C0000 + 3];
		break;
	case MSR_MTRRdefType:
		val = env->mtrr_deftype;
		break;
	case MSR_MTRRcap:
		if (env->features[FEAT_1_EDX] & CPUID_MTRR) {
			val = MSR_MTRRcap_VCNT | MSR_MTRRcap_FIXRANGE_SUPPORT | MSR_MTRRcap_WC_SUPPORTED;
		} else {
			/* XXX: exception? */
			val = 0;
		}
		break;
	case MSR_MCG_CAP:
		val = env->mcg_cap;
		break;
	case MSR_MCG_CTL:
		if (env->mcg_cap & MCG_CTL_P) {
			val = env->mcg_ctl;
		} else {
			val = 0;
		}
		break;
	case MSR_MCG_STATUS:
		val = env->mcg_status;
		break;
	case MSR_IA32_MISC_ENABLE:
		val = env->msr_ia32_misc_enable;
		break;
	case MSR_IA32_BNDCFGS:
		val = env->msr_bndcfgs;
		break;
	default:
		if (MsrIndex >= MSR_MC0_CTL && MsrIndex < MSR_MC0_CTL + (4 * env->mcg_cap & 0xff)) {
			uint32_t offset = MsrIndex - MSR_MC0_CTL;
			val = env->mce_banks[offset];
			break;
		}
		/* XXX: exception? */
		val = 0;
		break;
	}

	return val;
}
