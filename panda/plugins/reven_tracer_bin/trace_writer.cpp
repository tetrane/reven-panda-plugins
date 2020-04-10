#include "trace_writer.h"

#include <memory>
#include <cstring>

#include <panda/plugin_plugin.h>

#include "common.h"
#include "machine_description.h"
#include "custom_cpu_context.h"

namespace {

#if defined(TARGET_X86_64)
static CPUX86State_CPPversion comparison_state;
static uint16_t comparison_fpu_tag;
static target_ulong comparison_rip;
static std::uint64_t comparison_msr_apicbase;
static std::uint64_t comparison_cr8;

static uint32_t no_action_eflags_bits;
#endif

template <typename T>
inline void write_reg(InitialRegistersSectionWriter& writer, x86Register reg, std::uint64_t size, const T& value)
{
	if (size > sizeof(T)) {
		printf("reg %s's size %lu is > of passed value type %lu\n", reg_name(reg).c_str(), size, sizeof(T));
	}

	writer.write(reg_id(reg), reinterpret_cast<const std::uint8_t*>(&value), size);
}

template <typename T>
inline void write_reg(EventsSectionWriter& writer, x86Register reg, std::uint64_t size, const T& value, T& comparison_value)
{
	if (size > sizeof(T)) {
		printf("reg %s's size %lu is > from passed value type %lu\n", reg_name(reg).c_str(), size, sizeof(T));
	}

	if (value == comparison_value)
		return;
	comparison_value = value;

	writer.write_register(reg_id(reg), reinterpret_cast<const std::uint8_t*>(&value), size);
}

template <>
inline void write_reg<ZMMReg>(EventsSectionWriter& writer, x86Register reg, std::uint64_t size, const ZMMReg& value, ZMMReg& comparison_value)
{
	if (size > sizeof(ZMMReg)) {
		printf("reg %s's size %lu is > from passed value type %lu\n", reg_name(reg).c_str(), size, sizeof(ZMMReg));
	}

	if (std::memcmp(&value, &comparison_value, sizeof(ZMMReg)) == 0)
		return;
	std::memcpy(&comparison_value, &value, sizeof(ZMMReg));

	writer.write_register(reg_id(reg), reinterpret_cast<const std::uint8_t*>(&value), size);
}

template <>
inline void write_reg<FPReg>(EventsSectionWriter& writer, x86Register reg, std::uint64_t size, const FPReg& value, FPReg& comparison_value)
{
	if (value.d.high == comparison_value.d.high and value.d.low == comparison_value.d.low)
		return;
	comparison_value.d.high = value.d.high;
	comparison_value.d.low = value.d.low;

	writer.write_register(reg_id(reg), reinterpret_cast<const std::uint8_t*>(&value), size);
}

void write_segment_diff(EventsSectionWriter& writer, x86Register reg, std::uint8_t qemu_seg,
                        const CPUX86State_CPPversion& ctx, CPUX86State_CPPversion& old)
{
	if ((ctx.segs[qemu_seg].base != old.segs[qemu_seg].base) or
	    (ctx.segs[qemu_seg].limit != old.segs[qemu_seg].limit) or
	    (ctx.segs[qemu_seg].flags != old.segs[qemu_seg].flags)) {
		// Do not save selector yet, it is checked later on
		if (reg != r_gs_shadow and reg != r_fs_shadow) {
			// Save base except on GS and FS, because there are MSRs based on those same values
			old.segs[qemu_seg].base = ctx.segs[qemu_seg].base;
		}
		old.segs[qemu_seg].limit = ctx.segs[qemu_seg].limit;
		old.segs[qemu_seg].flags = ctx.segs[qemu_seg].flags;

		auto seg = compute_segment(ctx.segs[qemu_seg]);
		writer.write_register(reg_id(reg), reinterpret_cast<std::uint8_t*>(&seg), 8);
	}
}

}

PandaWriter::PandaWriter(const std::string& filename, const MachineDescription& desc)
  : TraceWriter(
    	std::make_unique<std::ofstream>(filename, std::ios::binary), desc,
    	tool_name,
    	tool_version,
    	tool_info
    )
{
}

void save_initial_memory(CPUState* /* cs */, const MachineDescription& machine, InitialMemorySectionWriter& writer)
{
#if defined(TARGET_X86_64)
	uint8_t mem_buf[TARGET_PAGE_SIZE];
	uint8_t zero_buf[TARGET_PAGE_SIZE];
	std::memset(zero_buf, 0, TARGET_PAGE_SIZE);

	for (const auto& region : machine.memory_regions) {
		for (ram_addr_t addr = region.start; addr < region.start + region.size; addr += TARGET_PAGE_SIZE) {
			auto size = std::min<std::size_t>(TARGET_PAGE_SIZE, region.start + region.size - addr);
			auto res = panda_physical_memory_rw(addr, mem_buf, size, 0);

			if (res == -1) { // I/O. Just fill page with zeroes.
				writer.write(zero_buf, size);
			} else {
				writer.write(mem_buf, size);
			}
		}
	}
#endif
}

void save_initial_registers(CPUState* cs, InitialRegistersSectionWriter& writer)
{
#if defined(TARGET_X86_64)
	auto state = get_cpu_state(cs);
	X86CPU* cpu = X86_CPU(cs);

	comparison_state = *state;

	comparison_rip = cs->panda_guest_pc;
	write_reg(writer, r_rip, 8, cs->panda_guest_pc);

	// Shadow segments
	write_reg(writer, r_cs_shadow, 8, compute_segment(state->segs[R_CS]));
	write_reg(writer, r_ds_shadow, 8, compute_segment(state->segs[R_DS]));
	write_reg(writer, r_es_shadow, 8, compute_segment(state->segs[R_ES]));
	write_reg(writer, r_ss_shadow, 8, compute_segment(state->segs[R_SS]));
	write_reg(writer, r_fs_shadow, 8, compute_segment(state->segs[R_FS]));
	write_reg(writer, r_gs_shadow, 8, compute_segment(state->segs[R_GS]));

	// Rsp will be special, too
	write_reg(writer, r_rsp, 8, state->regs[R_ESP]);
	comparison_state.regs[R_ESP] = state->regs[R_ESP];

	// Eflags needs special recomputation
	target_ulong eflags = cpu_compute_eflags(&X86_CPU(cs)->env);
	comparison_state.eflags = eflags;
	write_reg(writer, r_eflags, 4, eflags);

	no_action_eflags_bits = 0xffffffff;
	for (auto bit : eflags_bits) {
		no_action_eflags_bits ^= 1u << bit;
	}

	comparison_fpu_tag = compute_fpu_tags(cs);
	write_reg(writer, r_x87tags, 2, comparison_fpu_tag);

	// Special case: save it for later
	comparison_msr_apicbase = read_msr<MSR_IA32_APICBASE>(state);

	// CR8 is computed, not stored
	comparison_cr8 = cpu_get_apic_tpr(cpu->apic_state);
	write_reg(writer, r_cr8, 8, comparison_cr8);

    #define REGISTER(register, size)
	#define REGISTER_CTX(register, size, ctx) \
	write_reg(writer, r_##register, size, state->ctx);
	#define REGISTER_MSR(register, index) \
	write_reg(writer, r_##register, 8, read_msr<(index)>(state));
	#include "registers_priority.inc"
	#include "registers_others.inc"
	#undef REGISTER
	#undef REGISTER_CTX
	#undef REGISTER_MSR
#endif
}

void save_diff_registers(CPUState* cs, EventsSectionWriter& writer)
{
#if defined(TARGET_X86_64)
	auto state = get_cpu_state(cs);
	X86CPU* cpu = X86_CPU(cs);

	if ((cs->panda_guest_pc - comparison_rip) <= 15 and cs->panda_guest_pc != comparison_rip) {
		writer.write_register_action(
		  register_action_ids.at(RegisterOperationRipPlus1 - 1 + (cs->panda_guest_pc - comparison_rip)));
	} else {
		writer.write_register(reg_id(r_rip), reinterpret_cast<const std::uint8_t*>(&cs->panda_guest_pc), reg_size(r_rip));
	}
	comparison_rip = cs->panda_guest_pc;

	// Shadow segments
	write_segment_diff(writer, r_cs_shadow, R_CS, *state, comparison_state);
	write_segment_diff(writer, r_ds_shadow, R_DS, *state, comparison_state);
	write_segment_diff(writer, r_es_shadow, R_ES, *state, comparison_state);
	write_segment_diff(writer, r_ss_shadow, R_SS, *state, comparison_state);
	write_segment_diff(writer, r_fs_shadow, R_FS, *state, comparison_state);
	write_segment_diff(writer, r_gs_shadow, R_GS, *state, comparison_state);

	// Rsp action
	long int rsp_diff = state->regs[R_ESP] - comparison_state.regs[R_ESP];
	switch(rsp_diff) {
		case 0: break;
		case 2: writer.write_register_action(register_action_ids.at(RegisterOperationRspPlus2)); break;
		case 4: writer.write_register_action(register_action_ids.at(RegisterOperationRspPlus4)); break;
		case 8: writer.write_register_action(register_action_ids.at(RegisterOperationRspPlus8)); break;
		case 16: writer.write_register_action(register_action_ids.at(RegisterOperationRspPlus16)); break;
		case -2: writer.write_register_action(register_action_ids.at(RegisterOperationRspMinus2)); break;
		case -4: writer.write_register_action(register_action_ids.at(RegisterOperationRspMinus4)); break;
		case -8: writer.write_register_action(register_action_ids.at(RegisterOperationRspMinus8)); break;
		case -16: writer.write_register_action(register_action_ids.at(RegisterOperationRspMinus16)); break;
		default:
			writer.write_register(reg_id(r_rsp), reinterpret_cast<const std::uint8_t*>(&state->regs[R_ESP]),
			                      reg_size(r_rsp));
	}
	comparison_state.regs[R_ESP] = state->regs[R_ESP];

	// Eflags needs special recomputation
	target_ulong eflags = cpu_compute_eflags(&cpu->env);
	if (eflags != comparison_state.eflags) {
		if ((eflags & no_action_eflags_bits) != (comparison_state.eflags & no_action_eflags_bits)) {
			writer.write_register(reg_id(r_eflags), reinterpret_cast<const std::uint8_t*>(&eflags), reg_size(r_eflags));
		} else {
			int counter = 0;
			for (std::size_t i = 0; i < eflags_bits.size(); ++i) {
				std::uint32_t mask = 1u << eflags_bits[i];
				if ((eflags & mask) != (comparison_state.eflags & mask))
					counter++;
			}
			if (counter < 5) {
				for (std::size_t i = 0; i < eflags_bits.size(); ++i) {
					std::uint32_t mask = 1u << eflags_bits[i];

					if ((eflags & mask) != (comparison_state.eflags & mask)) {
						std::uint8_t action_base = eflags & mask ? RegisterOperationFlagSetCf : RegisterOperationFlagUnsetCf;
						writer.write_register_action(register_action_ids.at(action_base + i));
					}
				}
			} else {
				writer.write_register(reg_id(r_eflags), reinterpret_cast<const std::uint8_t*>(&eflags),
				                      reg_size(r_eflags));
			}
		}
		comparison_state.eflags = eflags;
	}

	// FPU tags
	write_reg(writer, r_x87tags, 2, compute_fpu_tags(cs), comparison_fpu_tag);

	// Special case for MSR apicbase which is not stored inside a CPUX86State_CPPversion, so not saved in comparison_state
	auto new_apicbase = read_msr<MSR_IA32_APICBASE>(state);
	if (new_apicbase != comparison_msr_apicbase) {
		comparison_msr_apicbase = new_apicbase;
		writer.write_register(reg_id(r_apicbase), reinterpret_cast<std::uint8_t*>(&new_apicbase), 8);
	}

	// CR8 is computed, not stored
	std::uint64_t new_cr8 = cpu_get_apic_tpr(cpu->apic_state);
	if (new_cr8 != comparison_cr8) {
		comparison_cr8 = new_cr8;
		writer.write_register(reg_id(r_cr8), reinterpret_cast<std::uint8_t*>(&new_cr8), 8);
	}

	// Regular registers
	bool msr_changed = false;
	#define REGISTER(register, size)
	#define REGISTER_CTX(register, size, ctx) \
	write_reg(writer, r_##register, size, state->ctx, comparison_state.ctx);
	#define REGISTER_MSR(register, index) \
	if (r_##register != r_apicbase) { \
		std::uint64_t new_msr = read_msr<index>(state); \
		if (new_msr != read_msr<index>(&comparison_state)) { \
			writer.write_register(reg_id(r_##register), reinterpret_cast<std::uint8_t*>(&new_msr), 8); \
			msr_changed = true; \
		} \
	}
	#include "registers_priority.inc"
	#include "registers_others.inc"
	#undef REGISTER
	#undef REGISTER_CTX
	#undef REGISTER_MSR

	// An MSR register has changed but we don't really know which one: copy entire context.
	if (msr_changed)
		std::memcpy(&comparison_state, state, sizeof(comparison_state));
#endif
}

uint16_t compute_fpu_tags(CPUState* cs)
{
	auto state = get_cpu_state(cs);
	uint16_t fpu_tag = 0x0;
	for (int i = 0; i < 8; i++) {
		fpu_tag |= ((!state->fptags[i]) << i);
	}

	return fpu_tag;
}
