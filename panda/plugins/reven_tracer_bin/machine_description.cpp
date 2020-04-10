#include "machine_description.h"

#include <cstdint>

#include <panda/plugin.h>
#include <panda/plugin_plugin.h>

#include "custom_cpu_context.h"

#include "../reven_common/vga_help.h"

namespace {

static std::vector<RegisterId> register_ids;
static std::vector<std::uint16_t> register_sizes;
static std::vector<std::string> register_names;

template <typename T>
static std::vector<std::uint8_t> value_to_buffer(const T& value)
{
	const auto buffer = reinterpret_cast<const std::uint8_t*>(&value);
	return {buffer, buffer + sizeof(T)};
}

}

std::vector<RegisterId> register_action_ids;

RegisterId reg_id(x86Register reg_name)
{
	return register_ids.at(reg_name);
}

std::uint16_t reg_size(x86Register reg_name)
{
	return register_sizes.at(reg_name);
}

const std::string& reg_name(x86Register reg_name)
{
	return register_names.at(reg_name);
}

void initialize_register_maps()
{
	RegisterId next_id = 0;
	char msr_name[255];

	register_ids.resize(register_enum_count);
	register_sizes.resize(register_enum_count);
	register_names.resize(register_enum_count);

	#define REGISTER(register, size)            \
	register_sizes[r_##register] = size;        \
	register_ids[r_##register] = next_id++;     \
	register_names[r_##register] = #register;
	#define REGISTER_CTX(register, size, ctx)   \
	register_sizes[r_##register] = size;        \
	register_ids[r_##register] = next_id++;     \
	register_names[r_##register] = #register;
	#define REGISTER_MSR(register, index)       \
	register_sizes[r_##register] = 8;           \
	register_ids[r_##register] = next_id++;     \
	sprintf(msr_name, "msr_%.8x", (index));     \
	register_names[r_##register] = std::string(msr_name);
	#include "registers_priority.inc"
	#undef REGISTER
	#undef REGISTER_CTX
	#undef REGISTER_MSR

	next_id += RegisterOperationIdLast;

	#define REGISTER(register, size)            \
	register_sizes[r_##register] = size;        \
	register_ids[r_##register] = next_id++;     \
	register_names[r_##register] = #register;
	#define REGISTER_CTX(register, size, ctx)   \
	register_sizes[r_##register] = size;        \
	register_ids[r_##register] = next_id++;     \
	register_names[r_##register] = #register;
	#define REGISTER_MSR(register, index)       \
	register_sizes[r_##register] = 8;           \
	register_ids[r_##register] = next_id++;     \
	sprintf(msr_name, "msr_%.8x", (index));     \
	register_names[r_##register] = std::string(msr_name);
	#include "registers_others.inc"
	#undef REGISTER
	#undef REGISTER_CTX
	#undef REGISTER_MSR
}

MachineDescription x64_machine_description(CPUState* cs)
{
	MachineDescription desc;

	desc.architecture = MachineDescription::Archi::x64_1;
	desc.physical_address_size = 6;

	RegisterId next_id = 0;

	for (std::size_t i = 0; i < register_priority_enum_count; ++i) {
		auto reg = static_cast<x86Register>(i);
		desc.registers.insert(std::make_pair(next_id++, MachineDescription::Register({reg_size(reg), reg_name(reg)})));
	}

	//////
	// Register action definitions
	// /!\ Order must match RegisterOperationId!!!
	// RIP movement
	for (std::uint64_t i = 0; i < 15; ++i) {
		register_action_ids.push_back(next_id);

		desc.register_operations.insert(std::make_pair(
		  next_id++, MachineDescription::RegisterOperation{ reg_id(r_rip), MachineDescription::RegisterOperator::Add,
		                                                 value_to_buffer<std::uint64_t>(i + 1) }));
	}

	// Eflag bit operations
	for (auto bit : eflags_bits) {
		register_action_ids.push_back(next_id);
		desc.register_operations.insert(std::make_pair(
		  next_id++, MachineDescription::RegisterOperation{ reg_id(r_eflags), MachineDescription::RegisterOperator::Or,
		                                                 value_to_buffer<std::uint32_t>(1u << bit) }));
	}
	for (auto bit : eflags_bits) {
		register_action_ids.push_back(next_id);
		desc.register_operations.insert(std::make_pair(
		  next_id++, MachineDescription::RegisterOperation{ reg_id(r_eflags), MachineDescription::RegisterOperator::And,
		                                                 value_to_buffer<std::uint32_t>(0xffffffffu ^ (1u << bit)) }));
	}

	// RSP mouvement
	for (std::uint64_t i = 2; i <= 16; i = i*2) {
		register_action_ids.push_back(next_id);
		desc.register_operations.insert(std::make_pair(
		  next_id++, MachineDescription::RegisterOperation{ reg_id(r_rsp), MachineDescription::RegisterOperator::Add,
		                                                 value_to_buffer<std::uint64_t>(i) }));
	}
	for (std::uint64_t i = 2; i <= 16; i = i*2) {
		register_action_ids.push_back(next_id);
		desc.register_operations.insert(std::make_pair(
		  next_id++, MachineDescription::RegisterOperation{ reg_id(r_rsp), MachineDescription::RegisterOperator::Add,
		                                                 value_to_buffer<std::uint64_t>(-i) }));
	}

	if (register_action_ids.size() != RegisterOperationIdLast)
		throw std::logic_error("Too few register actions defined");

	for (std::size_t i = register_priority_enum_count; i < register_enum_count; ++i) {
		auto reg = static_cast<x86Register>(i);
		desc.registers.insert(std::make_pair(next_id++, MachineDescription::Register({reg_size(reg), reg_name(reg)})));
	}

	const X86CPU* cpu = X86_CPU(cs);
	auto state = get_cpu_state(cs);
	desc.physical_address_size = cpu->phys_bits / 8 + (cpu->phys_bits % 8 ? 1 : 0);

	desc.static_registers["cpuid_pat"] = value_to_buffer<std::uint8_t>(state->features[FEAT_1_EDX] & CPUID_PAT ? 1 : 0);
	desc.static_registers["cpuid_pse36"] =
	  value_to_buffer<std::uint8_t>(state->features[FEAT_1_EDX] & CPUID_PSE36 ? 1 : 0);
	desc.static_registers["cpuid_1gb_pages"] =
	  value_to_buffer<std::uint8_t>(state->features[FEAT_8000_0001_EDX] & CPUID_EXT2_PDPE1GB ? 1 : 0);
	desc.static_registers["cpuid_max_phy_addr"] = value_to_buffer<std::uint8_t>(cpu->phys_bits);

	unsigned char linear_size;
	if (state->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_LA57) {
		linear_size = 0x39; /* 57 bits virtual */
	}
	else {
		linear_size = 0x30; /* 48 bits virtual */
	}
	desc.static_registers["cpuid_max_lin_addr"] = value_to_buffer<std::uint8_t>(linear_size);

	// Memory regions:
	// First, RAM
	desc.memory_regions.push_back({ 0, ram_size });

	// Then VGA framebuffer
	VGAInfo info;
	if (get_vga_info(&info)) {
		desc.memory_regions.push_back({ info.fb_address, info.fb_size });
	}

	return desc;
}

const std::string& exception_event_description(int32_t vector)
{
	static const std::string string_divide("divide error");
	static const std::string string_debug("debug");
	static const std::string string_nmi("nmi interrupt");
	static const std::string string_breakpoint("breakpoint");
	static const std::string string_overflow("overflow");
	static const std::string string_bound("bound range exceeded");
	static const std::string string_invalid_opcode("invalid opcode");
	static const std::string string_device("device not available");
	static const std::string string_double("double fault");
	static const std::string string_coprocessor("coprocessor segment overrun");
	static const std::string string_invalid_tss("invalid tss");
	static const std::string string_segment("segment not present");
	static const std::string string_stack("stack segment fault");
	static const std::string string_general("general protection");
	static const std::string string_page("page fault");
	static const std::string string_floating("floating-point error");
	static const std::string string_alignment("alignment check");
	static const std::string string_machine("machine check");
	static const std::string string_unknown("unknown exception");

	switch (vector) {
		case EXCP00_DIVZ:
			return string_divide;
		case EXCP01_DB:
			return string_debug;
		case EXCP02_NMI:
			return string_nmi;
		case EXCP03_INT3:
			return string_breakpoint;
		case EXCP04_INTO:
			return string_overflow;
		case EXCP05_BOUND:
			return string_bound;
		case EXCP06_ILLOP:
			return string_invalid_opcode;
		case EXCP07_PREX:
			return string_device;
		case EXCP08_DBLE:
			return string_double;
		case EXCP09_XERR:
			return string_coprocessor;
		case EXCP0A_TSS:
			return string_invalid_tss;
		case EXCP0B_NOSEG:
			return string_segment;
		case EXCP0C_STACK:
			return string_stack;
		case EXCP0D_GPF:
			return string_general;
		case EXCP0E_PAGE:
			return string_page;
		case EXCP10_COPR:
			return string_floating;
		case EXCP11_ALGN:
			return string_alignment;
		case EXCP12_MCHK:
			return string_machine;
	}
	return string_unknown;
}

std::uint64_t compute_segment(const SegmentCache& segment)
{
	std::uint64_t shadow = 0;
	shadow  = (segment.flags      & 0x00f0ff00);
	shadow |= (segment.limit      & 0x000f0000);
	shadow |= (segment.base >> 16 & 0x000000ff);
	shadow |= (segment.base       & 0xff000000);
	shadow <<= 32;
	shadow |= (segment.limit      & 0x0000ffff);
	shadow |= (segment.base << 16 & 0xffff0000);

	return shadow;
}
