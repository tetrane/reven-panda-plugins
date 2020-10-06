#include "machine_description.h"

#include <cstdint>
#include <iostream>

#include <boost/icl/interval_set.hpp>

#include <panda/plugin.h>
#include <panda/plugin_plugin.h>

#include "custom_cpu_context.h"

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

void get_all_panda_memory_regions(boost::icl::interval_set<std::uint64_t>& region_intervals, MemoryRegion *region) {
	auto mr_size = int128_getlo(region->size);
	// The memory regions size is working like that:
	//    - If the low 64 bits are 0 and the high 64 bits are equal to 1 it means that the region is taking the entire address space
	//    - If the low 64 bits aren't 0, the high 64 bits is 0 and the low 64 bits are the size of the region
	// We can ignore the region taking the entire address space as they are always split in subregions
	if (!int128_gethi(region->size) && mr_size > 0) {
		// The address is relative to the parent region.
		// To compute the real address of the region we can just add it to all its parent addresses.
		hwaddr mr_addr = 0;
		for (MemoryRegion *mr = region; mr; mr = mr->container) {
			mr_addr += mr->addr;
		}

		region_intervals.insert({mr_addr, mr_addr + mr_size});
	}

	MemoryRegion *submr;
	QTAILQ_FOREACH(submr, &region->subregions, subregions_link) {
		get_all_panda_memory_regions(region_intervals, submr);
	}
}

std::vector<MachineDescription::MemoryRegion> compute_panda_memory_regions()
{
	boost::icl::interval_set<std::uint64_t> region_intervals = {};

	get_all_panda_memory_regions(region_intervals, get_system_memory());
	get_all_panda_memory_regions(region_intervals, get_system_io());

	// rvnbintrace won't be happy with regions with size < TARGET_PAGE_SIZE
	for (auto it = region_intervals.begin(); it != region_intervals.end(); it++) {
		if (it->upper() - it->lower() < TARGET_PAGE_SIZE) {
			// When a region is smaller than TARGET_PAGE_SIZE we should be sure that it's a MMIO region before
			// resizing it to TARGET_PAGE_SIZE as we don't want to go out-of-bound when reading the RAM.
			uint8_t buf[1] = {0};
			if (panda_physical_memory_rw(it->lower(), buf, 1, false) == 0) {
				std::cout
					<< "Warning: Memory region (0x"
					<< std::hex << it->lower() << " -> 0x" << it->upper()
					<< ") is smaller than a page and is not a MMIO region." << std::endl;
			}

			region_intervals.insert({it->lower(), it->lower() + TARGET_PAGE_SIZE});
		}
	}

	std::vector<MachineDescription::MemoryRegion> regions = {};
	for (auto it = region_intervals.begin(); it != region_intervals.end(); it++) {
		regions.push_back({it->lower(), it->upper() - it->lower()});
	}

	return regions;
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
	desc.physical_address_size = cpu_get_phys_bits_cpu(cpu) / 8 + (cpu_get_phys_bits_cpu(cpu) % 8 ? 1 : 0);

	desc.static_registers["cpuid_pat"] = value_to_buffer<std::uint8_t>(state->features[FEAT_1_EDX] & CPUID_PAT ? 1 : 0);
	desc.static_registers["cpuid_pse36"] =
	  value_to_buffer<std::uint8_t>(state->features[FEAT_1_EDX] & CPUID_PSE36 ? 1 : 0);
	desc.static_registers["cpuid_1gb_pages"] =
	  value_to_buffer<std::uint8_t>(state->features[FEAT_8000_0001_EDX] & CPUID_EXT2_PDPE1GB ? 1 : 0);
	desc.static_registers["cpuid_max_phy_addr"] = value_to_buffer<std::uint8_t>(cpu_get_phys_bits_cpu(cpu));

	unsigned char linear_size;
	if (state->features[FEAT_7_0_ECX] & CPUID_7_0_ECX_LA57) {
		linear_size = 0x39; /* 57 bits virtual */
	}
	else {
		linear_size = 0x30; /* 48 bits virtual */
	}
	desc.static_registers["cpuid_max_lin_addr"] = value_to_buffer<std::uint8_t>(linear_size);

	desc.memory_regions = compute_panda_memory_regions();

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
