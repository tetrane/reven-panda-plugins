#pragma once

#include <cstdint>

#include <rvnbintrace/trace_sections.h>

using namespace reven::backend::plugins::file::libbintrace;

struct CPUState;
struct SegmentCache;
struct CPUX86State_CPPversion;

#define REGISTER(register, size) r_##register,
#define REGISTER_CTX(register, size, ctx) r_##register,
#define REGISTER_MSR(register, index) r_##register,
enum x86Register {
	#include "registers_priority.inc"
	register_priority_enum_count,
	register_enum_count_reset = register_priority_enum_count - 1, // to reset enum counting, do not use
	#include "registers_others.inc"
	register_enum_count,
};
#undef REGISTER
#undef REGISTER_CTX
#undef REGISTER_MSR

const std::string& exception_event_description(int32_t vector);

void initialize_register_maps();
RegisterId reg_id(x86Register reg_name);
std::uint16_t reg_size(x86Register reg_name);
const std::string& reg_name(x86Register reg_name);
std::uint64_t compute_segment(const SegmentCache& segment);

// be careful when reading MSR_IA32_APICBASE through this variant, ensure you have a legit CPUX86State
template<std::uint32_t MsrIndex>
std::uint64_t read_msr(CPUX86State_CPPversion* env);

MachineDescription x64_machine_description(CPUState* cs);

enum RegisterOperationId {
	RegisterOperationRipPlus1,
	RegisterOperationRipPlus2,
	RegisterOperationRipPlus3,
	RegisterOperationRipPlus4,
	RegisterOperationRipPlus5,
	RegisterOperationRipPlus6,
	RegisterOperationRipPlus7,
	RegisterOperationRipPlus8,
	RegisterOperationRipPlus9,
	RegisterOperationRipPlus10,
	RegisterOperationRipPlus11,
	RegisterOperationRipPlus12,
	RegisterOperationRipPlus13,
	RegisterOperationRipPlus14,
	RegisterOperationRipPlus15,

	RegisterOperationFlagSetCf,
	RegisterOperationFlagSetPf,
	RegisterOperationFlagSetAf,
	RegisterOperationFlagSetZf,
	RegisterOperationFlagSetSf,
	RegisterOperationFlagSetTf,
	RegisterOperationFlagSetIf,
	RegisterOperationFlagSetDf,
	RegisterOperationFlagSetOf,

	RegisterOperationFlagUnsetCf,
	RegisterOperationFlagUnsetPf,
	RegisterOperationFlagUnsetAf,
	RegisterOperationFlagUnsetZf,
	RegisterOperationFlagUnsetSf,
	RegisterOperationFlagUnsetTf,
	RegisterOperationFlagUnsetIf,
	RegisterOperationFlagUnsetDf,
	RegisterOperationFlagUnsetOf,

	RegisterOperationRspPlus2,
	RegisterOperationRspPlus4,
	RegisterOperationRspPlus8,
	RegisterOperationRspPlus16,
	RegisterOperationRspMinus2,
	RegisterOperationRspMinus4,
	RegisterOperationRspMinus8,
	RegisterOperationRspMinus16,

	RegisterOperationIdLast
};

const std::vector<std::uint8_t> eflags_bits = { 0, 2, 4, 6, 7, 8, 9, 10, 11 };
extern std::vector<RegisterId> register_action_ids;

#include "machine_description_impl.h"
