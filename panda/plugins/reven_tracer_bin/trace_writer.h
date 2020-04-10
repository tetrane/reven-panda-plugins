#pragma once

#include <panda/plugin.h>
#include <rvnbintrace/trace_writer.h>

using namespace reven::backend::plugins::file::libbintrace;

class PandaWriter : public TraceWriter {
public:
	PandaWriter(const std::string& filename, const MachineDescription& desc);
};

uint16_t compute_fpu_tags(CPUState* cs);
void save_initial_memory(CPUState* cs, const MachineDescription& machine, InitialMemorySectionWriter& writer);
void save_initial_registers(CPUState* cs, InitialRegistersSectionWriter& writer);
void save_diff_registers(CPUState* cs, EventsSectionWriter& writer);
