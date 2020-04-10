#include <cstring>
#include <experimental/optional>

#include <panda/plugin.h>
#include <panda/plugin_plugin.h>

#include "../reven_icount/reven_icount_ext.h"

#include "machine_description.h"
#include "trace_writer.h"
#include "cache_writer.h"

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);

int insn_exec_callback(CPUState*, target_ulong);
int phys_mem_after_write_callback(CPUState*, target_ulong, target_ulong, target_ulong, void*);
int replay_after_dma_callback(CPUState*, uint32_t, uint8_t*, uint64_t, uint32_t);
int before_interrupt(CPUState *cs,  int intno, int is_int, int error_code, target_ulong next_eip, int is_hw);
bool insn_translate_callback(CPUState*, target_ulong);
}

static std::experimental::optional<PandaWriter> trace_writer;
static std::experimental::optional<EventsSectionWriter> packet_writer;
static std::experimental::optional<PandaCacheWriter> cache_writer;

int before_interrupt(CPUState *cs, int intno, int is_int, int /* error_code */, target_ulong /* next_eip */, int is_hw)
{
	if (not packet_writer) {
		// Trace writer not initialized, this event will be in the initial context, skip it.
		return 0;
	}

	std::string description;
	if (is_int) {
		description = std::string("interrupt ") + std::to_string(intno);
	} else if (is_hw){
		description = std::string("hw interrupt ") + std::to_string(intno);
	} else {
		description = exception_event_description(intno);
	}

	if (is_hw) {
		// We know that hardware interrupt can't happen during an instruction
		// So we can assume that one did just finish: forcing the creation of its event in the case is hasn't allows us
		// to properly close it in the next block.
		if (!packet_writer->is_event_started()) {
			packet_writer->start_event_instruction();
		}
	}

	if (packet_writer->is_event_started()) {
		X86CPU* cpu = X86_CPU(cs);
		CPUX86State *env = &cpu->env;

		// If the current instruction is fully executed, env->eip contains the next instruction's pc.
		// If not, it contains the current instruction's pc.
		// In both cases though, cs->panda_guest_pc contains the current instruction's pc.
		// Since we close the current instruction, if it is indeed complete we want rip to reflect that,
		// so we temporarily override cs->panda_guest_pc to the most up-to-date value
		uint64_t tmp_panda_guest_pc = cs->panda_guest_pc;
		cs->panda_guest_pc = env->eip;

		// Save the registers for partial or complete execution before the interrupt
		save_diff_registers(cs, *packet_writer);

		cs->panda_guest_pc = tmp_panda_guest_pc;

		packet_writer->finish_event();
	}

	packet_writer->start_event_other(description);

	return 0; // unused
}

int insn_exec_callback(CPUState* cs, target_ulong /* pc */)
{
	static bool first_event = true;
	if (first_event) {
		first_event = false;

		auto machine_desc = x64_machine_description(cs);

		trace_writer.emplace("trace.bin", machine_desc);
		cache_writer.emplace("trace.cache", machine_desc, 1000000);

		auto memory_writer = trace_writer->start_initial_memory_section();

		save_initial_memory(cs, machine_desc, memory_writer);

		auto cpu_writer = trace_writer->start_initial_registers_section(std::move(memory_writer));

		save_initial_registers(cs, cpu_writer);

		packet_writer.emplace(trace_writer->start_events_section(std::move(cpu_writer)));

		return 0;
	}

	// No event or memory started the event? it's a regular instruction
	if (not packet_writer->is_event_started())
		packet_writer->start_event_instruction();

	if (not reven_exec_rep_ongoing())
	{
		save_diff_registers(cs, *packet_writer);

		packet_writer->finish_event();

		cache_writer->new_context(cs, packet_writer->event_count(), packet_writer->stream_pos());
	}

	if (packet_writer->event_count() != reven_icount()) {
		uninit_plugin(NULL);
		throw std::runtime_error("Inconsistency detected between event count and reven_icount plugin.");
	}

	return 0;
}

int phys_mem_after_write_callback(CPUState* /* cs */, target_ulong /* pc */, target_ulong addr, target_ulong size, void* buf)
{
	if (not packet_writer)
		return 0;

	if (not packet_writer->is_event_started())
		packet_writer->start_event_instruction();

    packet_writer->write_memory(addr, reinterpret_cast<const std::uint8_t*>(buf), size);
    cache_writer->mark_memory_dirty(addr, size);

    return 0;
}

int replay_after_dma_callback(CPUState* /* cs */, uint32_t is_write, uint8_t* src_addr, uint64_t dest_addr, uint32_t num_bytes)
{
	if (not packet_writer)
		return 0;

	if (is_write) {
		if (not packet_writer->is_event_started())
			packet_writer->start_event_instruction();
		packet_writer->write_memory(dest_addr, src_addr, num_bytes);
		cache_writer->mark_memory_dirty(dest_addr, num_bytes);
	}

	return 0;
}

bool insn_translate_callback(CPUState* /* cs */, target_ulong /* pc */)
{
	// Callback is necessary, otherwise panda crashes.
	return true;
}

void on_sigabrt(int /* signum */) {
	uninit_plugin(NULL);
}

bool init_plugin(void* self)
{
	signal(SIGABRT, &on_sigabrt);

	/*=== panda initialization ===*/
	panda_do_flush_tb();       // what does it realy do?
	panda_enable_precise_pc(); // enable precise guest's PC tracking
	panda_enable_memcb();      // enable on memory callback

	if (not init_reven_icount_api()) {
		printf("Couldn't initialize reven_icount plugin, aborting.\n");
		exit(0);
	}

	/*=== callbacks ===*/
	panda_cb pcb;

	pcb.before_interrupt = before_interrupt;
	panda_register_callback(self, PANDA_CB_BEFORE_INTERRUPT, pcb);

	pcb.insn_translate = insn_translate_callback;
	panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb); // called before an instruction_EVENT is translated

	pcb.insn_exec = insn_exec_callback;
	panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb); // called before an instruction_EVENT is executed

	pcb.phys_mem_after_write = phys_mem_after_write_callback;
	panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_WRITE, pcb); // called after write to physical memory

	pcb.replay_after_dma = replay_after_dma_callback;
	panda_register_callback(self, PANDA_CB_REPLAY_AFTER_DMA, pcb); // called after dma to physical memory

	initialize_register_maps();

	printf("Starting trace recording...\n");

	return true;
}

void uninit_plugin(void* /* self */)
{
	printf("Flushing trace...\n");
	if (trace_writer and packet_writer) {
		if (not packet_writer->is_event_started())
			packet_writer->start_event_instruction();

		X86CPU* cpu = X86_CPU(first_cpu);
		CPUX86State *env = &cpu->env;

		// If the current instruction is fully executed, env->eip contains the next instruction's pc.
		// If not, it contains the current instruction's pc.
		// In both cases though, first_cpu->panda_guest_pc contains the current instruction's pc.
		// Since we close the current instruction, if it is indeed complete we want rip to reflect that,
		// so we temporarily override first_cpu->panda_guest_pc to the most up-to-date value
		uint64_t tmp_panda_guest_pc = first_cpu->panda_guest_pc;
		first_cpu->panda_guest_pc = env->eip;

		save_diff_registers(first_cpu, *packet_writer);

		packet_writer->finish_event();

		cache_writer->new_context(first_cpu, packet_writer->event_count(), packet_writer->stream_pos());

		first_cpu->panda_guest_pc = tmp_panda_guest_pc;

		trace_writer->finish_events_section(std::move(packet_writer).value());
		trace_writer = std::experimental::nullopt;

		cache_writer->finalize();
		cache_writer = std::experimental::nullopt;
	}
}
