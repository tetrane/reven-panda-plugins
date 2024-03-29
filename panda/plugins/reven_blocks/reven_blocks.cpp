#include <fstream>
#include <unordered_map>
#include <vector>
#include <algorithm>
#include <array>
#include <string>
#include <iostream>

#include <panda/plugin.h>
#include <panda/plugin_plugin.h>
#include <panda/common.h>

#include <rvnblock/block_writer.h>

#include "../reven_icount/reven_icount_ext.h"
#include "../reven_icount/reven_icount_types.h"

extern "C"
{
bool init_plugin(void*);
void uninit_plugin(void*);
void before_block_exec(CPUState* cpu, TranslationBlock* tb);
}

using ExecutionMode = reven::block::ExecutionMode;
using namespace reven::block::writer;

static std::experimental::optional<Writer> writer;

void before_block_exec(CPUState* cpu, TranslationBlock* tb)
{
	try {
		static std::vector<std::uint8_t> data_buffer;

		data_buffer.clear();

		X86CPU* x86_cpu = X86_CPU(cpu);
		CPUX86State* env = &x86_cpu->env;

		data_buffer.resize(tb->size);
		if (panda_virtual_memory_read(cpu, tb->pc, data_buffer.data(), tb->size) != 0) {
			std::cerr << "Could not read virtual memory for basic block at address 0x" << std::hex << tb->pc
			<< std::dec << " with size " << tb->size << ". Exiting..." << std::endl;
			exit(2);
		}

		ExecutedBlock block;
		block.block_instruction_count = tb->icount;

		if (env->hflags & HF_CS64_MASK) {
			block.mode = ExecutionMode::x86_64_bits;
		} else if (env->hflags & HF_CS32_MASK) {
			block.mode = ExecutionMode::x86_32_bits;
		} else {
			block.mode = ExecutionMode::x86_16_bits;
		}

		block.pc = tb->pc;

		// For the first call to `add_block`, reven_icount() is not callable, because no instruction has actually been
		// executed on the first call to before_block_exec.
		// However on the first call to `add_block`, no execution will actually be registered,
		// meaning that `transition_count` will not be used.
		// So it is OK to leave transition_count to any value (e.g. 0) when the status is REVEN_EXEC_STATUS_NOT_STARTED.
		std::uint64_t transition_count = 0;
		if (reven_exec_status() != REVEN_EXEC_STATUS_NOT_STARTED) {
			transition_count = reven_icount();
		}

		writer->add_block(transition_count + 1, block, reven::block::Span{data_buffer.size(), data_buffer.data()});
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

void before_interrupt(CPUState* cs, int intno, bool /*is_int*/, int /*error_code*/, target_ptr_t /*next_eip*/, bool is_hw)
{
	try {
		if (reven_exec_status() == REVEN_EXEC_STATUS_NOT_STARTED) {
			return;
		}

		Interrupt interrupt;
		interrupt.number = intno;

		X86CPU* cpu = reinterpret_cast<X86CPU*>(cs);
		CPUX86State *env = &cpu->env;

		// Per reven-bin-trace, we know that during this callback:
		//    - env->eip will contains the address of the next instruction to execute after the interrupt
		//    - cs->panda_guest_pc will contains the address of the previously executed instruction
		// If the instruction to be executed is the same as the instruction previously executed,
		// it means that we were interrupted before the instruction was executed.

		// FIXME: this discriminates correctly between code and data PF, but in reven-bin-trace, the equivalent returns true
		// for hw interrupt, which it doesn't here.
		// A stop-gap measure to have the same behavior as REVEN's (probably ...) would be to check for the interrupt number
		// 14.
		interrupt.has_related_instruction = env->eip == cs->panda_guest_pc;

		// Experimentally this seems to be giving the same value as reven-bin-trace, although I (@snoopy) can't offer an
		// explanation of why that is.
		// Fully tested on bksod scenario.
		interrupt.pc = env->eip;

		// Experimentally verified to be in sync with the trace on a scenario executing a 32b binary on a 64b OS.
		if (env->hflags & HF_CS64_MASK) {
			interrupt.mode = ExecutionMode::x86_64_bits;
		} else if (env->hflags & HF_CS32_MASK) {
			interrupt.mode = ExecutionMode::x86_32_bits;
		} else {
			interrupt.mode = ExecutionMode::x86_16_bits;
		}

		interrupt.is_hw = is_hw;

		writer->add_interrupt(reven_icount(), interrupt);
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

int insn_exec_callback(CPUState* cs, target_ptr_t)
{
	try {
		writer->add_block_instruction(cs->panda_guest_pc);
		return 0;
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

void on_sigabrt(int /* signum */) {
	uninit_plugin(NULL);
}

bool init_plugin(void* self)
{
	try {
		signal(SIGABRT, &on_sigabrt);

		/*=== plugin dependencies ===*/
		if (not init_reven_icount_api()) {
			printf("reven_blocks plugin requires reven_icount plugin to proceed. Aborting.\n");
			exit(1);
		}

		panda_cb pcb;
		pcb.before_block_exec = before_block_exec;
		panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

		pcb.before_interrupt = before_interrupt;
		panda_register_callback(self, PANDA_CB_BEFORE_INTERRUPT, pcb);

		pcb.insn_exec = insn_exec_callback;
		panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

		writer = Writer("blocks.sqlite", "panda_block_writer", "1.0.0", "Generated with Panda");

		return true;
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

void uninit_plugin(void*)
{
	try {
		// Add the past-the-end icount, so that even the last instruction
		// remains lower than the last executed block entry
		if (reven_exec_status() != REVEN_EXEC_STATUS_NOT_STARTED) {
			writer->finalize_execution(reven_icount() + 1);
		}
		writer = std::experimental::nullopt;
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}
