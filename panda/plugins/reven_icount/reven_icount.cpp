#include <panda/plugin.h>
#include <panda/plugin_plugin.h>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <experimental/optional>
#include <limits>

#include "reven_icount_int_fns.h"
#include "reven_icount_types.h"

// #define ACTIVATE_DEBUG_LOGS

#ifdef ACTIVATE_DEBUG_LOGS
#define DEBUG_LOG(...) printf(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);
}

extern int nb_panda_plugins;
extern panda_plugin panda_plugins[];

int insn_exec_callback(CPUState* env, target_ptr_t pc);
bool insn_translate_callback(CPUState* env, target_ptr_t pc);
void before_interrupt(CPUState* env, int intno, bool is_int, int error_code, target_ptr_t next_eip, bool is_hw);
void replay_after_dma_callback(CPUState* env, const uint8_t* buf, hwaddr addr, size_t size, bool is_write);
void phys_mem_after_read_callback(CPUState* env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t* buf);
void phys_mem_after_write_callback(CPUState* env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t* buf);

namespace {

std::experimental::optional<std::uint64_t> max_icount;

void unload_plugins()
{
	for (int i = 0; i < nb_panda_plugins; ++i) {
		if (0 != strcmp(panda_plugins[i].name, "reven_icount")) {
			panda_do_unload_plugin(i);
		}
	}
}

}

static class
{
public:
	std::uint64_t icount() const {
		if (not has_counting_started_)
			throw std::logic_error("Cannot call reven icount if counting hasn't started yet!");
		return icount_;
	}

	void before_new_instruction(std::uint64_t pc, std::uint64_t rcx) {
		if (not has_counting_started_) {
			DEBUG_LOG("start trace recording\n");
			has_counting_started_ = true;
		} else {
			if (previous_pc_ and previous_pc_.value() == pc and previous_rcx_.value() == rcx + 1)
			{
				DEBUG_LOG("At #%lu Is a REP: no PC change since last instruction at %lx, but rcx changed to %lx\n",
				          icount_, pc, rcx);

				previous_rcx_ = rcx;

				recording_transition_ = true;
				interrupt_firing_ = false;
				translating_ = false; // Note translation can happen right after the first iteration of a REP.
				is_rep_ongoing_ = true;
				return;
			}

			previous_pc_ = pc;
			previous_rcx_ = rcx;

			if (recording_transition_) {
				DEBUG_LOG("finish instruction %lu\n", icount_);
			} else {
				DEBUG_LOG("register-only instruction %lu\n", icount_);
			}

			check_max_icount();
			// Always increment counter, even if empty instruction
			icount_++;
		}

		// We don't know if this instruction will be executed or broken
		recording_transition_ = false;
		interrupt_firing_ = false;
		translating_ = false;
		is_rep_ongoing_ = false;
	}

	void before_interrupt() {
		if (not has_counting_started_) {
			return;
		}

		// We create a new instruction only if necessary, eg if information has been stored
		// about this instruction already
		if (recording_transition_) {
			check_max_icount();
			icount_++;
		}

		// It might be possible for a double (or triple) fault to occur right when trying to fire an interrupt.
		// Note in this case, there will probably be one transition per fault.
		if (interrupt_firing_) {
			DEBUG_LOG("double / triple firing interrupt %lu\n", icount_);
		} else {
			DEBUG_LOG("firing interrupt %lu\n", icount_);
		}

		// We now force recording the interrupt
		recording_transition_ = true;
		interrupt_firing_ = true;
		translating_ = false;
		is_rep_ongoing_ = false;
		previous_pc_ = std::experimental::nullopt;
	}

	void before_translation() {
		if (not translating_) {
			DEBUG_LOG("before translation\n");
			translating_ = true;
		}
	}

	void ensure_recording(const char* reason __attribute__((unused))) {
		if (not has_counting_started_)
			return;

		// Instruction has started for sure
		if (not interrupt_firing_ and not recording_transition_) {
			DEBUG_LOG("start recording %lu for %s\n", icount_, reason);
			recording_transition_ = true;

			// We might still be translating, in which case we want to keep it that way
		}
	}

	RevenExecStatus status() {
		if (not has_counting_started_)
			return REVEN_EXEC_STATUS_NOT_STARTED;
		if (translating_)
			return REVEN_EXEC_STATUS_TRANSLATING;
		if (interrupt_firing_)
			return REVEN_EXEC_STATUS_EXEC_INT;

		// By default, let's assume it's going to be an , even if we're not recording
		return REVEN_EXEC_STATUS_EXEC_INSTR;
	}

	bool is_rep_ongoing() const { return is_rep_ongoing_; }

private:

	void check_max_icount()
	{
		if (has_counting_started_ && max_icount && icount_ > max_icount.value()) {
			unload_plugins();
			exit(0);
		}
	}

	std::uint64_t icount_ = 0; // The next instruction tick
	bool has_counting_started_ = false; //! Whether the trace recording has actually started. If not, we're still waiting for the initial state.

	// These booleans refer to what the cpu is doing now, ie what the current transition is.
	bool interrupt_firing_ = false;      //! Is an interrupt firing? Note, this does not refer to whether an int handler
	                                     //! is running, but rather to whether the cpu is currently firing an int &
	                                     //! setting everything up before transfering control to the registered handler.
	bool recording_transition_ = false;  //! Has the recording started for the current transition? Since the libbintrace
	                                     //! requires knowing which type a transition is when starting its recording,
	                                     //! delaying it helps not recording empty transitions.
	bool translating_ = false;           //! Are we currently translating? If yes, we do not want to record reads.
	bool is_rep_ongoing_ = false;        //! Is the current icount being held while a REP instruction is executing.
	std::experimental::optional<std::uint64_t> previous_pc_;
	std::experimental::optional<std::uint64_t> previous_rcx_;
} execution_status;

uint64_t reven_icount(void)
{
	return execution_status.icount();
}

int reven_exec_status(void)
{
	return execution_status.status();
}

bool reven_exec_rep_ongoing(void)
{
	return execution_status.is_rep_ongoing();
}

void phys_mem_after_read_callback(CPUState*, target_ptr_t, target_ptr_t, size_t, uint8_t*)
{
	// Do nothing
}

void phys_mem_after_write_callback(CPUState*, target_ptr_t, target_ptr_t, size_t, uint8_t*)
{
	if (execution_status.status() == REVEN_EXEC_STATUS_TRANSLATING)
		throw std::logic_error("Virtual memory writes should not happen during translation!");

	execution_status.ensure_recording("mem write");
}

void replay_after_dma_callback(CPUState*, const uint8_t*, hwaddr, size_t, bool is_write)
{
	if (is_write) {
		execution_status.ensure_recording("dma write");
	}
}

bool insn_translate_callback(CPUState*, target_ptr_t)
{
	execution_status.before_translation();
	return true;
}

int insn_exec_callback(CPUState* cs, target_ptr_t)
{
	CPUX86State* cpu = &reinterpret_cast<X86CPU*>(cs)->env;
	execution_status.before_new_instruction(cs->panda_guest_pc, cpu->regs[R_ECX]);
	return 0;
}

void before_interrupt(CPUState* cs, int /* intno */, bool /* is_int */, int /* error_code */, target_ptr_t /* next_eip */, bool is_hw)
{
	// hardware interrupts cannot happen in the middle of an instruction,
	// so we know for sure the previous instruction for which before_interrupt has been called did start
	// and is now fully executed, and that the next instruction's callback before_interrupt has not been called:
	// force the current instruction's start if not started already.
	if (is_hw) {
		execution_status.ensure_recording("hardware interrupt");
	}

	X86CPU* cpu = reinterpret_cast<X86CPU*>(cs);
	CPUX86State *env = &cpu->env;

	if (env->eip != cs->panda_guest_pc) {
		// We know that we won't detect an instruction before the interrupt if its only doing read accesses
		// We also know that during this callback:
		//    - env->eip will contains the address of the next instruction to execute after the interrupt
		//    - cs->panda_guest_pc will contains the address of the previously executed instruction
		// So if they don't match that means that the previously executed instruction won't be resumed after the
		// interrupt meaning that that the interrupt didn't occured during the instruction but after it.
		execution_status.ensure_recording("interrupt after read-only instruction");
	}

	execution_status.before_interrupt();
}

void on_sigabrt(int /* signum */) {
	printf("Aborting at icount = %lu\n", reven_icount());
}

bool init_plugin(void* self)
{
	signal(SIGABRT, &on_sigabrt);

	/*=== panda initialization ===*/
	panda_enable_memcb(); // enable on memory callback

	/*=== callbacks ===*/
	panda_cb pcb;

	pcb.phys_mem_after_write = phys_mem_after_write_callback;
	panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_WRITE, pcb);

	pcb.phys_mem_after_read = phys_mem_after_read_callback;
	panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_READ, pcb);

	pcb.replay_after_dma = replay_after_dma_callback;
	panda_register_callback(self, PANDA_CB_REPLAY_AFTER_DMA, pcb);

	pcb.insn_translate = insn_translate_callback;
	panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

	pcb.insn_exec = insn_exec_callback;
	panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

	pcb.before_interrupt = before_interrupt;
	panda_register_callback(self, PANDA_CB_BEFORE_INTERRUPT, pcb);

	/* get `max_icount` argument */
	panda_arg_list *args = panda_get_args("reven_icount");
	std::uint64_t max_icount_arg = panda_parse_uint64(args, "max_icount", std::numeric_limits<std::uint64_t>::max());
	if (max_icount_arg != std::numeric_limits<std::uint64_t>::max()) {
		max_icount = max_icount_arg;
	}
	panda_free_args(args);

	return true;
}

void uninit_plugin(void* /* self */) {}
