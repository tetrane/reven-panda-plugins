#include <map>
#include <vector>
#include <cstring>
#include <algorithm>
#include <thread>
#include <chrono>
#include <sstream>

#include <execinfo.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <signal.h>
#include <ucontext.h>
#include <stdlib.h>
#include <stddef.h>

#include <panda/plugin.h>
#include <panda/plugin_plugin.h>

#include "prettifier.h"

/**
 * This plugin tests that the memory read / write / dma callbacks are indeed always called when a memory access is
 * performed (both for plain accesses and DMA).
 *
 * To do so, it mprotects the host addresses corresponding to guest RAM regions, then traps the SIGSEGV signal to
 * receive accesses. There are limitations to this:
 * - we do not know about consecutives accesses by the same instruction to more than one byte inside a single page, so
 * we don't know actual access sizes.
 * - we get a lot of information, including code fetching, soem of it is irrelevant: we must disregard certain accesses.
 * - we ignore MMIO accesses for now, these are an entirely different beast.
 *
 * /!\ /!\ /!\
 * As is, you *will* get errors! You must patch panda to report block translation earlier (yes, this is crude):
 * In file cpu-exec.c, you must move line 396 `panda_callbacks_before_block_translate(cpu, pc);` on line 380 (right
 * before `tb = tb_htable_lookup(cpu, pc, cs_base, flags);`).
 */

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);
}

int insn_exec_callback(CPUState*, target_ptr_t);
void phys_mem_before_write_callback(CPUState*, target_ptr_t, target_ptr_t, size_t, uint8_t*);
void phys_mem_before_read_callback(CPUState*, target_ptr_t, target_ptr_t, size_t);
void phys_mem_after_write_callback(CPUState*, target_ptr_t, target_ptr_t, size_t, uint8_t*);
void phys_mem_after_read_callback(CPUState*, target_ptr_t, target_ptr_t, size_t, uint8_t*);
void replay_after_dma_callback(CPUState*, const uint8_t*, hwaddr, size_t, bool);
bool insn_translate_callback(CPUState*, target_ptr_t);
void replay_before_block_exec(CPUState *env, TranslationBlock *tb);
void replay_after_block_exec(CPUState *env, TranslationBlock *tb, uint8_t);
void replay_before_block_translate(CPUState *env, target_ptr_t pc);

struct RecordedAccess {
	std::uint64_t address;
	std::uint64_t size; // If 0: unknown
	std::array<void*, 30> backtrace; // The host code triggering this access, if available.
	bool is_write;
	bool has_succeeded; // Some accesses might start but not succeed (page fault, etc), and those might or might not
	                    // generate associated real accesses. We store them anyway, because real accesses might have
	                    // occured, so we need them to match against.

	std::string desc() const {
		std::stringstream out;
		out << "access " << (is_write ? "w" : "r") << " @0x" << std::hex << address << " - " << std::dec << size;
		for (const auto& code_address: backtrace) {
			if (code_address) {
				out << std::endl << "\t@ " << pretty_location(code_address);
			}
		}
		return out.str();
	}
};

struct Regions {
	std::uint64_t guest_base;
	void* host_base;
	std::uint64_t size;
};

// This object contains the memory regions that have been discovered
std::vector<Regions> regions;
// This object contains the "real" accesses to those memory regions, trapped via mprotect & sigsegv
// We do not know their size, so it's always set to 0.
std::vector<RecordedAccess> real_accesses;
// This object contains the accesses reported by panda
std::vector<RecordedAccess> panda_accesses;
// Panda will not report readings for code fetching, this variable helps muting the real accesses recording.
bool record_real_accesses = false;

bool is_address_in_ranges(target_ulong address)
{
	for (const auto& region: regions) {
		if (address >= region.guest_base and address < region.guest_base + region.size)
			return true;
	}
	return false;
}
std::uint64_t rebase_host_to_guest(std::uint64_t host_address)
{
	for (const auto& region: regions) {
		if (host_address >= (uint64_t)region.host_base and host_address < (uint64_t)region.host_base + region.size) {
			return host_address - (uint64_t)region.host_base + region.guest_base;
		}
	}
	printf("Couldn't rebase %lx!\n", host_address);
	exit(1);
}

bool access_match(const RecordedAccess& real, const RecordedAccess& panda)
{
	auto host_address = rebase_host_to_guest(real.address);
	auto guest_addr = panda.address;
	auto size = panda.size;
	// Sometimes QEMU read a few bytes before the actual access, 8 max: case of unaligned accesses
	return host_address + 8 >= guest_addr and host_address < guest_addr + size and real.is_write == panda.is_write;
}

bool save_real_accesses(siginfo_t *info, ucontext_t* context, bool is_write)
{
	if ((not record_real_accesses))
		return false;

	RecordedAccess access { (uint64_t)info->si_addr, 0, {{ 0 }}, is_write, true };
	std::array<void*, 30> backtrace {{0}};
	::backtrace(backtrace.data(), backtrace.size());

	auto start_backtrace = std::find(backtrace.begin(), backtrace.end(), reinterpret_cast<void*>(context->uc_mcontext.gregs[REG_RIP]));
	auto size = std::max<std::size_t>(std::distance(start_backtrace, backtrace.end()), access.backtrace.size());

	if (start_backtrace != backtrace.end()) {
		std::copy(start_backtrace, start_backtrace + size, access.backtrace.begin());
	}
	real_accesses.emplace_back(std::move(access));

	return true;
}

void print_all_accesses()
{
	printf("callbacks: %lu\n", panda_accesses.size());
	for (const auto& access : panda_accesses) {
		printf("%s\n", access.desc().c_str());
	}
	printf("real: %lu\n", real_accesses.size());
	for (const auto& access : real_accesses) {
		printf("%s\n", access.desc().c_str());
	}

	printf("real: %lu\n", real_accesses.size());
	for (const auto& real : real_accesses) {
		bool found = false;
		for (auto& panda : panda_accesses) {
			if (access_match(real, panda)) {
				found = true;
				break;
			}
		}
		if (not found)
			printf("not found: %s\n", real.desc().c_str());
	}
	printf("callbacks: %lu\n", panda_accesses.size());
	for (const auto& panda : panda_accesses) {
		if (not panda.has_succeeded)
			continue;

		bool found = false;
		for (const auto& real : real_accesses) {
			if (access_match(real, panda)) {
				found = true;
				break;
			}
		}
		if (not found)
			printf("not found: %s\n", panda.desc().c_str());
	}
}

bool do_accesses_mismatch()
{
	if (panda_accesses.size() == real_accesses.size())
		return false;

	// Ensure all real access are inside a cb access
	for (const auto& real : real_accesses) {
		bool found = false;

		for (auto& panda : panda_accesses) {
			if (access_match(real, panda)) {
				found = true;
				break;
			}
		}
		if (not found)
			return true;
	}

	for (const auto& panda : panda_accesses) {
		// Do not check failed accesses.
		if (not panda.has_succeeded)
			continue;

		bool found = false;
		for (const auto& real : real_accesses) {
			if (access_match(real, panda)) {
				found = true;
				break;
			}
		}
		if (not found)
			return true;
	}
	return false;
}

void sig_handler(int signum, siginfo_t *info, void *ptr)
{
	constexpr std::uint64_t page_size = 4*1024; // Is this always true?
	static void* page_address = 0;
	static std::size_t previous_access_id = -1;
	ucontext_t *context = (ucontext_t *)ptr;

	if (signum == SIGSEGV) {
		if (page_address != 0 and page_address == (void*)((uint64_t)info->si_addr & ~(page_size-1))) {
			// The access being mapped as "read" didn't work, so let's try as "write"
			if (previous_access_id != static_cast<std::size_t>(-1))
				real_accesses.at(previous_access_id).is_write = true;

			mprotect(page_address, page_size, PROT_READ | PROT_WRITE);
		} else {
			// Assume the access is "read" for the moment, and mprotect it as such
			if (save_real_accesses(info, context, false))
				previous_access_id = real_accesses.size() - 1;

			page_address = (void*)((uint64_t)info->si_addr & ~(page_size-1));
			mprotect(page_address, page_size, PROT_READ);
			context->uc_mcontext.gregs[REG_EFL] |= 0x100;
		}
	} else if (signum == SIGTRAP) {
		// The trapped instruction finished execution, let's mprotect back to NONE.
		context->uc_mcontext.gregs[REG_EFL] ^= context->uc_mcontext.gregs[REG_EFL] & 0x100;
		if (page_address == 0)
			return;
		mprotect(page_address, page_size, PROT_NONE);
		page_address = 0;
		previous_access_id = -1;
	}
}

int insn_exec_callback(CPUState* /* cs */, target_ptr_t /* pc */)
{
	static std::uint64_t context_counter = 0;
	if (context_counter == 0) {
		// This signal have been blocked somewhere, unblock them so the handler does get called.
		sigset_t intmask;
		sigaddset(&intmask, SIGSEGV);
		sigaddset(&intmask, SIGTRAP);
		if (sigprocmask(SIG_UNBLOCK, &intmask, NULL))
			printf("Error sigprocmask! \n");

		extern AddressSpace address_space_memory;
		printf("[*] Retreiving pointers...\n");
		auto root = address_space_memory.root;
		std::vector<MemoryRegionSection> sections;
		for (std::size_t i = 0; i < (uint32_t)(-1024); i += 1024) {
			auto section = memory_region_find(root, i, 1);
			if (section.mr == nullptr)
				continue;
			if (std::find_if(sections.begin(), sections.end(),
			              [&](const MemoryRegionSection& other) { return other.mr == section.mr; }) == sections.end()) {
				sections.push_back(section);
				if (memory_access_is_direct(section.mr, 0)) {
					printf("found in region 0x%lx size 0x%lx @ 0x%lx\n", i, memory_region_size(section.mr),
					       (uint64_t)memory_region_get_ram_ptr(section.mr));
					if (mprotect(memory_region_get_ram_ptr(section.mr), memory_region_size(section.mr), PROT_NONE) != 0) {
						printf("Call to mprotect failed: %d\n", errno);
					}
					regions.push_back({ i, memory_region_get_ram_ptr(section.mr), memory_region_size(section.mr) });
				} else {
					printf("ignoring mmio in region 0x%lx size 0x%lx\n", i, memory_region_size(section.mr));
				}
			}
		}
		printf("[*] Done - now monitoring.\n");
	} else {
		// Compare panda_accesses and real_accesses
		if (do_accesses_mismatch()) {
			printf("[*] Found a mismatch at %lu:\n", context_counter);
			print_all_accesses();
		}
	}
	panda_accesses.clear();
	real_accesses.clear();
	++context_counter;
	return 0;
}

void phys_mem_before_write_callback(CPUState* /* cs */, target_ptr_t /* pc */, target_ptr_t addr, size_t size, uint8_t* /* buf */)
{
	if (not record_real_accesses or not is_address_in_ranges(addr)) {
		return;
	}

	panda_accesses.push_back({ addr, size, {{ 0 }}, true, false });
	return;
}

void phys_mem_before_read_callback(CPUState* /* cs */, target_ptr_t /* pc */, target_ptr_t addr, size_t size)
{
	if (not record_real_accesses or not is_address_in_ranges(addr)) {
		return;
	}

	panda_accesses.push_back({ addr, size, {{ 0 }}, false, false });
	return;
}

void phys_mem_after_write_callback(CPUState* /* cs */, target_ptr_t /* pc */, target_ptr_t addr, size_t /* size */, uint8_t* /* buf */)
{
	if (not record_real_accesses or not is_address_in_ranges(addr)) {
		return;
	}

	panda_accesses.back().has_succeeded = true;
	return;
}

void phys_mem_after_read_callback(CPUState* /* cs */, target_ptr_t /* pc */, target_ptr_t addr, size_t /* size */, uint8_t* /* buf */)
{
	if (not record_real_accesses or not is_address_in_ranges(addr)) {
		return;
	}

	panda_accesses.back().has_succeeded = true;
	return;
}

void replay_after_dma_callback(CPUState* /* cs */, const uint8_t* /* buf */, hwaddr dest_addr, size_t num_bytes, bool is_write)
{
	if (not record_real_accesses or not is_address_in_ranges(dest_addr)) {
		return;
	}

	panda_accesses.push_back({ dest_addr, num_bytes, {{ 0 }}, is_write, true });
	return;
}

bool insn_translate_callback(CPUState* /* cs */, target_ptr_t /* pc */)
{
	record_real_accesses = false;
	return true;
}

void replay_before_block_exec(CPUState* /* cs */, TranslationBlock* /* tb */)
{
	record_real_accesses = true;
	return;
}

void replay_after_block_exec(CPUState* /* cs */, TranslationBlock* /* tb */, uint8_t /* exitCode */)
{
	record_real_accesses = false;
	return;
}

void replay_before_block_translate(CPUState* /* cs */, target_ptr_t /* pc */)
{
	record_real_accesses = false;
	return;
}

bool init_plugin(void* self)
{
	struct sigaction act;
	memset(&act, 0, sizeof(struct sigaction));
	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = sig_handler;
	if (sigaction(SIGSEGV, &act, NULL))
		printf("Error setting sigaction! \n");
	if (sigaction(SIGTRAP, &act, NULL))
		printf("Error setting sigaction! \n");

	/*=== panda initialization ===*/
	panda_do_flush_tb();       // what does it realy do?
	panda_enable_precise_pc(); // enable precise guest's PC tracking
	panda_enable_memcb();      // enable on memory callback

	/*=== callbacks ===*/
	panda_cb pcb;

	pcb.insn_translate = insn_translate_callback;
	panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

	pcb.insn_exec = insn_exec_callback;
	panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);

	// Before and after are required to know failed attempts (which is a before with no corresponding after).
	pcb.phys_mem_before_write = phys_mem_before_write_callback;
	panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);
	pcb.phys_mem_after_write = phys_mem_after_write_callback;
	panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_WRITE, pcb);

	pcb.phys_mem_before_read = phys_mem_before_read_callback;
	panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_READ, pcb);
	pcb.phys_mem_after_read = phys_mem_after_read_callback;
	panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_READ, pcb);

	pcb.replay_after_dma = replay_after_dma_callback;
	panda_register_callback(self, PANDA_CB_REPLAY_AFTER_DMA, pcb);

	// Only record when executing block, disregard all other accesses.
	pcb.before_block_exec = replay_before_block_exec;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
	pcb.after_block_exec = replay_after_block_exec;
	panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);
	pcb.before_block_translate = replay_before_block_translate;
	panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_TRANSLATE, pcb);

	return true;
}

void uninit_plugin(void* /* self */)
{
	printf("[*] See above log for potential errors, if any.");
	printf("    --> If you have errors, check you applied the necessary manual patch to panda (see source file).");
}
