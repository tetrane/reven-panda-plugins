#include <map>
#include <vector>
#include <cstring>

#include <panda/plugin.h>
#include <panda/plugin_plugin.h>

/**
 * This plugin tests that the "(physical) memory written" callbacks are indeed always called when a memory write is
 * performed (both for plain accesses and DMA).
 *
 * To do so, it maintains a memory buffer created from the initial memory state of panda, and updated using the memory
 * callbacks. At the end of the replay, it checks the contents of its memory buffer against the actual memory of QEMU
 * and reports any differences.
 *
 * This plugin does not test read memory callbacks.
 */

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);

int insn_exec_callback(CPUState*, target_ulong);
int phys_mem_after_write_callback(CPUState*, target_ulong, target_ulong, target_ulong, void*);
int replay_after_dma_callback(CPUState*, uint32_t, uint8_t*, uint64_t, uint32_t);
bool insn_translate_callback(CPUState*, target_ulong);
}

//! Our physical memory object
std::map<std::uint64_t, std::vector<std::uint8_t>> memory;

constexpr std::size_t page_size = TARGET_PAGE_SIZE;

void write_buffer(std::uint64_t address, std::uint8_t* buffer, std::size_t size)
{
	if (address + size > ram_size or memory.empty())
		return;

	auto offset_in_page = address % page_size;
	auto page_address =  address - offset_in_page;

	// Copy buffer, one destination page at a time
	while (size > 0) {
		auto& page = memory.at(page_address);
		auto copy_size = std::min(size, page_size - offset_in_page);
		std::memcpy(page.data() + offset_in_page, buffer, copy_size);
		offset_in_page = 0;
		page_address += page_size;
		buffer += copy_size;
		size -= copy_size;
	}
}

int insn_exec_callback(CPUState* /* cs */, target_ulong /* pc */)
{
	static bool first_event = true;
	if (first_event) {
		first_event = false;

		printf("[*] Copying initial memory...\n");

		for (ram_addr_t addr = 0; addr < ram_size; addr += page_size) {
			std::vector<std::uint8_t> buffer(page_size);
			panda_physical_memory_rw(addr, buffer.data(), page_size, 0);
			memory.emplace(std::make_pair(addr, std::move(buffer)));
		}

		printf("[*] Memory copied, will start recording memory events.\n");
	}

	return 0;
}

int phys_mem_after_write_callback(CPUState* /* cs */, target_ulong /* pc */, target_ulong addr, target_ulong size, void* buf)
{
	write_buffer(addr, reinterpret_cast<std::uint8_t*>(buf), size);
    return 0;
}

int replay_after_dma_callback(CPUState* /* cs */, uint32_t is_write, uint8_t* src_addr, uint64_t dest_addr, uint32_t num_bytes)
{
	if (is_write) {
		write_buffer(dest_addr, src_addr, num_bytes);
	}

	return 0;
}

bool insn_translate_callback(CPUState* /* cs */, target_ulong /* pc */)
{
	// Callback is necessary, otherwise panda crashes.
	return true;
}

bool init_plugin(void* self)
{
	/*=== panda initialization ===*/
	panda_do_flush_tb();       // what does it realy do?
	panda_enable_precise_pc(); // enable precise guest's PC tracking
	panda_enable_memcb();      // enable on memory callback

	/*=== callbacks ===*/
	panda_cb pcb;

	pcb.insn_translate = insn_translate_callback;
	panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb); // called before an instruction_EVENT is translated

	pcb.insn_exec = insn_exec_callback;
	panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb); // called before an instruction_EVENT is executed

	pcb.phys_mem_after_write = phys_mem_after_write_callback;
	panda_register_callback(self, PANDA_CB_PHYS_MEM_AFTER_WRITE, pcb); // called after write to physical memory

	pcb.replay_after_dma = replay_after_dma_callback;
	panda_register_callback(self, PANDA_CB_REPLAY_AFTER_DMA, pcb); // called after dma to physical memory

	return true;
}

void uninit_plugin(void* /* self */)
{
	printf("[*] Comparing...\n");
	bool difference = false;

	for (ram_addr_t addr = 0; addr < ram_size; addr += page_size) {
		std::vector<std::uint8_t> buffer(page_size, 0);
		panda_physical_memory_rw(addr, buffer.data(), page_size, 0);
		if (buffer != memory.at(addr)) {
			difference = true;
			printf("[>] Difference found at [%lx - %lx[\n", addr, addr + page_size);
		}
	}

	if (not difference) {
		printf("No difference found!\n");
	}
}
