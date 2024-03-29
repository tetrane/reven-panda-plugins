#include <memory>
// std::remove(const char*)
#include <cstdio>
#include <experimental/optional>
#include <panda/plugin.h>
#include <panda/plugin_plugin.h>
#include <panda/common.h>

#include "../reven_icount/reven_icount_ext.h"
#include "../reven_icount/reven_icount_types.h"
#include "common.h"
#include <rvnmemhistwriter/db_writer.h>

using DbWriter = reven::backend::memaccess::db::DbWriter;
using MemoryAccess = reven::backend::memaccess::db::MemoryAccess;
using Operation = reven::backend::memaccess::db::Operation;

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);

int insn_exec_callback(CPUState* env, target_ptr_t pc);
bool insn_translate_callback(CPUState* env, target_ptr_t pc);
void replay_after_dma_callback(CPUState* env, const uint8_t* buf, hwaddr addr, size_t size, bool is_write);

void virt_mem_before_read_callback(CPUState* env, target_ptr_t pc, target_ptr_t addr, size_t size);
void phys_mem_before_read_callback(CPUState* env, target_ptr_t pc, target_ptr_t addr, size_t size);
void virt_mem_after_read_callback(CPUState* env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t* buf);

void virt_mem_before_write_callback(CPUState* env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t* buf);
void phys_mem_before_write_callback(CPUState* env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t* buf);
void virt_mem_after_write_callback(CPUState* env, target_ptr_t pc, target_ptr_t addr, size_t size, uint8_t* buf);
}

std::unique_ptr<DbWriter> memory_history_writer;

struct AccessInfoBuilder {
	struct AddrSize {
		target_ulong addr;
		target_ulong size;
	};

	AccessInfoBuilder(AddrSize virt, bool is_write) : virt(virt), is_write(is_write) {}
	AddrSize virt;
	std::experimental::optional<AddrSize> phy1;
	std::experimental::optional<AddrSize> phy2;
	bool is_write = false;

	void add_phy(AddrSize content) {
		if (not phy1) {
			phy1 = { content.addr, content.size };
		} else if (not phy2) {
			phy2 = { content.addr, content.size };
		} else {
			throw std::logic_error("Cannot build access with more than 2 physicals");
		}
	}

	bool is_consistent() {
		if (phy1 and phy2) {
			return virt.size == phy1->size + phy2->size;
		} else if (phy1) {
			return virt.size == phy1->size;
		}
		return false;
	}

	void push_accesses(DbWriter* writer) {
		if (not is_consistent()) {
			throw std::logic_error("Trying to push inconsistent access");
		}
		const auto op = is_write ? Operation::Write : Operation::Read;
		writer->push({reven_icount(), phy1->addr, virt.addr, static_cast<std::uint32_t>(phy1->size), true, op});
		if (phy2) {
			writer->push(
			  { reven_icount(), phy2->addr, virt.addr + phy1->size, static_cast<std::uint32_t>(phy2->size), true, op });
		}
	}

};

std::experimental::optional<AccessInfoBuilder> access_builder;

void virt_mem_before_read_callback(CPUState* /* cs */, target_ptr_t /* pc */, target_ptr_t addr, size_t size)
{
	try {
		access_builder = AccessInfoBuilder({ addr, size }, false);
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

void phys_mem_before_read_callback(CPUState* /* cpu */, target_ptr_t /* pc */, target_ptr_t addr, size_t size)
{
	try {
		if (not access_builder or access_builder->is_write) {
			throw std::logic_error("Physical read access without previous virtual");
		}

		access_builder->add_phy({ addr, size });
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}


void virt_mem_after_read_callback(CPUState* /* cs */, target_ptr_t /* pc */, target_ptr_t addr, size_t size, uint8_t* /* buf */)
{
	try {
		if (not memory_history_writer || reven_exec_status() == REVEN_EXEC_STATUS_TRANSLATING) {
			return;
		}

		if (not access_builder or access_builder->is_write or access_builder->virt.addr != addr or
		    access_builder->virt.size != size) {
			throw std::logic_error("Virtual read_after without consistent read_befores");
		}

		access_builder->push_accesses(memory_history_writer.get());
		access_builder = {};
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

void virt_mem_before_write_callback(CPUState* /* cs */, target_ptr_t /* pc */, target_ptr_t addr, size_t size, uint8_t* /* buf */)
{
	try {
		access_builder = AccessInfoBuilder({ addr, size }, true);
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

void phys_mem_before_write_callback(CPUState* /* cpu */, target_ptr_t /* pc */, target_ptr_t addr, size_t size, uint8_t* /* buf */)
{
	try {
		if (not access_builder or not access_builder->is_write) {
			throw std::logic_error("Physical write access without previous virtual");
		}

		access_builder->add_phy({ addr, size });
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

void virt_mem_after_write_callback(CPUState* /* cs */, target_ptr_t /* pc */, target_ptr_t addr, size_t size, uint8_t* /* buf */)
{
	try {
		if (not memory_history_writer) {
			return;
		}

		if (not access_builder or not access_builder->is_write or access_builder->virt.addr != addr or
		    access_builder->virt.size != size) {
			throw std::logic_error("Virtual write_after without consistent write_befores");
		}

		access_builder->push_accesses(memory_history_writer.get());
		access_builder = {};
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

void replay_after_dma_callback(CPUState* cs, const uint8_t* /* src_buffer */, hwaddr dest_addr, size_t num_bytes, bool is_write)
{
	try {
		// Hack: if cs is null, we know the call is coming from a direct physical write from the MMU.
		// We don't want to keep MMU accesses, because they have a huge impact on the database's size.
		// TODO: actually add a proper callback for this case.
		if (not memory_history_writer or not cs) {
			return;
		}

		const std::uint32_t narrowing_access_size = num_bytes;
		if (is_write) {
			memory_history_writer->push({reven_icount(), dest_addr, 0, narrowing_access_size, false, Operation::Write});
		} else if (reven_exec_status() != REVEN_EXEC_STATUS_TRANSLATING) {
			memory_history_writer->push({reven_icount(), dest_addr, 0, narrowing_access_size, false, Operation::Read});
		}
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

bool insn_translate_callback(CPUState* /* cs */, target_ptr_t /* pc */)
{
	try {
		// Callback is necessary, otherwise panda crashes.
		return true;
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

int insn_exec_callback(CPUState* /* cs */, target_ptr_t /* pc */)
{
	try {
		static bool first_event = true;
		if (first_event) {
			// initialize reader on first event
			// remove possibly existing file
			std::remove("memhist.sqlite");
			memory_history_writer = std::make_unique<DbWriter>(
				"memhist.sqlite",
				tool_name,
				tool_version,
				tool_info
			);
			first_event = false;
		}
		return 0;
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

bool init_plugin(void* self)
{
	try {
		/*=== panda initialization ===*/
		panda_enable_memcb(); // enable on memory callback

		/*=== plugin dependencies ===*/
		if (not init_reven_icount_api()) {
			printf("memory_history plugin requires reven_icount plugin to proceed. Aborting.\n");
			exit(1);
		}

		/*=== callbacks ===*/
		panda_cb pcb;

		pcb.phys_mem_before_write = phys_mem_before_write_callback;
		panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);
		pcb.virt_mem_before_write = virt_mem_before_write_callback;
		panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_WRITE, pcb);
		pcb.virt_mem_after_write = virt_mem_after_write_callback;
		panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_WRITE, pcb);

		pcb.phys_mem_before_read = phys_mem_before_read_callback;
		panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_READ, pcb);
		pcb.virt_mem_before_read = virt_mem_before_read_callback;
		panda_register_callback(self, PANDA_CB_VIRT_MEM_BEFORE_READ, pcb);
		pcb.virt_mem_after_read = virt_mem_after_read_callback;
		panda_register_callback(self, PANDA_CB_VIRT_MEM_AFTER_READ, pcb);

		pcb.insn_translate = insn_translate_callback;
		panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb); // called before an instruction_EVENT is translated

		pcb.insn_exec = insn_exec_callback;
		panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb); // called before an instruction_EVENT is executed

		pcb.replay_after_dma = replay_after_dma_callback;
		panda_register_callback(self, PANDA_CB_REPLAY_AFTER_DMA, pcb); // called after dma to physical memory

		return true;
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

void uninit_plugin(void* /* self */)
{
	try {
		memory_history_writer.reset();
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}
