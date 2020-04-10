#include "cache_writer.h"

#include <panda/plugin_plugin.h>

#include "common.h"
#include "machine_description.h"
#include "custom_cpu_context.h"
#include "trace_writer.h"

PandaCacheWriter::PandaCacheWriter(const std::string& filename, const MachineDescription& desc,
                                   std::uint64_t cache_frequency)
  : CacheWriter(
    	std::make_unique<std::ofstream>(filename, std::ios::binary), TARGET_PAGE_SIZE, desc,
    	tool_name,
    	tool_version,
    	tool_info
    )
  , cache_points_writer_(start_cache_points_section())
  , last_dumped_context_id_(0)
  , cache_frequency_(cache_frequency)
  , memory_buffer_(header().page_size)
{

}

void PandaCacheWriter::mark_memory_dirty(std::uint64_t address, std::uint64_t size)
{
	bool found_region = false;
	for (const auto& region : machine().memory_regions) {
		if (address >= region.start and address + size <= region.start + region.size) {
			found_region = true;
			break;
		}
	}
	if (not found_region)
		return;

	size += address % header().page_size;
	address -= address % header().page_size;

	for(std::uint64_t sized_covered = 0; sized_covered < size; sized_covered += header().page_size) {
		dirty_pages_.insert(address + sized_covered);
	}
}

void PandaCacheWriter::new_context(CPUState* cs, std::uint64_t context_id, std::uint64_t trace_stream_pos)
{
	if (context_id - last_dumped_context_id_ < cache_frequency_)
		return;
	last_dumped_context_id_ = context_id;

	cache_points_writer_.start_cache_point(context_id, trace_stream_pos);

#if defined(TARGET_X86_64)
	auto state = get_cpu_state(cs);
	X86CPU* cpu = X86_CPU(cs);

	cache_points_writer_.write_register(reg_id(r_rip), reinterpret_cast<const std::uint8_t*>(&cs->panda_guest_pc), 8);

	// Shadow segments
	std::uint64_t segment_value;
	segment_value = compute_segment(state->segs[R_CS]);
	cache_points_writer_.write_register(reg_id(r_cs_shadow), reinterpret_cast<const std::uint8_t*>(&segment_value), 8);
	segment_value = compute_segment(state->segs[R_DS]);
	cache_points_writer_.write_register(reg_id(r_ds_shadow), reinterpret_cast<const std::uint8_t*>(&segment_value), 8);
	segment_value = compute_segment(state->segs[R_ES]);
	cache_points_writer_.write_register(reg_id(r_es_shadow), reinterpret_cast<const std::uint8_t*>(&segment_value), 8);
	segment_value = compute_segment(state->segs[R_SS]);
	cache_points_writer_.write_register(reg_id(r_ss_shadow), reinterpret_cast<const std::uint8_t*>(&segment_value), 8);
	segment_value = compute_segment(state->segs[R_FS]);
	cache_points_writer_.write_register(reg_id(r_fs_shadow), reinterpret_cast<const std::uint8_t*>(&segment_value), 8);
	segment_value = compute_segment(state->segs[R_GS]);
	cache_points_writer_.write_register(reg_id(r_gs_shadow), reinterpret_cast<const std::uint8_t*>(&segment_value), 8);

	cache_points_writer_.write_register(reg_id(r_rsp), reinterpret_cast<const std::uint8_t*>(&state->regs[R_ESP]), 8);

	auto eflags = cpu_compute_eflags(&cpu->env);
	cache_points_writer_.write_register(reg_id(r_eflags), reinterpret_cast<const std::uint8_t*>(&eflags), 4);
	auto fpu_tag = compute_fpu_tags(cs);
	cache_points_writer_.write_register(reg_id(r_x87tags), reinterpret_cast<const std::uint8_t*>(&fpu_tag), 2);

	std::uint64_t cr8 = cpu_get_apic_tpr(cpu->apic_state);
	cache_points_writer_.write_register(reg_id(r_cr8), reinterpret_cast<const std::uint8_t*>(&cr8), 8);

	std::uint64_t msr_value;
	#define REGISTER(register, size)
	#define REGISTER_CTX(register, size, ctx) \
	cache_points_writer_.write_register(reg_id(r_##register), reinterpret_cast<const std::uint8_t*>(&state->ctx), size);
	#define REGISTER_MSR(register, index) \
	msr_value = read_msr<(index)>(state); \
	cache_points_writer_.write_register(reg_id(r_##register), reinterpret_cast<const std::uint8_t*>(&msr_value), 8);
	#include "registers_priority.inc"
	#include "registers_others.inc"
	#undef REGISTER
	#undef REGISTER_CTX
	#undef REGISTER_MSR
#endif

	for (auto page : dirty_pages_) {
		auto res = panda_physical_memory_rw(page, memory_buffer_.data(), header().page_size, 0);

		if (res != -1) {
			cache_points_writer_.write_memory_page(page, memory_buffer_.data());
		} else {
			std::cout << "Couldn't read physical memory " << page << "! Aborting." << std::endl;
			exit(1);
		}
	}
	dirty_pages_.clear();

	cache_points_writer_.finish_cache_point();
}

void PandaCacheWriter::finalize()
{
	finish_cache_points_section(std::move(cache_points_writer_));
}
