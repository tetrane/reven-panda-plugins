#pragma once

#include <set>

#include <panda/plugin.h>
#include <rvnbintrace/cache_writer.h>

using namespace reven::backend::plugins::file::libbintrace;

class PandaCacheWriter : public CacheWriter {
public:
	PandaCacheWriter(const std::string& filename, const MachineDescription& desc, std::uint64_t cache_frequency);

	void mark_memory_dirty(std::uint64_t address, std::uint64_t size);
	void new_context(CPUState* cs, std::uint64_t context_id, std::uint64_t trace_stream_pos);

	void finalize();

private:
	std::set<std::uint64_t> dirty_pages_;
	CachePointsSectionWriter cache_points_writer_;
	std::uint64_t last_dumped_context_id_;
	const std::uint64_t cache_frequency_;
	std::vector<std::uint8_t> memory_buffer_;
};
