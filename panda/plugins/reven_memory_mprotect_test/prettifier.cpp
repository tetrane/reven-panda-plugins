#include "prettifier.h"
#include "gcc_demangler.h"

#include <fstream>
#include <sstream>
#include <iomanip>

#include <execinfo.h>
#include <fcntl.h>
#include <unistd.h>
#include <dlfcn.h>
#include <libdwarf/libdwarf.h>

// code location information (binary offset = file:line)
struct code_location
{
	Dwarf_Addr binary_offset;
	std::string filename;
	Dwarf_Signed fileline;
};

code_location make_code_location_from_line(Dwarf_Line line, Dwarf_Addr binary_offset)
{
	code_location code_loc;
	code_loc.binary_offset = binary_offset;

	Dwarf_Error error;
	char* file;
	if (dwarf_linesrc(line, &file, &error) == DW_DLV_OK) {
		code_loc.filename = file;
		Dwarf_Unsigned lineno;
		if (dwarf_lineno(line, &lineno, &error)  == DW_DLV_OK)
			code_loc.fileline = lineno;
	}
	return code_loc;
}

// RAII of Dwarf_Line*
struct src_lines_dealloc_guard
{
	src_lines_dealloc_guard(Dwarf_Debug dbg, Dwarf_Line* src_lines, Dwarf_Signed size)
		: dbg_(dbg), src_lines_(src_lines), size_(size) {}

	~src_lines_dealloc_guard()
	{
		if (src_lines_)
			src_lines_dealloc();
	}

private:
	Dwarf_Debug dbg_;
	Dwarf_Line* src_lines_;
	Dwarf_Signed size_;

	void src_lines_dealloc()
	{
		for (auto i = 0; i < size_; ++i)
			dwarf_dealloc(dbg_, src_lines_[i], DW_DLA_LINE);

		dwarf_dealloc(dbg_, src_lines_, DW_DLA_LIST);
	}

};

// A compilation unit contains a list of Dwarf_Line
// (Dwarf_Line = code location information structure (file name, line number, binary offset,…)

//! find the best Dwarf_Line for a given set of Dwarf_Line and a given binary offset

// Remark 0: best = closest binary offset and <= wanted binary offset
// Remark 1: that list is unordered
// Remark 2: if the wanted binary offset is higher than every offsets in the list
//           then there is no possible matching line for that set of lines
bool has_matching_src_line(Dwarf_Line* src_lines, Dwarf_Signed src_lines_size, Dwarf_Addr wanted_binary_offset,
                           Dwarf_Signed& src_line_index, Dwarf_Addr& src_line_binary_offset)
{
	// upper_bound_exists == true if a source line addr is > wanted addr
	bool upper_bound_exists = false;
	Dwarf_Signed index = 0;
	src_line_binary_offset = 0;

	// scans every source line
	for (auto i = 0; i < src_lines_size; ++i) {
		Dwarf_Addr binary_offset;
		Dwarf_Error error;

		if (dwarf_lineaddr(src_lines[i], &binary_offset, &error) != DW_DLV_OK)
			return false;

		Dwarf_Bool is_line_ending_text_sequence;
		if (dwarf_lineendsequence(src_lines[i], &is_line_ending_text_sequence, &error) != DW_DLV_OK)
			return false;

		if (is_line_ending_text_sequence)
			continue;

		if (binary_offset > wanted_binary_offset) {
			upper_bound_exists = true;
		} else if (binary_offset > src_line_binary_offset) {
			src_line_binary_offset = binary_offset;
			index = i;
		}
	}

	src_line_index = index;
	return upper_bound_exists; // true = there is a matching line
}

//! find the best matching code location for the given cu and given binary offset
// equivalent to the function dwarf_getsrc_die(…) of libdw
bool has_matching_code_location(Dwarf_Debug dbg, Dwarf_Die cu_die, Dwarf_Addr wanted_binary_offset,
                                code_location& matching_code_location)
{
	Dwarf_Signed cnt = 0;
	Dwarf_Line* cu_src_lines = NULL;
	Dwarf_Error error;
	if (dwarf_srclines(cu_die, &cu_src_lines, &cnt, &error) != DW_DLV_OK)
		return false;

	src_lines_dealloc_guard guard(dbg, cu_src_lines, cnt);

	Dwarf_Signed src_line_index;
	Dwarf_Addr src_line_binary_offset;
	if (not has_matching_src_line(cu_src_lines, cnt, wanted_binary_offset, src_line_index, src_line_binary_offset))
		return false;

	matching_code_location = make_code_location_from_line(cu_src_lines[src_line_index], src_line_binary_offset);
	return true;
}

//! find the best code location of a cu that match the given offset
//! @param [in] offset An offset in the binary or an absolute address (base address + offset).
//! @param [out] matching_code_location A matching code location with binary_offset between 0 and \param offset.
bool cu_code_location(Dwarf_Debug dbg, Dwarf_Die cu_die, const void* offset, Dl_info& dlInfo,
                      code_location& matching_code_location)
{
	code_location code_loc;

	auto binary_offset = static_cast<Dwarf_Addr>((unsigned long)(offset) - 1);
	if (not has_matching_code_location(dbg, cu_die, binary_offset, code_loc)) {
		// If the cu does not contain binary_offset, assume its an absolute address.
		binary_offset = static_cast<Dwarf_Addr>((unsigned long)(offset) - (unsigned long)(dlInfo.dli_fbase) - 1);
		if (not has_matching_code_location(dbg, cu_die, binary_offset, code_loc))
			return false;
	}

	if (code_loc.binary_offset > static_cast<Dwarf_Addr>((unsigned long)(offset)))
		return false;

	matching_code_location = code_loc;
	return true;
}

//! read cu header and set next_cu_header
bool read_cu_header(Dwarf_Debug dbg, Dwarf_Unsigned& next_cu_header)
{
	Dwarf_Unsigned cu_header_length;
	Dwarf_Half     version_stamp;
	Dwarf_Unsigned abbrev_offset;
	Dwarf_Half     address_size;
	Dwarf_Half     offset_size;
	Dwarf_Half     extension_size;
	Dwarf_Error error;

	int res = dwarf_next_cu_header_b(dbg,
	                                 &cu_header_length,
	                                 &version_stamp,
	                                 &abbrev_offset,
	                                 &address_size,
	                                 &offset_size,
	                                 &extension_size,
	                                 &next_cu_header,
	                                 &error);

	return res != DW_DLV_ERROR and res != DW_DLV_NO_ENTRY;
}

//! get cu die from cu header
Dwarf_Die cu_from_header(Dwarf_Debug dbg, Dwarf_Unsigned& cu_header_offset)
{
	Dwarf_Error error;
	Dwarf_Unsigned cu_offset;  //cu_die offset in debug_info

	int res = dwarf_get_cu_die_offset_given_cu_header_offset(dbg, cu_header_offset, &cu_offset, &error);
	if (res == DW_DLV_ERROR)
		return nullptr;

	Dwarf_Die cu_die;
	res = dwarf_offdie(dbg, cu_offset, &cu_die, &error);
	if (res == DW_DLV_ERROR or res == DW_DLV_NO_ENTRY)
		return nullptr;

	return cu_die;
}

//!
//! Scans every cu (compilation unit) contained in a dwarf to find
//! the file name and file line corresponding to an binary offset
//!
//! @param offset offset to find
//! @param dlInfo The line to extract.
//! @param filename [out] correponding file name
//! @param fileLine [out] correponding file line
//! @return true on success.
//!
bool getDwarfInfos(const void* offset, Dl_info& dlInfo, std::string& filename, int& fileline)
{
	const char* fname = dlInfo.dli_fname;
	if (not fname)
		fname = "/proc/self/exe";

	int file_descriptor = ::open(fname, O_RDONLY);
	if (file_descriptor < 0)
		return false;

	Dwarf_Debug dbg = 0;
	Dwarf_Error error;
	Dwarf_Handler errhand = 0;
	Dwarf_Ptr errarg = 0;

	auto res = dwarf_init(file_descriptor, DW_DLC_READ, errhand, errarg, &dbg, &error);
	if (res != DW_DLV_OK) {
		::close(file_descriptor);
		return false;
	}

	// scans every cu header, starting with the header at offset 0.
	Dwarf_Addr binary_offset = 0;
	for (Dwarf_Unsigned current_hdr_cu_off = 0, next_hdr_cu_off;
	     read_cu_header(dbg, next_hdr_cu_off);
	     current_hdr_cu_off = next_hdr_cu_off) {
		Dwarf_Die cu_die = cu_from_header(dbg, current_hdr_cu_off);
		if (not cu_die)
			break;

		code_location code_loc;
		if (cu_code_location(dbg, cu_die, offset, dlInfo, code_loc)) {
			if (code_loc.binary_offset > binary_offset) {
				// keep the code_location closest to the target offset.
				filename = code_loc.filename;
				fileline = code_loc.fileline;
				binary_offset = code_loc.binary_offset;
			}
		}

		dwarf_dealloc(dbg, cu_die, DW_DLA_DIE);
	}

	dwarf_finish(dbg, &error);
	::close(file_descriptor);

	return binary_offset != 0;
}

//!
//! Extracts a line from a file name, removing leading and trailing whitespaces.
//!
//! @param file_path The path to an existing source file.
//! @param file_line The line to extract.
//! @return The trimmed content of file_path at the file_line-th line.
//!
std::string extract_backtrace_source(const std::string& file_path, std::uint64_t file_line)
{
	std::string line;

	std::ifstream file(file_path);

	if (not file)
		return line;

	// For better performance, reserve space upfront.
	// Since this is done to extract source code, it is very likely
	// that a line is less than 180 characters.
	line.reserve(180);

	for (std::uint64_t i = 0; file.good() and (i < (file_line - 1)); ++i)
		std::getline(file, line);

	if (not file.good())
		return std::string();

	std::getline(file, line);

	return line;
}

bool debugBackTraceGetDebugInfosDL(const void* offset, std::string& function_name, std::string& file_path,
                                   int& file_line, void*& offset_out)
{
	using dl_info = Dl_info;

	dl_info info;
	if (dladdr(offset, &info) == 0) {
		return false;
	}

	if (not info.dli_sname) {
		// no symbol found
		function_name = "?";
		offset_out = nullptr;
	} else {
		function_name = demangle_gcc(info.dli_sname);
		offset_out = info.dli_saddr;
	}

	if (not getDwarfInfos(offset, info, file_path, file_line)) {
		// No dwarf informations available.
		if (not info.dli_fname) {
			file_path = "?";
		} else {
			file_path = "(" + std::string(info.dli_fname) + ")";
		}
		file_line = 0;
	}

	return true;
}

std::string pretty_location(void* offset)
{
	struct DbgLine {
		std::string funcName;
		std::string file_path;
		int file_line;
		std::string source;
		void* startOffset;
	};

	DbgLine dbgLine;

	bool success = debugBackTraceGetDebugInfosDL(offset, dbgLine.funcName, dbgLine.file_path, dbgLine.file_line,
	                                             dbgLine.startOffset);

	if (not success)
		return "unknown symbol";

	dbgLine.source = extract_backtrace_source(dbgLine.file_path, dbgLine.file_line);

	unsigned long relativePos =
	  reinterpret_cast<unsigned long>(offset) - reinterpret_cast<unsigned long>(dbgLine.startOffset);

	std::stringstream out;

	out << dbgLine.file_path << ":" << dbgLine.file_line << " in " << dbgLine.funcName << "+" << relativePos << " : "
	    << dbgLine.source;

	return out.str();
}
