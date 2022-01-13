#include <cstring>
#include <fstream>

#include <panda/plugin.h>
#include <panda/plugin_plugin.h>

#include "../reven_common/vga_help.h"

extern "C" {
bool init_plugin(void*);
void uninit_plugin(void*);

int insn_exec_callback(CPUState*, target_ulong);
}

namespace {

void* plugin = nullptr;

void save_trace_metadata(CPUState* /* cs */)
{
	VGAInfo info;
	if (not get_vga_info(&info)) {
		printf("Could not access VGA hw. Will not output framebuffer information.");
		return;
	}

	std::ofstream file("metadata.json");
	file << "{" << std::endl;

	file << "\t\"framebuffer\": {" << std::endl;

	// We handle graphic mode only for now.
	// Text mode doesn't work yet because fb memory area is not updated as it should.
	// Besides, this doesn't handle cases where the fb info changes during the trace.
	if (info.is_graphic_mode) {
		file << "\t\t\"mode\": \"graphic\"" << "," << std::endl;
		file << "\t\t\"address\": " << std::dec << info.fb_address << "," << std::endl;
		file << "\t\t\"width\": " << std::dec << info.width << "," << std::endl;
		file << "\t\t\"height\": " << std::dec << info.height << "," << std::endl;
		file << "\t\t\"line_byte_size\": " << std::dec << info.line_byte_size << "," << std::endl;
		file << "\t\t\"bytes_per_pixel\": " << std::dec << info.bytes_per_pixel << std::endl;
	}

	file << "\t}" << std::endl;

	file << "}" << std::endl;
	file.close();
}

}

bool insn_translate_callback(CPUState* /* cs */, target_ulong /* pc */)
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

int insn_exec_callback(CPUState* cs, target_ulong /* pc */)
{
	try {
		save_trace_metadata(cs);
		exit(0);

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
		plugin = self;

		/*=== callbacks ===*/
		panda_cb pcb;

		pcb.insn_exec = insn_exec_callback;
		panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb); // called before an instruction_EVENT is executed

		pcb.insn_translate = insn_translate_callback;
		panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb); // called before an instruction_EVENT is translated

		printf("Starting metadata recording...\n");

		return true;
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}

void uninit_plugin(void* /* self */) {
	try {
		// Do nothing
	} catch(const std::exception &e) {
		fprintf(stderr, "An exception occurred: %s\n", e.what());
		exit(1);
	} catch(...) {
		fprintf(stderr, "An unknown exception occurred\n");
		exit(1);
	}
}
