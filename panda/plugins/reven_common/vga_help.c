#include "vga_help.h"

#include <qemu/osdep.h>
#include <hw/pci/pci.h>
#include <ui/console.h>
#include <hw/display/vga_int.h>

// Keep this file a C file, so access to QEMU structures is assured to be compatible.
// (see also custom_cpu_context.h)

void get_vga_state_from_device(PCIBus *bus, PCIDevice *d, void *opaque);

void get_vga_state_from_device(__attribute__((unused)) PCIBus *bus, PCIDevice *d, void *opaque)
{
	if (strcmp(d->name, "VGA") == 0) {
		*(void**)opaque = (void*)(d + 1);
		return;
	}
}

int get_vga_info(VGAInfo* info)
{
	uint32_t dummy;

	PCIBus* bus = pci_find_primary_bus();
	VGACommonState* s = NULL;
	pci_for_each_device(bus, 0, get_vga_state_from_device, (void*)&s);
	if (s == NULL) {
		return false;
	}

	info->fb_address = s->vram.addr;
	info->fb_size = s->vram.size;
	s->get_resolution(s, &info->width, &info->height);
	info->bytes_per_pixel = (s->get_bpp(s) + 7) / 8;
	info->is_graphic_mode = info->bytes_per_pixel != 0;
	s->get_offsets(s, &info->line_byte_size, &dummy, &dummy);

	return true;
}
