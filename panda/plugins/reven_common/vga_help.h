#ifndef __REVEN_TRACER_VGA_HELP__
#define __REVEN_TRACER_VGA_HELP__

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
	unsigned int fb_address; // Start address of the framebuffer area
	unsigned int fb_size; // Full size of the framebuffer memory area, may be bigger than necessary
	int is_graphic_mode; // If 0, is text mode
	int width; // Screen width
	int height; // Screen height
	unsigned int line_byte_size; // Size that separate each line's begin.
	                             // At least big enough to contain width * bytes_per_pixel.
	int bytes_per_pixel; // No use if is_graphic_mode is 0
} VGAInfo;

int get_vga_info(VGAInfo* info);

#ifdef __cplusplus
}
#endif

#endif // __REVEN_TRACER_VGA_HELP__
