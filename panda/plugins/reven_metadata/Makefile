# Don't forget to add your plugin to config.panda!

# UGLY: Change the flags of QEMU/Panda to include their headers with -isystem
# instead of -I to avoid warnings (and errors) when compiling with -Wall and -Werror
QEMU_LOCAL_INCLUDES = -isystem$(@D)
QEMU_INCLUDES := $(foreach tmp,$(QEMU_INCLUDES),$(subst -I,-isystem,$(tmp)))
QEMU_CFLAGS := $(foreach tmp,$(QEMU_CFLAGS),$(subst -I,-isystem,$(tmp)))
QEMU_CXXFLAGS := $(foreach tmp,$(QEMU_CXXFLAGS),$(subst -I,-isystem,$(tmp)))

CFLAGS+=-O3 -msse2 -Wall -Wextra -Werror
LIBS+=-L$(PLUGIN_SRC_DIR)/lib

QEMU_CXXFLAGS+=-std=c++14

PLUGIN_HEADERS=$(PLUGIN_OBJ_DIR)/../reven_common/vga_help.h
PLUGIN_OBJFILES=$(PLUGIN_OBJ_DIR)/../reven_common/vga_help.o $(PLUGIN_OBJ_DIR)/reven_metadata.o

# The main rule for your plugin. List all object-file dependencies.
$(PLUGIN_TARGET_DIR)/panda_$(PLUGIN_NAME).so: \
	$(PLUGIN_OBJ_DIR)/$(PLUGIN_NAME).o $(PLUGIN_OBJFILES)
