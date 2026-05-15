ifndef KP_DIR
    KP_DIR = ../..
endif

ifeq ($(strip $(TARGET_COMPILE)),)
    TARGET_CC := $(shell command -v aarch64-none-elf-gcc 2>/dev/null || command -v aarch64-linux-android-gcc 2>/dev/null)
    ifeq ($(strip $(TARGET_CC)),)
        $(error TARGET_COMPILE not set and no aarch64 cross gcc found in PATH)
    endif
    TARGET_COMPILE := $(patsubst %gcc,%,$(TARGET_CC))
endif

CC = $(TARGET_COMPILE)gcc
LD = $(TARGET_COMPILE)ld

INCLUDE_DIRS := . include patch/include linux linux/include linux/arch/arm64/include linux/tools/arch/arm64/include
INCLUDE_FLAGS := $(foreach dir,$(INCLUDE_DIRS),-I$(KP_DIR)/kernel/$(dir))

objs := selinux_query_guard.o

all: selinux_query_guard.kpm

selinux_query_guard.kpm: ${objs}
	${CC} -r -o $@ $^

%.o: %.c
	${CC} $(CFLAGS) $(INCLUDE_FLAGS) -c -O2 -o $@ $<

.PHONY: clean
clean:
	rm -rf *.kpm
	find . -name "*.o" | xargs rm -f
