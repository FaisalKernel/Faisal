# FAISAL CogOS experimental kernel module
# Default follows the attachment; FAISAL validation overrides KDIR/KBUILD_OUTPUT.
KDIR ?= /lib/modules/$(shell uname -r)/build
KBUILD_OUTPUT ?=
PWD := $(shell pwd)

obj-m += cog_kernel.o
ccflags-y += -Wall -Werror -Wno-declaration-after-statement

all:
	$(MAKE) -C $(KDIR) $(if $(KBUILD_OUTPUT),O=$(KBUILD_OUTPUT),) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) $(if $(KBUILD_OUTPUT),O=$(KBUILD_OUTPUT),) M=$(PWD) clean
