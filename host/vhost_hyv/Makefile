LINUX_SRC_PATH = /lib/modules/$(shell uname -r)/build
VHOST_C=$(KSRC)/drivers/vhost/vhost.c

default: modules

install: modules
	@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` modules_install

modules: | vhost_mem.c
	@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` modules

vhost_mem.c:
	# This extracts the translation functions for gpm to hvm from the kernel source
	# note that this is a hack and only works with kernel version 3.13.11 (copyright/licensing issues)
	# Extracts function find_region and translate_desc (rename to vhost_gpm_to_hvm)
	head -n12 $(VHOST_C) > vhost_mem.c
	echo "" >> vhost_mem.c
	echo "#include <vhost.h>" >> vhost_mem.c
	echo "" >> vhost_mem.c
	head -n+920 $(VHOST_C) | tail -n16 >> vhost_mem.c
	echo "" >> vhost_mem.c
	head -n+1084 $(VHOST_C) | tail -n36 >> vhost_mem.c
	sed -i 's/translate_desc/vhost_gpm_to_hvm/g' vhost_mem.c
	sed -i '33s/static //g' vhost_mem.c

clean:
	-@${MAKE} -C $(LINUX_SRC_PATH) M=`pwd` clean
	rm vhost_mem.c
	rm *~

.PHONY: clean modules install

