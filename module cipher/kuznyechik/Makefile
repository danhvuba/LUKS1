obj-m := kuznyechik.o

KERNELDIR = /lib/modules/$(shell uname -r)/build

install:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR)

clean:
	$(MAKE) -C $(KERNELDIR) M=$(CURDIR) clean
